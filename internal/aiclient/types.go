// Package aiclient is the Hexward AI Assist client. It talks to the
// hexward-ai sidecar (an OpenAI-compatible /v1/chat/completions server,
// normally llama.cpp) over plain HTTP and turns a product's own finding
// into a short, grounded narrative.
//
// This file is written ONCE in the hexward-ai repository and then copied
// verbatim into each pilot product's own repo (RuleHawk, AuditLight). There
// is no shared "Hexward Core" Go module to import it from — every Hexward
// product is its own standalone module, and this package follows the same
// per-repo pattern already used for Ed25519 license validation. See
// hexward-ai's docs/CONCEPTS.md and the spec it implements
// (02 Topik/hexward-ai-spec-v0.md in the product vault) for the reasoning.
//
// Hard rule this package exists to protect, not just document: the
// deterministic Go engine in each product is the ONLY source of findings
// and severity. Nothing in this package invents a finding, changes a
// severity, or decides pass/fail. It only asks a local model to narrate
// data the caller already has, and it hands back prose plus a disclaimer —
// never a new fact.
package aiclient

import "encoding/json"

// CanonicalDisclaimer is the exact sentence every AI-generated response
// must carry in the product's UI. The client overwrites whatever string
// the model produced for this field with this constant (see Explain and
// WhyDisappeared) — the wording must never depend on model behavior,
// because it is the one honesty signal shown to every end user.
const CanonicalDisclaimer = "AI-generated summary — verify against raw findings"

// Feature identifies which Phase 1 pilot prompt template the sidecar
// should use. hexward-ai never guesses a feature from the payload shape;
// the caller states it explicitly. Adding a feature means adding a case
// here AND a matching prompt template under docker/prompts/ — the two
// must move together.
type Feature string

const (
	// FeatureRuleHawkExplainFinding narrates one RuleHawk shadowed/
	// permissive-rule finding. It never drafts a replacement rule.
	FeatureRuleHawkExplainFinding Feature = "rulehawk.explain_finding"

	// FeatureAuditLightWhyDisappeared classifies why a finding that
	// appeared in an earlier AuditLight/Posture Report run is absent
	// from the latest one: fixed, no-longer-detected, check-failed, or
	// target-skipped. AuditLight's own Change Report / Process Report
	// already carries this distinction; the sidecar only puts it into
	// plain language, it never re-derives the classification itself.
	FeatureAuditLightWhyDisappeared Feature = "auditlight.why_disappeared"

	// FeatureExplainFinding is the generic, product-agnostic "explain
	// this finding" feature used by every Hexward product built on the
	// shared core.Finding shape (CertLight, Attack Surface Monitor,
	// Decoy, Patchlight, Loglight, DmarcWatch, TenantWatch, Posture
	// Report, and any later product on the same contract). Its payload
	// is a CoreFinding, built with NewFindingPacket so that evidence is
	// capped and secret-looking keys are dropped before anything leaves
	// the product.
	FeatureExplainFinding Feature = "hexward.explain_finding"
)

// CoreFinding is the subset of a product's core.Finding that the generic
// explain feature forwards. Field names match core.Finding's JSON tags so
// a product can convert with a plain field copy. Evidence is whatever the
// product's own check recorded; NewFindingPacket sanitises it — callers
// should not put raw configs, credentials or full logs here in the first
// place (spec §7), but the client does not rely on that alone.
type CoreFinding struct {
	Fingerprint string         `json:"fingerprint,omitempty"`
	Module      string         `json:"module,omitempty"`
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Target      string         `json:"target,omitempty"`
	Severity    string         `json:"severity"`
	Status      string         `json:"status,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

// CoverageStatus is the closed set of reasons AuditLight/Posture Report
// already tracks for why a finding is no longer present. The caller reads
// this from its own Change Report / Process Report — hexward-ai is never
// asked to decide which of these happened, only to explain the one the
// caller already determined.
type CoverageStatus string

const (
	CoverageFixed            CoverageStatus = "fixed"
	CoverageNoLongerDetected CoverageStatus = "no_longer_detected"
	CoverageCheckFailed      CoverageStatus = "check_failed"
	CoverageTargetSkipped    CoverageStatus = "target_skipped"
)

// EvidencePacket is the ONLY data a product sends to hexward-ai. It is
// deliberately minimal: per spec §7, hexward-ai must never receive
// credentials, raw config files, or full database dumps — only what one
// finding needs to be explained. Finding carries the feature-specific
// payload (e.g. RuleHawkFinding or AuditLightDisappearance) already
// marshaled by the caller; the client does not interpret it, it only
// forwards it inside the prompt for the model to read.
type EvidencePacket struct {
	Feature Feature         `json:"feature"`
	Product string          `json:"product"`
	Finding json.RawMessage `json:"finding"`
	// Language selects the narration language: "en" (default) or "id"
	// (Bahasa Indonesia). Any other value falls back to English. The
	// client turns this into an explicit instruction — models ignore a
	// bare field in the payload (observed on Phi-4-mini and Qwen3-4B).
	Language string `json:"language,omitempty"`
}

// RuleHawkFinding is the self-contained shape of one shadowed/permissive
// rule finding, matching spec §4's example exactly. It carries the rule
// text and evaluation order already computed by RuleHawk's deterministic
// engine — hexward-ai only narrates fields present here, it never invents
// a rule number or rule text absent from this struct.
type RuleHawkFinding struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	RuleIndex        int    `json:"rule_index"`
	RuleText         string `json:"rule_text"`
	ShadowsRuleIndex int    `json:"shadows_rule_index,omitempty"`
	ShadowedRuleText string `json:"shadowed_rule_text,omitempty"`
}

// AuditLightDisappearance is the self-contained shape of one "why did
// this finding disappear" input. Status is read from AuditLight's own
// Change Report / Process Report by the caller — hexward-ai narrates it,
// it never classifies it.
type AuditLightDisappearance struct {
	FindingID   string         `json:"finding_id"`
	Description string         `json:"description"`
	LastSeenRun string         `json:"last_seen_run"`
	CurrentRun  string         `json:"current_run"`
	Status      CoverageStatus `json:"status"`
	Detail      string         `json:"detail,omitempty"`
}

// Explanation is the grammar-enforced response shape from hexward-ai,
// matching spec §4 exactly. The sidecar's GBNF grammar forces the model
// to emit valid JSON in this shape; the client still validates it (a
// grammar constrains syntax, not truthfulness) and never trusts Disclaimer
// as received — see Explain.
type Explanation struct {
	ExplanationText string   `json:"explanation"`
	WhatToVerify    []string `json:"what_to_verify"`
	Disclaimer      string   `json:"disclaimer"`
}
