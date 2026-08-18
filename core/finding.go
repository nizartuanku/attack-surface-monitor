// Package core defines the two contracts every Sentinel product is built on:
// the normalised Finding and the Collector interface. Nothing in this package
// knows about TLS, CVEs, firewalls, or any specific product — that intelligence
// lives in each product's Collector. The core stays generic so that all six
// products share one scheduler, one store, one notifier, one dashboard.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Severity ranks a finding's urgency. Ordered constants let the store and UI
// sort and threshold without a separate lookup table.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// rank gives a total order for severities (higher = more urgent). Unknown
// severities sort lowest so a malformed collector can never mask a real critical.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityInfo:
		return 0
	default:
		return -1
	}
}

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool { return s.rank() >= 0 }

// FindingStatus is the core-owned lifecycle state. Collectors never set this;
// the store's reconcile logic drives every transition.
type FindingStatus string

const (
	StatusOpen         FindingStatus = "open"
	StatusResolved     FindingStatus = "resolved"
	StatusAcknowledged FindingStatus = "acknowledged"
	StatusSuppressed   FindingStatus = "suppressed"
)

// MaxEvidenceBytes caps the serialised Evidence blob so a pathological collector
// cannot bloat the database. Oversized evidence is truncated with a marker at
// reconcile time (decision #3 in the contracts spec).
const MaxEvidenceBytes = 64 * 1024

// Finding is the normalised unit of everything Sentinel Core reasons about.
// A Collector returns []Finding from Collect(); the core owns everything after.
//
// Field ownership (see contracts spec §1.3):
//   - Collector fills: Fingerprint, Target, Check, Title, Severity,
//     Remediation, Evidence.
//   - Core fills/owns: ID, Module, Status, FirstSeen, LastSeen, ResolvedAt.
//
// A Collector leaves the core-owned fields zero; the store populates them.
type Finding struct {
	// Fingerprint is a stable, collector-computed identity for "the same
	// problem on the same target". It MUST be deterministic and MUST NOT
	// embed values that change benignly over time (days remaining, timestamps).
	// See Fingerprint().
	Fingerprint string `json:"fingerprint"`

	// Collector-owned descriptive fields.
	Target      string         `json:"target"`      // canonical target, e.g. "example.com:443"
	Check       string         `json:"check"`       // rule id, e.g. "tls.expiry"
	Title       string         `json:"title"`       // one human-facing line
	Severity    Severity       `json:"severity"`    //
	Remediation string         `json:"remediation"` // REQUIRED: what to do now
	Evidence    map[string]any `json:"evidence,omitempty"`

	// Core-owned fields. Collectors leave these zero.
	ID         string        `json:"id"`
	Module     string        `json:"module"`
	Status     FindingStatus `json:"status"`
	GroupID    *string       `json:"group_id,omitempty"` // nullable; MSP/tenant grouping (decision #4)
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	ResolvedAt *time.Time    `json:"resolved_at,omitempty"`
}

// ValidateForIngest checks the collector-owned fields the core requires before
// a finding can be stored. It returns nil when the finding is well-formed.
// This is the "fail loud" guard: a finding without remediation or title is a
// bug in the collector, not something to silently persist.
func (f Finding) ValidateForIngest() error {
	switch {
	case f.Fingerprint == "":
		return &IngestError{Field: "fingerprint", Reason: "empty"}
	case f.Target == "":
		return &IngestError{Field: "target", Reason: "empty"}
	case f.Check == "":
		return &IngestError{Field: "check", Reason: "empty"}
	case f.Title == "":
		return &IngestError{Field: "title", Reason: "empty"}
	case f.Remediation == "":
		return &IngestError{Field: "remediation", Reason: "empty (every finding must tell the user what to do)"}
	case !f.Severity.Valid():
		return &IngestError{Field: "severity", Reason: "unknown value: " + string(f.Severity)}
	}
	return nil
}

// IngestError describes why a finding was rejected at reconcile time.
type IngestError struct {
	Field  string
	Reason string
}

func (e *IngestError) Error() string {
	return "invalid finding: " + e.Field + ": " + e.Reason
}

// Fingerprint builds a deterministic 128-bit identity from the parts that
// distinguish one finding from another. The discriminator is the minimal thing
// that separates two findings of the same check on the same target (e.g. the
// cipher name for a weak-cipher check; empty for a single-instance check like
// expiry). Callers MUST NOT pass values that change benignly over time.
func Fingerprint(module, target, check, discriminator string) string {
	h := sha256.Sum256([]byte(module + "|" + target + "|" + check + "|" + discriminator))
	return hex.EncodeToString(h[:16]) // 128 bits is plenty; keeps the column small
}
