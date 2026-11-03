package aiclient

import (
	"errors"
	"regexp"
	"strings"
)

// severityWords is the closed set of severity labels used across the
// Hexward line.
var severityWords = []string{"critical", "high", "medium", "moderate", "low", "info", "informational"}

// sentenceSplit splits narration into sentences while keeping the
// terminator with each one.
var sentenceSplit = regexp.MustCompile(`[^.!?]+[.!?]*\s*`)

// dropConflictingSeverity removes every sentence of text that states a
// severity other than the engine's own. It is the deterministic backstop
// behind the prompt rule: in live tests the free-tier model still called
// an "info" finding "low-severity" about half the time despite being told
// the exact word. A sentence counts as stating a severity when a severity
// word sits directly next to "severity" or "risk" ("low-severity", "high
// risk", "severity is medium", "severity of critical"). English only —
// Indonesian narration is left untouched, which the docs state.
// If every sentence would be dropped, the original text is returned and
// the caller's disclaimer carries the warning.
func dropConflictingSeverity(text, engineSeverity string) string {
	engine := strings.ToLower(strings.TrimSpace(engineSeverity))
	if engine == "" || text == "" {
		return text
	}
	same := map[string]bool{engine: true}
	switch engine {
	case "info", "informational":
		same["info"], same["informational"] = true, true
	case "medium", "moderate":
		same["medium"], same["moderate"] = true, true
	}
	var conflicting []string
	for _, w := range severityWords {
		if !same[w] {
			conflicting = append(conflicting, w)
		}
	}
	alt := strings.Join(conflicting, "|")
	re := regexp.MustCompile(`(?i)\b(` + alt + `)[\s-]+(severity|risk|priority)\b|\b(severity|risk|priority)\s+(is|of|level\s+is|rating\s+is)?\s*(` + alt + `)\b`)

	var kept []string
	for _, s := range sentenceSplit.FindAllString(text, -1) {
		if re.MatchString(s) {
			continue
		}
		kept = append(kept, s)
	}
	out := strings.TrimSpace(strings.Join(kept, ""))
	if out == "" {
		return text
	}
	return out
}

// ErrRejected means the model's answer was discarded by the deterministic
// guards: after removing sentences that claim a status or severity the
// engine did not produce, nothing grounded was left. Products should
// render this the way they render ErrUnavailable — the finding itself is
// untouched — and may log it, because a steady stream of rejections is a
// sign of a poisoned evidence source or an unsuitable model.
var ErrRejected = errors.New("aiclient: model output rejected by guard (no grounded explanation remained)")

// IsRejected reports whether err came from the output guard.
func IsRejected(err error) bool { return errors.Is(err, ErrRejected) }

// statusClaim matches a sentence in which the narration asserts that the
// finding's state changed — "has been marked as resolved", "severity was
// adjusted to low", "is now fixed/closed" — which the model cannot know
// and must never say: status and severity are the engine's alone. This is
// the sibling of dropConflictingSeverity for the injection case seen on
// 2026-11-03, where the output was a bare compliance statement.
var statusClaim = regexp.MustCompile(`(?i)\b(has been|have been|was|were|is now|are now|will be|been)\s+(marked|set|adjusted|changed|lowered|raised|updated|reclassified|downgraded|upgraded|closed|resolved|fixed)\b|\b(marked|flagged|classified)\s+(as|to)\s+(resolved|fixed|closed|safe|not a risk|false positive)\b|\bseverity\s+(has been|was|is now)?\s*(adjusted|changed|lowered|raised|set)\b`)

// dropStatusClaims removes every sentence of text that asserts a status
// or severity change. Unlike dropConflictingSeverity it never falls back
// to the original text: a status claim is never acceptable narration, so
// if nothing remains the caller treats the response as rejected.
func dropStatusClaims(text string) string {
	if text == "" {
		return text
	}
	var kept []string
	for _, s := range sentenceSplit.FindAllString(text, -1) {
		if statusClaim.MatchString(s) {
			continue
		}
		kept = append(kept, s)
	}
	return strings.TrimSpace(strings.Join(kept, ""))
}

// minGroundedExplanation is the shortest explanation accepted after the
// guards ran. Anything shorter is not an explanation of a finding.
const minGroundedExplanation = 20

// applyOutputGuards runs every deterministic output check in order and
// reports whether the explanation survived. It mutates exp in place.
func applyOutputGuards(exp *Explanation, engineSeverity string) error {
	if engineSeverity != "" {
		exp.ExplanationText = dropConflictingSeverity(exp.ExplanationText, engineSeverity)
	}
	exp.ExplanationText = dropStatusClaims(exp.ExplanationText)
	var verify []string
	for _, v := range exp.WhatToVerify {
		if v = dropStatusClaims(v); strings.TrimSpace(v) != "" {
			verify = append(verify, v)
		}
	}
	exp.WhatToVerify = verify
	if len([]rune(strings.TrimSpace(exp.ExplanationText))) < minGroundedExplanation {
		return ErrRejected
	}
	return nil
}
