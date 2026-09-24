package aiclient

import (
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
