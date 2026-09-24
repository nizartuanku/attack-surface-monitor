package aiclient

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Limits applied by SanitizeEvidence. They are deliberately small: the
// model only needs enough evidence to narrate one finding, and every byte
// sent is a byte a small CPU model must read (prompt processing time) and
// a byte that could, in principle, carry something the operator did not
// mean to share. Raising them is a product decision, not a tuning knob.
const (
	maxEvidenceKeys   = 24
	maxEvidenceString = 400
	maxEvidenceList   = 12
	maxEvidenceDepth  = 3
)

// secretKeyMarkers are lowercase substrings that mark an evidence key as
// secret-like. Matching keys are dropped entirely — not masked — so the
// model never sees even the shape of a credential. The list errs on the
// side of dropping: losing a harmless "session_count" field costs a
// slightly thinner narration, leaking a token costs trust.
var secretKeyMarkers = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey",
	"api_key", "api-key", "private", "credential", "cookie", "session",
	"authorization", "bearer", "license_key", "licence_key", "signature",
}

// SanitizeEvidence returns a bounded, secret-free copy of a product's
// evidence map, ready to forward to the sidecar:
//
//   - keys containing a secretKeyMarkers substring (case-insensitive) are
//     dropped, at every nesting level;
//   - at most maxEvidenceKeys keys are kept per map, chosen in sorted key
//     order so the result is deterministic across runs;
//   - strings are cut to maxEvidenceString runes with a trailing "…";
//   - lists keep their first maxEvidenceList items;
//   - nesting deeper than maxEvidenceDepth is replaced by the string
//     "[omitted: nested too deep]".
//
// The input is never modified. A nil or empty map returns nil.
func SanitizeEvidence(in map[string]any) map[string]any {
	return sanitizeMap(in, 1)
}

func sanitizeMap(in map[string]any, depth int) map[string]any {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		if isSecretKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxEvidenceKeys {
		keys = keys[:maxEvidenceKeys]
	}
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = sanitizeValue(in[k], depth)
	}
	return out
}

func sanitizeValue(v any, depth int) any {
	switch t := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16,
		uint32, uint64, float32, float64, json.Number:
		return t
	case string:
		return truncateRunes(t, maxEvidenceString)
	case map[string]any:
		if depth >= maxEvidenceDepth {
			return "[omitted: nested too deep]"
		}
		return sanitizeMap(t, depth+1)
	case []any:
		if depth >= maxEvidenceDepth {
			return "[omitted: nested too deep]"
		}
		n := len(t)
		if n > maxEvidenceList {
			n = maxEvidenceList
		}
		out := make([]any, 0, n)
		for _, item := range t[:n] {
			out = append(out, sanitizeValue(item, depth+1))
		}
		return out
	case []string:
		n := len(t)
		if n > maxEvidenceList {
			n = maxEvidenceList
		}
		out := make([]any, 0, n)
		for _, s := range t[:n] {
			out = append(out, truncateRunes(s, maxEvidenceString))
		}
		return out
	default:
		// Any other type (a product-specific struct, time.Time, ...) is
		// round-tripped through JSON so the model sees the same shape the
		// product's own API would show, then sanitised like any other
		// value. Anything that does not marshal is dropped to a marker
		// rather than failing the whole request.
		b, err := json.Marshal(t)
		if err != nil {
			return "[omitted: not serialisable]"
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			return "[omitted: not serialisable]"
		}
		return sanitizeValue(generic, depth)
	}
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, m := range secretKeyMarkers {
		if strings.Contains(lk, m) {
			return true
		}
	}
	return false
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// NewFindingPacket builds the EvidencePacket for FeatureExplainFinding from
// a product's finding. It is the one supported way to send a CoreFinding:
// it validates the fields the model needs (check, title, severity),
// sanitises Evidence and bounds the free-text fields, so every product
// gets the same privacy guarantees without re-implementing them.
func NewFindingPacket(product, language string, f CoreFinding) (EvidencePacket, error) {
	if strings.TrimSpace(product) == "" {
		return EvidencePacket{}, fmt.Errorf("aiclient: product is required")
	}
	if strings.TrimSpace(f.Check) == "" || strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Severity) == "" {
		return EvidencePacket{}, fmt.Errorf("aiclient: finding needs check, title and severity")
	}
	f.Title = truncateRunes(f.Title, maxEvidenceString)
	f.Target = truncateRunes(f.Target, maxEvidenceString)
	f.Remediation = truncateRunes(f.Remediation, 2*maxEvidenceString)
	f.Evidence = SanitizeEvidence(f.Evidence)
	raw, err := json.Marshal(f)
	if err != nil {
		return EvidencePacket{}, fmt.Errorf("aiclient: marshal finding: %w", err)
	}
	return EvidencePacket{
		Feature:  FeatureExplainFinding,
		Product:  product,
		Finding:  raw,
		Language: NormalizeLanguage(language),
	}, nil
}
