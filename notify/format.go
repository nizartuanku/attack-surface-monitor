package notify

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// FormatText renders a digest as the plain-text message every chat channel
// shares. One consistent voice across all six products: severity-ordered,
// remediation attached, resolved news last. Kept deliberately terse — this is
// a notification, not the dashboard.
func FormatText(d Digest) string {
	var b strings.Builder

	if n := len(d.Opened); n > 0 {
		fmt.Fprintf(&b, "%s — %d new finding(s)\n", productName(d.Module), n)
		for _, f := range d.Opened {
			fmt.Fprintf(&b, "\n%s %s\n  %s\n  → %s\n",
				severityBadge(f.Severity), f.Target, f.Title, f.Remediation)
		}
	}
	if n := len(d.Resolved); n > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "✅ %d finding(s) resolved\n", n)
		for _, f := range d.Resolved {
			fmt.Fprintf(&b, "  • %s — %s\n", f.Target, f.Title)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func severityBadge(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "🟥 CRITICAL"
	case core.SeverityHigh:
		return "🟧 HIGH"
	case core.SeverityMedium:
		return "🟨 MEDIUM"
	case core.SeverityLow:
		return "🟦 LOW"
	default:
		return "⬜ INFO"
	}
}

// productName maps module ids to display names. Central here so every channel
// renders the same brand; grows as modules ship.
func productName(module string) string {
	switch module {
	case "certwatch":
		return "CertWatch"
	case "asm":
		return "Attack Surface Monitor"
	default:
		return module
	}
}
