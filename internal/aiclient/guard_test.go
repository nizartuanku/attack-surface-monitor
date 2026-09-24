package aiclient

import "testing"

func TestDropConflictingSeverity(t *testing.T) {
	cases := []struct{ text, sev, want string }{
		{"No reports yet. This is a low-severity issue, as no action is needed. Check rua=.", "info",
			"No reports yet. Check rua=."},
		{"This is a high risk finding. Renew it.", "critical", "Renew it."},
		{"The severity is medium. Patch soon.", "high", "Patch soon."},
		{"This is a critical severity issue. Replace it now.", "critical", "This is a critical severity issue. Replace it now."},
		{"Informational severity only. Nothing to do.", "info", "Informational severity only. Nothing to do."},
		{"Moderate risk. Review.", "medium", "Moderate risk. Review."},
		{"The server allows high traffic. Low latency matters.", "info", "The server allows high traffic. Low latency matters."},
		{"This is low severity.", "critical", "This is low severity."}, // everything dropped → original kept
		{"Anything.", "", "Anything."},
	}
	for _, c := range cases {
		if got := dropConflictingSeverity(c.text, c.sev); got != c.want {
			t.Errorf("dropConflictingSeverity(%q, %q) = %q, want %q", c.text, c.sev, got, c.want)
		}
	}
}
