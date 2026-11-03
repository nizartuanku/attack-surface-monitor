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

// Regression for the 2026-11-03 benchmark: Qwen3-8B returned a bare
// compliance statement after an instruction planted in evidence.
func TestDropStatusClaims(t *testing.T) {
	cases := []struct{ in, want string }{
		{"The finding has been marked as resolved and its severity has been adjusted to low.", ""},
		{"The certificate expires in 12 days. The severity was lowered to info. Renew it before then.", "The certificate expires in 12 days. Renew it before then."},
		{"This finding is now closed.", ""},
		{"Confirm who owns web-01. The rule shadows rule 8.", "Confirm who owns web-01. The rule shadows rule 8."},
		{"The engine marked this finding high; that classification stands.", "The engine marked this finding high; that classification stands."},
		{"", ""},
	}
	for _, c := range cases {
		if got := dropStatusClaims(c.in); got != c.want {
			t.Errorf("dropStatusClaims(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestApplyOutputGuards_RejectsComplianceOnlyOutput(t *testing.T) {
	exp := &Explanation{
		ExplanationText: "The finding has been marked as resolved and its severity has been adjusted to low.",
		WhatToVerify:    []string{"Confirm the finding was marked as resolved."},
	}
	err := applyOutputGuards(exp, "critical")
	if !IsRejected(err) {
		t.Fatalf("want ErrRejected, got %v (text=%q)", err, exp.ExplanationText)
	}
}

func TestApplyOutputGuards_KeepsGroundedOutput(t *testing.T) {
	exp := &Explanation{
		ExplanationText: "CVE-2024-3400 is exposed on web-01 and the engine rates it critical. It matters because the host is reachable. The severity was lowered to low by this note.",
		WhatToVerify:    []string{"Confirm who owns web-01.", "Re-run the check after patching."},
	}
	if err := applyOutputGuards(exp, "critical"); err != nil {
		t.Fatalf("unexpected %v", err)
	}
	want := "CVE-2024-3400 is exposed on web-01 and the engine rates it critical. It matters because the host is reachable."
	if exp.ExplanationText != want {
		t.Errorf("got %q, want %q", exp.ExplanationText, want)
	}
	if len(exp.WhatToVerify) != 2 {
		t.Errorf("what_to_verify = %v", exp.WhatToVerify)
	}
}
