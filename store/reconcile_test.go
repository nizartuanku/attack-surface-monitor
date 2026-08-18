package store

import (
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// --- test scaffolding -------------------------------------------------------

var testMod = core.ModuleInfo{ID: "certwatch", Name: "CertWatch", ResolveAfter: 1}

// fixedClock returns a controllable clock so timestamps are deterministic.
func fixedClock(t *time.Time) Clock { return func() time.Time { return *t } }

// seqID hands out predictable ids so tests can assert on them if needed.
func seqID(n *int) IDGen {
	return func(time.Time) (string, error) { *n++; return "id-" + itoa(*n), nil }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newTestEngine() (*Engine, *MemStore, *time.Time) {
	clk := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	ids := 0
	s := NewMemStore()
	e := NewEngine(s).WithClock(fixedClock(&clk)).WithIDGen(seqID(&ids))
	return e, s, &clk
}

func expiryFinding(target string, daysLeft int) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint("certwatch", target, "tls.expiry", ""),
		Target:      target,
		Check:       "tls.expiry",
		Title:       "Certificate expires soon",
		Severity:    core.SeverityHigh,
		Remediation: "Renew the certificate.",
		Evidence:    map[string]any{"days_left": daysLeft},
	}
}

// --- tests ------------------------------------------------------------------

func TestReconcile_NewFindingIsInsertedOpenAndNotified(t *testing.T) {
	e, s, _ := newTestEngine()
	res, err := e.Reconcile(testMod, "example.com:443", []core.Finding{expiryFinding("example.com:443", 20)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NewlyOpen) != 1 {
		t.Fatalf("want 1 newly-open, got %d", len(res.NewlyOpen))
	}
	recs, _ := s.ListByTarget("certwatch", "example.com:443")
	if len(recs) != 1 || recs[0].Status != core.StatusOpen {
		t.Fatalf("want 1 open record, got %+v", recs)
	}
	if recs[0].ID == "" || recs[0].Module != "certwatch" {
		t.Fatalf("core did not populate id/module: %+v", recs[0])
	}
}

// The single most important behaviour: a finding whose underlying value drifts
// (20 → 19 days) must keep the SAME fingerprint, so it does NOT re-notify and
// its first_seen is preserved — only last_seen advances.
func TestReconcile_StableFingerprintDoesNotReNotify(t *testing.T) {
	e, s, clk := newTestEngine()
	target := "example.com:443"

	r1, _ := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})
	if len(r1.NewlyOpen) != 1 {
		t.Fatalf("first scan should notify once, got %d", len(r1.NewlyOpen))
	}
	firstSeen := mustGet(t, s, target).FirstSeen

	*clk = clk.Add(24 * time.Hour)
	r2, _ := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 19)})
	if len(r2.NewlyOpen) != 0 {
		t.Fatalf("drifting value must NOT re-notify, got %d", len(r2.NewlyOpen))
	}
	rec := mustGet(t, s, target)
	if !rec.FirstSeen.Equal(firstSeen) {
		t.Fatalf("first_seen must be preserved: was %v now %v", firstSeen, rec.FirstSeen)
	}
	if !rec.LastSeen.After(firstSeen) {
		t.Fatalf("last_seen must advance")
	}
	if got := rec.Evidence["days_left"]; got != 19 {
		t.Fatalf("mutable evidence should update to 19, got %v", got)
	}
}

func TestReconcile_AbsentFindingAutoResolves(t *testing.T) {
	e, s, clk := newTestEngine()
	target := "example.com:443"
	e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})

	*clk = clk.Add(24 * time.Hour)
	res, _ := e.Reconcile(testMod, target, nil) // cert renewed → no finding
	if len(res.Resolved) != 1 {
		t.Fatalf("want 1 auto-resolved, got %d", len(res.Resolved))
	}
	if mustGet(t, s, target).Status != core.StatusResolved {
		t.Fatalf("finding should be resolved")
	}
}

func TestReconcile_ResolveAfterThresholdRespected(t *testing.T) {
	e, s, clk := newTestEngine()
	mod := core.ModuleInfo{ID: "certwatch", ResolveAfter: 2} // needs 2 absent scans
	target := "flappy.example:443"
	e.Reconcile(mod, target, []core.Finding{expiryFinding(target, 20)})

	*clk = clk.Add(time.Hour)
	res1, _ := e.Reconcile(mod, target, nil)
	if len(res1.Resolved) != 0 {
		t.Fatalf("must not resolve after only 1 absent scan")
	}
	if mustGet(t, s, target).Status != core.StatusOpen {
		t.Fatalf("should still be open after 1 absent scan")
	}

	*clk = clk.Add(time.Hour)
	res2, _ := e.Reconcile(mod, target, nil)
	if len(res2.Resolved) != 1 {
		t.Fatalf("must resolve after 2 absent scans, got %d", len(res2.Resolved))
	}
}

func TestReconcile_ReopenAfterResolveNotifiesAgain(t *testing.T) {
	e, s, clk := newTestEngine()
	target := "example.com:443"
	e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})
	*clk = clk.Add(time.Hour)
	e.Reconcile(testMod, target, nil) // resolve
	if mustGet(t, s, target).Status != core.StatusResolved {
		t.Fatal("precondition: should be resolved")
	}

	*clk = clk.Add(time.Hour)
	res, _ := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 5)}) // problem returns
	if len(res.NewlyOpen) != 1 {
		t.Fatalf("reopened finding must notify again, got %d", len(res.NewlyOpen))
	}
	rec := mustGet(t, s, target)
	if rec.Status != core.StatusOpen || rec.ResolvedAt != nil {
		t.Fatalf("reopened finding must be open with nil resolved_at: %+v", rec)
	}
}

func TestReconcile_SuppressedNeverResolvesOrNotifies(t *testing.T) {
	e, s, clk := newTestEngine()
	target := "example.com:443"
	e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})

	// User suppresses the finding.
	rec := mustGet(t, s, target)
	rec.Status = core.StatusSuppressed
	s.Upsert(rec)

	// It stays present but suppressed: no re-notify.
	*clk = clk.Add(time.Hour)
	res1, _ := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 19)})
	if len(res1.NewlyOpen) != 0 {
		t.Fatalf("suppressed finding must not notify")
	}
	if mustGet(t, s, target).Status != core.StatusSuppressed {
		t.Fatalf("suppressed must stay suppressed while present")
	}

	// It disappears: suppressed must NOT auto-resolve (user owns that state).
	*clk = clk.Add(time.Hour)
	res2, _ := e.Reconcile(testMod, target, nil)
	if len(res2.Resolved) != 0 {
		t.Fatalf("suppressed finding must not auto-resolve")
	}
	if mustGet(t, s, target).Status != core.StatusSuppressed {
		t.Fatalf("suppressed must remain suppressed when absent")
	}
}

func TestReconcile_AcknowledgedSilentButStillResolves(t *testing.T) {
	e, s, clk := newTestEngine()
	target := "example.com:443"
	e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})

	rec := mustGet(t, s, target)
	rec.Status = core.StatusAcknowledged
	s.Upsert(rec)

	// Present + acknowledged: no re-notify.
	*clk = clk.Add(time.Hour)
	res1, _ := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 19)})
	if len(res1.NewlyOpen) != 0 {
		t.Fatalf("acknowledged must not re-notify")
	}
	if mustGet(t, s, target).Status != core.StatusAcknowledged {
		t.Fatalf("acknowledged should persist while present")
	}

	// Disappears: acknowledged DOES resolve (unlike suppressed).
	*clk = clk.Add(time.Hour)
	res2, _ := e.Reconcile(testMod, target, nil)
	if len(res2.Resolved) != 1 {
		t.Fatalf("acknowledged finding should resolve when gone, got %d", len(res2.Resolved))
	}
}

func TestReconcile_RejectsFindingMissingRemediation(t *testing.T) {
	e, _, _ := newTestEngine()
	bad := expiryFinding("example.com:443", 20)
	bad.Remediation = "" // the philosophy-critical required field
	res, err := e.Reconcile(testMod, "example.com:443", []core.Finding{bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("want 1 rejected, got %d", len(res.Rejected))
	}
	if len(res.NewlyOpen) != 0 {
		t.Fatalf("rejected finding must not be stored/notified")
	}
}

func TestReconcile_TwoChecksSameTargetAreDistinct(t *testing.T) {
	e, s, _ := newTestEngine()
	target := "example.com:443"
	expiry := expiryFinding(target, 20)
	weak := core.Finding{
		Fingerprint: core.Fingerprint("certwatch", target, "tls.weak_protocol", "TLS1.0"),
		Target:      target, Check: "tls.weak_protocol", Title: "Obsolete TLS",
		Severity: core.SeverityHigh, Remediation: "Disable TLS 1.0.",
	}
	res, _ := e.Reconcile(testMod, target, []core.Finding{expiry, weak})
	if len(res.NewlyOpen) != 2 {
		t.Fatalf("two distinct checks must both open, got %d", len(res.NewlyOpen))
	}
	recs, _ := s.ListByTarget("certwatch", target)
	if len(recs) != 2 {
		t.Fatalf("want 2 stored records, got %d", len(recs))
	}
}

func TestReconcile_EvidenceOverCapIsTruncated(t *testing.T) {
	e, s, _ := newTestEngine()
	target := "example.com:443"
	big := make([]byte, core.MaxEvidenceBytes+10)
	for i := range big {
		big[i] = 'x'
	}
	f := expiryFinding(target, 20)
	f.Evidence = map[string]any{"blob": string(big)}
	e.Reconcile(testMod, target, []core.Finding{f})
	rec := mustGet(t, s, target)
	if rec.Evidence["_truncated"] != true {
		t.Fatalf("oversized evidence should be truncated, got %+v", rec.Evidence)
	}
}

func mustGet(t *testing.T, s *MemStore, target string) Record {
	t.Helper()
	recs, _ := s.ListByTarget("certwatch", target)
	if len(recs) == 0 {
		t.Fatalf("no record for %s", target)
	}
	return recs[0]
}
