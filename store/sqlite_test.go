package store

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // test driver; release builds swap to modernc.org/sqlite
	"github.com/nizartuanku/attack-surface-monitor/core"
)

func newSQLiteTest(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Roundtrip: every field must survive Upsert → Get unchanged, including the
// nullable ones (evidence, group_id, resolved_at).
func TestSQLite_UpsertGetRoundtrip(t *testing.T) {
	s := newSQLiteTest(t)
	group := "client-a"
	resolved := time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC)
	rec := Record{
		Finding: core.Finding{
			Fingerprint: "fp-1",
			Target:      "example.com:443",
			Check:       "tls.expiry",
			Title:       "Certificate expires in 20 days",
			Severity:    core.SeverityHigh,
			Remediation: "Renew the certificate.",
			Evidence:    map[string]any{"days_left": float64(20), "issuer": "R11"},
			ID:          "01TESTULID0000000000000000",
			Module:      "certwatch",
			Status:      core.StatusResolved,
			GroupID:     &group,
			FirstSeen:   time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
			LastSeen:    time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
			ResolvedAt:  &resolved,
		},
		AbsentStreak: 2,
	}
	if err := s.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("certwatch", "fp-1")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if got.Title != rec.Title || got.Severity != rec.Severity || got.Status != rec.Status ||
		got.Remediation != rec.Remediation || got.AbsentStreak != 2 {
		t.Fatalf("scalar fields mismatched: %+v", got)
	}
	if got.Evidence["days_left"] != float64(20) || got.Evidence["issuer"] != "R11" {
		t.Fatalf("evidence mismatched: %+v", got.Evidence)
	}
	if got.GroupID == nil || *got.GroupID != "client-a" {
		t.Fatalf("group_id mismatched: %v", got.GroupID)
	}
	if got.ResolvedAt == nil || !got.ResolvedAt.UTC().Equal(resolved) {
		t.Fatalf("resolved_at mismatched: %v", got.ResolvedAt)
	}
	if !got.FirstSeen.UTC().Equal(rec.FirstSeen) || !got.LastSeen.UTC().Equal(rec.LastSeen) {
		t.Fatalf("timestamps mismatched: %+v", got)
	}
}

// The UNIQUE(module, fingerprint) upsert must update in place, not duplicate.
func TestSQLite_UpsertConflictUpdatesInPlace(t *testing.T) {
	s := newSQLiteTest(t)
	base := Record{Finding: core.Finding{
		Fingerprint: "fp-1", Target: "example.com:443", Check: "tls.expiry",
		Title: "old title", Severity: core.SeverityMedium, Remediation: "renew",
		ID: "id-1", Module: "certwatch", Status: core.StatusOpen,
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}}
	if err := s.Upsert(base); err != nil {
		t.Fatal(err)
	}
	updated := base
	updated.Title = "new title"
	updated.Severity = core.SeverityCritical
	if err := s.Upsert(updated); err != nil {
		t.Fatal(err)
	}
	recs, err := s.ListByTarget("certwatch", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("upsert must not duplicate: got %d rows", len(recs))
	}
	if recs[0].Title != "new title" || recs[0].Severity != core.SeverityCritical {
		t.Fatalf("update not applied: %+v", recs[0])
	}
	// ID must be preserved from the first insert (conflict path doesn't touch id).
	if recs[0].ID != "id-1" {
		t.Fatalf("id must be stable across upserts, got %s", recs[0].ID)
	}
}

// The full lifecycle — new → value drift (no re-notify) → gone (auto-resolve)
// → back (reopen + notify) — run against real SQLite through the same Engine
// the product will use. This is the SQLite twin of the MemStore tests.
func TestSQLite_ReconcileLifecycle(t *testing.T) {
	s := newSQLiteTest(t)
	clk := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	ids := 0
	e := NewEngine(s).WithClock(fixedClock(&clk)).WithIDGen(seqID(&ids))
	target := "example.com:443"

	// Scan 1: new finding → notify.
	r1, err := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 20)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.NewlyOpen) != 1 {
		t.Fatalf("scan1: want 1 newly-open, got %d", len(r1.NewlyOpen))
	}

	// Scan 2: value drifts → same fingerprint, silent.
	clk = clk.Add(24 * time.Hour)
	r2, err := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 19)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.NewlyOpen) != 0 {
		t.Fatalf("scan2: drift must not re-notify")
	}

	// Scan 3: cert renewed → auto-resolve.
	clk = clk.Add(24 * time.Hour)
	r3, err := e.Reconcile(testMod, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r3.Resolved) != 1 {
		t.Fatalf("scan3: want auto-resolve, got %d", len(r3.Resolved))
	}

	// Scan 4: problem returns → reopen + notify.
	clk = clk.Add(24 * time.Hour)
	r4, err := e.Reconcile(testMod, target, []core.Finding{expiryFinding(target, 5)})
	if err != nil {
		t.Fatal(err)
	}
	if len(r4.NewlyOpen) != 1 {
		t.Fatalf("scan4: reopen must notify, got %d", len(r4.NewlyOpen))
	}

	open, err := s.ListOpen("certwatch")
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("want exactly 1 open finding at the end, got %d", len(open))
	}
}

func TestSQLite_PruneResolvedBefore(t *testing.T) {
	s := newSQLiteTest(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	mk := func(fp string, at time.Time) Record {
		return Record{Finding: core.Finding{
			Fingerprint: fp, Target: "t", Check: "c", Title: "x",
			Severity: core.SeverityLow, Remediation: "r",
			ID: "id-" + fp, Module: "certwatch", Status: core.StatusResolved,
			FirstSeen: at, LastSeen: at, ResolvedAt: &at,
		}}
	}
	s.Upsert(mk("old", old))
	s.Upsert(mk("recent", recent))

	n, err := s.PruneResolvedBefore(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 pruned, got %d", n)
	}
	if _, ok, _ := s.Get("certwatch", "old"); ok {
		t.Fatal("old resolved finding should be pruned")
	}
	if _, ok, _ := s.Get("certwatch", "recent"); !ok {
		t.Fatal("recent resolved finding must remain")
	}
}
