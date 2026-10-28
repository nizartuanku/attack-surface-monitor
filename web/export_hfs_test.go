package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/license"
	"github.com/nizartuanku/attack-surface-monitor/sched"
	"github.com/nizartuanku/attack-surface-monitor/store"
	"github.com/nizartuanku/hexward-core/hfs"
)

func TestFindingsExportHFSSnapshot(t *testing.T) {
	mod := core.ModuleInfo{ID: "asm", Name: "Attack Surface Monitor", Version: "0.1.3", DefaultInterval: time.Hour}
	ms := store.NewMemStore()
	sc := sched.New(store.NewEngine(ms), sched.Config{ScanTimeout: 5 * time.Second})
	pub, _, err := license.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(mod, ms, sc, pub, filepath.Join(t.TempDir(), "license.key"))
	now := time.Now()
	for i, sev := range []core.Severity{core.SeverityHigh, core.SeverityLow} {
		rec := store.Record{Finding: core.Finding{
			Fingerprint: core.Fingerprint(mod.ID, "fw1", "rule.permissive", string(rune('a'+i))),
			Target:      "fw1", Check: "rule.permissive", Title: "Permissive rule", Severity: sev,
			Remediation: "Tighten it.", Module: mod.ID, Status: core.StatusOpen,
			FirstSeen: now, LastSeen: now,
			Evidence: map[string]any{"rule_index": i, "password": "never-exported"},
		}}
		if err := ms.Upsert(rec); err != nil {
			t.Fatal(err)
		}
	}
	api := httptest.NewServer(srv.Handler())
	defer api.Close()

	resp, err := http.Get(api.URL + "/api/findings/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "findings.hfs.ndjson") {
		t.Fatalf("Content-Disposition %q", cd)
	}
	dec := json.NewDecoder(resp.Body)
	n := 0
	for dec.More() {
		var e hfs.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		if e.Schema != hfs.SchemaV1 || e.Event != hfs.KindSnapshot || e.Product != "asm" || e.ProductVersion != "0.1.3" {
			t.Fatalf("event %+v", e)
		}
		if _, leaked := e.Finding.Evidence["password"]; leaked {
			t.Fatal("secret-like evidence in snapshot")
		}
		n++
	}
	if n != 2 {
		t.Fatalf("snapshot events = %d, want 2", n)
	}

}
