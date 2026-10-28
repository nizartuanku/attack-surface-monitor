package notify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"
)

func TestHFSChannelWritesSchemaEvents(t *testing.T) {
	at := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	p := filepath.Join(t.TempDir(), "rulehawk.ndjson")
	ch := &HFSChannel{Sink: &sink.File{Path: p}, Meta: hfs.Meta{Version: "9.9.9", Host: "h1"}}
	d := Digest{
		Module: "rulehawk",
		At:     at,
		Opened: []core.Finding{{
			ID: "id1", Fingerprint: "fp-open", Target: "fw1", Check: "rule.permissive",
			Title: "Any to RDP", Severity: core.SeverityHigh, Status: core.StatusOpen,
			Remediation: "Restrict the source.", Evidence: map[string]any{"src_ip": "203.0.113.9", "secret": "x"},
		}},
		Resolved: []core.Finding{{
			Fingerprint: "fp-gone", Target: "fw1", Check: "rule.duplicate",
			Title: "Duplicate rule", Severity: core.SeverityLow, Status: core.StatusOpen,
			Remediation: "Remove the duplicate.",
		}},
	}
	if err := ch.Send(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %d: %s", len(lines), b)
	}
	var open, gone hfs.Event
	if err := json.Unmarshal([]byte(lines[0]), &open); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &gone); err != nil {
		t.Fatal(err)
	}
	if open.Schema != hfs.SchemaV1 || open.Event != hfs.KindOpened || open.Product != "rulehawk" ||
		open.ProductVersion != "9.9.9" || open.Host != "h1" || open.SrcIP != "203.0.113.9" ||
		open.Finding.Fingerprint != "fp-open" || open.Finding.ID != "id1" || open.Finding.SeverityNum != 8 {
		t.Fatalf("opened event wrong: %+v", open)
	}
	if gone.Event != hfs.KindResolved || gone.Finding.Status != "resolved" {
		t.Fatalf("resolved event wrong: %+v", gone)
	}
	if strings.Contains(string(b), `"secret"`) {
		t.Fatal("secret-like evidence exported")
	}
}

func TestHFSChannelEvidenceNone(t *testing.T) {
	d := Digest{Module: "rulehawk", Opened: []core.Finding{{
		Fingerprint: "a", Check: "c", Title: "t", Target: "x", Severity: core.SeverityMedium,
		Evidence: map[string]any{"line": "permit ip any any", "src_ip": "198.51.100.1"},
	}}}
	evs := Events(hfs.Meta{}, d, hfs.Options{Evidence: hfs.EvidenceNone})
	if len(evs) != 1 || evs[0].Finding.Evidence != nil || evs[0].SrcIP != "198.51.100.1" {
		t.Fatalf("%+v", evs)
	}
}

func TestHFSChannelSkipsEmptyDigest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.ndjson")
	ch := &HFSChannel{Sink: &sink.File{Path: p}}
	if err := ch.Send(context.Background(), Digest{Module: "rulehawk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("empty digest created a file")
	}
}
