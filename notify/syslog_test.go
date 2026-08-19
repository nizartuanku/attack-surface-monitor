package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

func syslogDigest() Digest {
	return Digest{
		Module: "decoy",
		At:     time.Date(2026, 8, 19, 13, 52, 1, 0, time.UTC),
		Opened: []core.Finding{{
			Target: "80ba4e8d4e38", Check: "decoy.trip", Severity: core.SeverityCritical,
			Title:       "DECOY TRIPPED: legacy-admin touched by 198.51.100.66",
			Remediation: "Investigate now.",
			Evidence:    map[string]any{"source_ip": "198.51.100.66", "port": 8080},
		}},
		Resolved: []core.Finding{{
			Target: "example.com:443", Check: "tls.expiry", Severity: core.SeverityMedium,
			Title: "Certificate expires in 11 day(s)",
		}},
	}
}

func TestSyslogLineShape(t *testing.T) {
	s := &SyslogChannel{Addr: "127.0.0.1:5514", Hostname: "sentinel"}
	lines := s.lines(syslogDigest())
	if len(lines) != 2 {
		t.Fatalf("want one line per finding, got %d", len(lines))
	}
	open := lines[0]
	// local0 (16) * 8 + crit (2) = 130
	if !strings.HasPrefix(open, "<130>Aug 19 13:52:01 sentinel decoy[") {
		t.Errorf("header wrong: %q", open)
	}
	for _, want := range []string{
		"severity=critical", "check=decoy.trip", "status=open",
		"src=198.51.100.66", "product=decoy",
	} {
		if !strings.Contains(open, want) {
			t.Errorf("missing %q in %q", want, open)
		}
	}
	if !strings.HasSuffix(open, "\n") {
		t.Error("lines must be newline-terminated so TCP collectors can frame them")
	}
	if !strings.Contains(lines[1], "RESOLVED: ") || !strings.Contains(lines[1], "status=resolved") {
		t.Errorf("resolved line wrong: %q", lines[1])
	}
	// A resolution must not page anyone: notice, not error.
	if !strings.HasPrefix(lines[1], "<133>") {
		t.Errorf("resolved should be notice (16*8+5=133): %q", lines[1])
	}
}

// src= is the field a collector keys on. Emitting a hostname there would make
// every downstream correlation wrong, so it must only appear for real IPs.
func TestSyslogSrcOnlyForRealIPs(t *testing.T) {
	d := syslogDigest()
	d.Opened[0].Evidence = map[string]any{"host": "acme-corp.internal", "port": 5432}
	line := (&SyslogChannel{Hostname: "h"}).lines(d)[0]
	if strings.Contains(line, "src=") {
		t.Errorf("hostname must not be emitted as src: %q", line)
	}
}

// A finding title is attacker-influenced (it can quote a captured value), so a
// newline in it must never become a second syslog frame.
func TestSyslogRejectsFrameInjection(t *testing.T) {
	d := syslogDigest()
	d.Opened[0].Title = "trip\n<13>Aug 19 13:52:01 h evil[1]: forged"
	d.Resolved = nil
	lines := (&SyslogChannel{Hostname: "h"}).lines(d)
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(lines))
	}
	if strings.Count(lines[0], "\n") != 1 {
		t.Errorf("embedded newline survived: %q", lines[0])
	}
}
