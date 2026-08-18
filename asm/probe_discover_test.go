package asm

import (
	"context"
	"errors"
	"testing"

	"github.com/nizartuanku/attack-surface-monitor/internal/tlsprobe"
)

func TestClassify_SeverityByService(t *testing.T) {
	cases := []struct {
		port int
		sev  string
		sens bool
	}{
		{5432, tlsprobe.SevCritical, true},  // PostgreSQL
		{27017, tlsprobe.SevCritical, true}, // MongoDB
		{3389, tlsprobe.SevHigh, true},      // RDP
		{23, tlsprobe.SevHigh, true},        // Telnet
		{22, tlsprobe.SevLow, false},        // SSH — common, inventory
		{443, tlsprobe.SevLow, false},       // HTTPS — inventory
	}
	for _, c := range cases {
		e, ok := classifyPort("host.example", c.port)
		if !ok {
			t.Fatalf("port %d missing from catalog", c.port)
		}
		if e.Severity != c.sev {
			t.Fatalf("port %d: want %s got %s", c.port, c.sev, e.Severity)
		}
		if e.Remediation == "" {
			t.Fatalf("port %d: exposure must carry remediation", c.port)
		}
		// Sensitive services name the service in the title; inventory says "Open port".
		if c.sens && e.Title[:1] == "O" {
			t.Fatalf("port %d: sensitive service should not read as inventory: %q", c.port, e.Title)
		}
	}
	if _, ok := classifyPort("h", 12345); ok {
		t.Fatal("uncatalogued port must not classify")
	}
}

// Discovery: CT names are filtered to the domain, wildcards normalised, and only
// resolving names are kept — all without touching the network.
func TestDiscover_CTFilteringAndResolution(t *testing.T) {
	d := &ctDNSDiscoverer{
		ctBudget: 100,
		httpGet: func(ctx context.Context, url string) (string, error) {
			// crt.sh-style JSON: some in-domain, a wildcard, and an unrelated name.
			return `[
				{"name_value":"api.example.com"},
				{"name_value":"*.example.com"},
				{"name_value":"dead.example.com"},
				{"name_value":"evil.attacker.test"}
			]`, nil
		},
		resolve: func(ctx context.Context, host string) bool {
			return host != "dead.example.com" // "dead" no longer resolves
		},
	}
	assets, err := d.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range assets.Hostnames {
		got[h] = true
	}
	if !got["api.example.com"] || !got["example.com"] {
		t.Fatalf("expected api + root, got %v", assets.Hostnames)
	}
	if got["dead.example.com"] {
		t.Fatal("non-resolving name must be dropped")
	}
	if got["evil.attacker.test"] {
		t.Fatal("out-of-domain name must be filtered out")
	}
	// Wildcard "*.example.com" normalises to "example.com" (already present).
}

// If CT is unavailable, discovery still returns the root (never empty).
func TestDiscover_CTFailureStillReturnsRoot(t *testing.T) {
	d := &ctDNSDiscoverer{
		ctBudget: 100,
		httpGet:  func(ctx context.Context, url string) (string, error) { return "", errors.New("crt.sh down") },
		resolve:  func(ctx context.Context, host string) bool { return true },
	}
	assets, err := d.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.Hostnames) != 1 || assets.Hostnames[0] != "example.com" {
		t.Fatalf("CT failure should still yield the root, got %v", assets.Hostnames)
	}
}
