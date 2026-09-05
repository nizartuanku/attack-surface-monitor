package asm

import (
	"context"
	"strings"
	"testing"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/verify"
)

// Regression for the hexwardlabs.com case (P-5, 5 Sep 2026): crt.sh held only
// the root name and a wildcard, so every candidate collapsed to the root and the
// scan reported a single asset — while bridge.hexwardlabs.com was live the whole
// time. The wildcard must survive discovery so the report can say why the
// inventory is short instead of implying the domain has one asset.
func TestDiscover_WildcardIsRecordedNotSwallowed(t *testing.T) {
	d := &ctDNSDiscoverer{
		ctBudget: 100,
		httpGet: func(ctx context.Context, url string) (string, error) {
			// Exactly what crt.sh returns for hexwardlabs.com: nothing but the
			// root and a wildcard covering everything under it.
			return `[
				{"name_value":"hexwardlabs.com"},
				{"name_value":"*.hexwardlabs.com"},
				{"name_value":"*.hexwardlabs.com"}
			]`, nil
		},
		resolve: func(ctx context.Context, host string) bool { return true },
	}
	assets, err := d.Discover(context.Background(), "hexwardlabs.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.Wildcards) != 1 || assets.Wildcards[0] != "*.hexwardlabs.com" {
		t.Fatalf("wildcard must be reported once and untrimmed, got %v", assets.Wildcards)
	}
	// The wildcard still contributes its base name, as before.
	var hasRoot bool
	for _, h := range assets.Hostnames {
		if h == "hexwardlabs.com" {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Fatalf("root must remain in the inventory, got %v", assets.Hostnames)
	}
}

// A wildcard from an unrelated domain must not be attributed to this root.
func TestDiscover_ForeignWildcardIsIgnored(t *testing.T) {
	d := &ctDNSDiscoverer{
		ctBudget: 100,
		httpGet: func(ctx context.Context, url string) (string, error) {
			return `[{"name_value":"*.attacker.test"},{"name_value":"api.example.com"}]`, nil
		},
		resolve: func(ctx context.Context, host string) bool { return true },
	}
	assets, err := d.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets.Wildcards) != 0 {
		t.Fatalf("out-of-domain wildcard must be ignored, got %v", assets.Wildcards)
	}
}

// wildcardDiscoverer is a Discoverer that reports a wildcard alongside its hosts.
type wildcardDiscoverer struct {
	hosts     []string
	wildcards []string
}

func (w wildcardDiscoverer) Discover(ctx context.Context, root string) (Assets, error) {
	return Assets{Hostnames: w.hosts, Wildcards: w.wildcards}, nil
}

// The coverage limit must reach the dashboard as its own finding — a short
// inventory with no explanation is a false all-clear.
func TestCollect_WildcardEmitsCoverageLimitFinding(t *testing.T) {
	st := verify.NewMemStore()
	a := newASM(t, st,
		wildcardDiscoverer{
			hosts:     []string{"hexwardlabs.com"},
			wildcards: []string{"*.hexwardlabs.com"},
		},
		fakeProber{byHost: map[string][]Exposure{}},
		verify.Verifier{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			ch, _, _ := st.Get("asm", "hexwardlabs.com")
			return []string{ch.DNSRecordValue()}, nil
		}})

	tgt, err := a.ValidateTarget("hexwardlabs.com")
	if err != nil {
		t.Fatal(err)
	}
	found, err := a.Collect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	var cov *core.Finding
	for i := range found {
		if found[i].Check == "asm.coverage-wildcard" {
			cov = &found[i]
		}
	}
	if cov == nil {
		t.Fatalf("expected an asm.coverage-wildcard finding, got %d findings", len(found))
	}
	if !strings.Contains(cov.Title, "*.hexwardlabs.com") {
		t.Fatalf("finding must name the wildcard, got %q", cov.Title)
	}
	if cov.Remediation == "" {
		t.Fatal("a coverage caveat without guidance is not actionable")
	}
}
