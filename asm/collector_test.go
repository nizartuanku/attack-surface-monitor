package asm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/sched"
	"github.com/nizartuanku/attack-surface-monitor/store"
	"github.com/nizartuanku/attack-surface-monitor/verify"
)

var clk = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// fakeDiscoverer returns a fixed asset set.
type fakeDiscoverer struct{ hosts []string }

func (f fakeDiscoverer) Discover(ctx context.Context, root string) (Assets, error) {
	return Assets{Hostnames: f.hosts, Sources: []string{"test"}}, nil
}

// fakeProber returns fixed exposures per host.
type fakeProber struct{ byHost map[string][]Exposure }

func (f fakeProber) Probe(ctx context.Context, host string) ([]Exposure, error) {
	return f.byHost[host], nil
}

func newASM(t *testing.T, st verify.Store, disc Discoverer, prober Prober, verifier verify.Verifier) *ASM {
	t.Helper()
	return &ASM{
		Verifier: verifier, Store: st, Discoverer: disc, Prober: prober,
		now: func() time.Time { return clk },
	}
}

func checks(fs []core.Finding) map[string]core.Finding {
	m := map[string]core.Finding{}
	for _, f := range fs {
		m[f.Check] = f
	}
	return m
}

// The gate: an unverified domain must NEVER be probed — Collect stays silent.
func TestCollect_UnverifiedDomainIsNeverProbed(t *testing.T) {
	st := verify.NewMemStore()
	probed := false
	prober := probeFunc(func(host string) []Exposure { probed = true; return nil })
	a := newASM(t, st, fakeDiscoverer{[]string{"example.com"}}, prober,
		verify.Verifier{}) // no lookups → never satisfied

	tgt, err := a.ValidateTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := a.Collect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("unverified domain must yield no findings, got %v", findings)
	}
	if probed {
		t.Fatal("unverified domain must NOT be probed")
	}
	// The challenge must have been recorded as pending.
	ch, ok, _ := st.Get("asm", "example.com")
	if !ok || ch.State != verify.StatePending {
		t.Fatalf("expected a pending challenge, got %+v ok=%v", ch, ok)
	}
}

// Once the DNS proof appears, the next scan flips to verified and probes.
func TestCollect_VerifiedScanDiscoversAndProbes(t *testing.T) {
	st := verify.NewMemStore()
	a := newASM(t, st,
		fakeDiscoverer{[]string{"example.com", "db.example.com"}},
		fakeProber{byHost: map[string][]Exposure{
			"db.example.com": {classifyMust(t, "db.example.com", 5432)},
		}},
		verify.Verifier{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			// Return the correct token so verification succeeds.
			ch, _, _ := st.Get("asm", "example.com")
			return []string{ch.DNSRecordValue()}, nil
		}})

	tgt, _ := a.ValidateTarget("example.com")
	findings, err := a.Collect(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}

	// Domain is now verified.
	if ch, _, _ := st.Get("asm", "example.com"); ch.State != verify.StateVerified {
		t.Fatalf("domain should be verified after satisfied challenge")
	}
	// Two asset findings + one critical exposure (PostgreSQL).
	byCheck := checks(findings)
	if _, ok := byCheck["asm.asset"]; !ok {
		t.Fatalf("expected asset findings, got %v", findings)
	}
	exp, ok := byCheck["asm.exposure"]
	if !ok {
		t.Fatalf("expected an exposure finding")
	}
	if exp.Severity != core.SeverityCritical {
		t.Fatalf("exposed PostgreSQL must be critical, got %s", exp.Severity)
	}
	if exp.Remediation == "" || exp.Target != "example.com" {
		t.Fatalf("exposure finding malformed: %+v", exp)
	}
}

// Findings must all carry Target = root domain so the engine's per-target
// reconcile/auto-resolve works, with the specific host in the title.
func TestCollect_FindingsTargetIsRootDomain(t *testing.T) {
	st := verify.NewMemStore()
	a := verifiedASM(t, st,
		fakeDiscoverer{[]string{"a.example.com", "b.example.com"}},
		fakeProber{byHost: map[string][]Exposure{
			"a.example.com": {classifyMust(t, "a.example.com", 3389)}, // RDP high
		}})
	tgt, _ := a.ValidateTarget("example.com")
	findings, _ := a.Collect(context.Background(), tgt)
	for _, f := range findings {
		if f.Target != "example.com" {
			t.Fatalf("finding target must be root domain, got %q (title %q)", f.Target, f.Title)
		}
		if f.Fingerprint == "" {
			t.Fatal("finding missing fingerprint")
		}
	}
}

// End-to-end through the framework: a verified domain's exposure lands in the
// store, and a second scan with the port closed auto-resolves it (the diff).
func TestEndToEnd_ExposureAppearsThenAutoResolves(t *testing.T) {
	st := verify.NewMemStore()
	ms := store.NewMemStore()
	// Prober whose result we can flip between scans.
	live := true
	prober := probeFunc(func(host string) []Exposure {
		if host == "db.example.com" && live {
			return []Exposure{classifyMust(t, "db.example.com", 6379)} // Redis critical
		}
		return nil
	})
	a := &ASM{
		Store: st, Discoverer: fakeDiscoverer{[]string{"db.example.com"}}, Prober: prober,
		Verifier: verify.Verifier{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			ch, _, _ := st.Get("asm", "example.com")
			return []string{ch.DNSRecordValue()}, nil
		}},
		now: func() time.Time { return clk },
	}

	engine := store.NewEngine(ms)
	sc := sched.New(engine, sched.Config{ScanTimeout: 5 * time.Second})
	if err := sc.Register(a); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.AddTarget("asm", "example.com"); err != nil {
		t.Fatal(err)
	}

	// Scan 1: Redis exposure opens.
	if err := sc.ScanNow(context.Background(), "asm"); err != nil {
		t.Fatal(err)
	}
	open, _ := ms.ListOpen("asm")
	var sawExposure bool
	for _, r := range open {
		if r.Check == "asm.exposure" && r.Severity == core.SeverityCritical {
			sawExposure = true
		}
	}
	if !sawExposure {
		t.Fatalf("scan1 should record the critical Redis exposure, open=%v", open)
	}

	// Redis is locked down; ResolveAfter=2 means two clean scans to resolve.
	live = false
	sc.ScanNow(context.Background(), "asm")
	sc.ScanNow(context.Background(), "asm")

	open, _ = ms.ListOpen("asm")
	for _, r := range open {
		if r.Check == "asm.exposure" {
			t.Fatalf("closed Redis exposure should have auto-resolved, still open: %+v", r)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	a := New(verify.NewMemStore())
	for _, tc := range []struct{ in, want string }{
		{"Example.com", "example.com"},
		{"https://sub.example.com/path", "sub.example.com"},
		{" example.com. ", "example.com"},
	} {
		got, err := a.ValidateTarget(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got.Canonical != tc.want {
			t.Fatalf("%q → %q, want %q", tc.in, got.Canonical, tc.want)
		}
	}
	for _, bad := range []string{"", "localhost", "10.0.0.1"} {
		if _, err := a.ValidateTarget(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

// --- test helpers -----------------------------------------------------------

// probeFunc adapts a func to the Prober interface.
type probeFunc func(host string) []Exposure

func (f probeFunc) Probe(ctx context.Context, host string) ([]Exposure, error) {
	return f(host), nil
}

func classifyMust(t *testing.T, host string, port int) Exposure {
	t.Helper()
	e, ok := classifyPort(host, port)
	if !ok {
		t.Fatalf("port %d not in catalog", port)
	}
	return e
}

// verifiedASM returns an ASM whose verifier always confirms ownership.
func verifiedASM(t *testing.T, st verify.Store, disc Discoverer, prober Prober) *ASM {
	t.Helper()
	return newASM(t, st, disc, prober,
		verify.Verifier{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			for _, ch := range mustList(t, st) {
				if name == ch.DNSRecordName() {
					return []string{ch.DNSRecordValue()}, nil
				}
			}
			return nil, errors.New("nxdomain")
		}})
}

func mustList(t *testing.T, st verify.Store) []verify.Challenge {
	t.Helper()
	l, err := st.List("asm")
	if err != nil {
		t.Fatal(err)
	}
	return l
}
