// Package asm is the Attack Surface Monitor product: it discovers a verified
// domain's external assets, probes what's exposed, and reports it as findings
// on the Sentinel Core engine. The framework's fingerprint-based reconcile turns
// each scan into the daily diff for free — a newly open port appears as a new
// finding, a closed one auto-resolves — so this collector represents each asset
// and exposure as a finding and lets the core do the diffing.
//
// The authorization gate is enforced here: a domain is not probed until its
// ownership challenge (verify package) is satisfied. While pending, Collect is
// silent; the pending challenge and its instructions are surfaced by the UI.
package asm

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/internal/tlsprobe"
	"github.com/nizartuanku/attack-surface-monitor/verify"
)

const moduleID = "asm"

// Severity aliases (kept local so probe.go/collector.go don't import tlsprobe
// just for the strings).
const (
	sevCritical = tlsprobe.SevCritical
	sevHigh     = tlsprobe.SevHigh
	sevMedium   = tlsprobe.SevMedium
	sevLow      = tlsprobe.SevLow
	sevInfo     = tlsprobe.SevInfo
)

// ASM implements core.Collector.
type ASM struct {
	Verifier   verify.Verifier
	Store      verify.Store
	Discoverer Discoverer
	Prober     Prober

	// TLSRoots overrides the trust store for the TLS posture pass. nil = system.
	TLSRoots *x509.CertPool
	// now is injectable for deterministic tests.
	now func() time.Time
}

// New returns a production-configured ASM with real network implementations.
// The caller supplies the challenge Store (shared with the web layer).
func New(store verify.Store) *ASM {
	return &ASM{
		Verifier:   verify.Verifier{LookupTXT: lookupTXT, FetchHTTP: httpGet},
		Store:      store,
		Discoverer: newDiscoverer(),
		Prober:     newDialProber(),
		now:        time.Now,
	}
}

func (a *ASM) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              moduleID,
		Name:            "Attack Surface Monitor",
		Version:         "0.1.0",
		TargetKind:      "domain",
		DefaultInterval: 24 * time.Hour, // attack surface changes slowly; be polite
		ResolveAfter:    2,              // network flaps happen — need 2 absent scans to resolve
	}
}

// ValidateTarget accepts a bare root domain and, on first sight, issues a
// pending ownership challenge. The domain is not scannable until verified.
func (a *ASM) ValidateTarget(raw string) (core.Target, error) {
	d := normalizeDomain(raw)
	if d == "" {
		return core.Target{}, fmt.Errorf("enter a domain like example.com")
	}
	if net.ParseIP(d) != nil {
		return core.Target{}, fmt.Errorf("enter a domain name, not an IP address")
	}
	if !strings.Contains(d, ".") {
		return core.Target{}, fmt.Errorf("enter a full domain, e.g. example.com")
	}

	// Issue a challenge if this domain has none yet (idempotent on restore).
	if _, ok, _ := a.Store.Get(moduleID, d); !ok {
		ch, err := verify.NewChallenge(d, a.clock())
		if err != nil {
			return core.Target{}, err
		}
		if err := a.Store.Put(moduleID, ch); err != nil {
			return core.Target{}, err
		}
	}
	return core.Target{Raw: raw, Canonical: d, Meta: map[string]string{"domain": d}}, nil
}

// Collect gates on verification, then discovers assets and probes exposures.
// All findings carry Target = the root domain (so the engine's per-target
// reconcile/auto-resolve works); the specific asset host lives in the title and
// evidence. A dial/discovery failure inside a verified scan is a scan error.
func (a *ASM) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	domain := t.Canonical

	ch, ok, err := a.Store.Get(moduleID, domain)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // no challenge on record → nothing to do
	}
	if ch.State != verify.StateVerified {
		// Re-check the challenge on this scan; flip to verified if satisfied.
		satisfied, _, _ := a.Verifier.Satisfied(ctx, ch)
		if !satisfied {
			return nil, nil // still pending → stay silent, never probe
		}
		now := a.clock()
		ch.State = verify.StateVerified
		ch.VerifiedAt = &now
		_ = a.Store.Put(moduleID, ch)
	}

	assets, err := a.Discoverer.Discover(ctx, domain)
	if err != nil {
		return nil, err
	}

	var out []core.Finding
	for _, host := range assets.Hostnames {
		// Inventory: each live asset is an info finding, so a NEW subdomain shows
		// up in the diff and a REMOVED one auto-resolves.
		out = append(out, a.finding(domain, "asm.asset", host,
			sevInfo, fmt.Sprintf("Asset in scope: %s", host),
			"Confirm this host should be internet-facing and is accounted for.",
			map[string]any{"host": host, "sources": assets.Sources}))

		exposures, perr := a.Prober.Probe(ctx, host)
		if perr != nil {
			continue // one unreachable host must not fail the whole scan
		}
		for _, e := range exposures {
			out = append(out, a.finding(domain, "asm.exposure",
				fmt.Sprintf("%s:%d/%s", e.Host, e.Port, e.Service),
				e.Severity, e.Title, e.Remediation, e.Evidence))

			// TLS posture on HTTPS-ish ports, via the shared engine.
			if e.Port == 443 || e.Port == 8443 {
				out = append(out, a.tlsFindings(ctx, domain, e.Host, e.Port)...)
			}
		}
	}
	return out, nil
}

// Diff returns nil: the fingerprint-based reconcile in the core already yields
// the daily diff (added/removed/changed) from the asset & exposure findings.
func (a *ASM) Diff(prev, cur []core.Finding) []core.Change { return nil }

// --- helpers ----------------------------------------------------------------

func (a *ASM) tlsFindings(ctx context.Context, domain, host string, port int) []core.Finding {
	addr := net.JoinHostPort(host, itoa(port))
	grades, err := tlsprobe.Probe(ctx, addr, host, tlsprobe.Options{Roots: a.TLSRoots, Now: a.now})
	if err != nil {
		return nil // TLS unreachable on this asset is not itself a finding
	}
	out := make([]core.Finding, 0, len(grades))
	for _, g := range grades {
		out = append(out, a.finding(domain, g.Check,
			host+"|"+g.Discriminator,
			g.Severity, host+": "+g.Title, g.Remediation,
			mergeEvidence(g.Evidence, map[string]any{"host": host, "port": port})))
	}
	return out
}

// finding builds a core.Finding with a fingerprint scoped to the root domain
// but discriminated by the specific asset, so distinct assets are distinct
// findings under one reconcile target.
func (a *ASM) finding(domain, check, discriminator, sev, title, remediation string, ev map[string]any) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint(moduleID, domain, check, discriminator),
		Target:      domain,
		Check:       check,
		Title:       title,
		Severity:    core.Severity(sev),
		Remediation: remediation,
		Evidence:    ev,
	}
}

func (a *ASM) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func mergeEvidence(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// normalizeDomain mirrors verify's normalization for the target layer.
func normalizeDomain(in string) string {
	s := strings.TrimSpace(strings.ToLower(in))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "]") {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

// lookupTXT is the default DNS TXT resolver used by the verifier.
func lookupTXT(ctx context.Context, name string) ([]string, error) {
	var r net.Resolver
	return r.LookupTXT(ctx, name)
}
