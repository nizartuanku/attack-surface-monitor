package core

import (
	"context"
	"time"
)

// Collector is the ONLY thing a new product must implement. Everything generic
// a product needs — scheduling, concurrency, storage, dedup, diffing,
// notification, display — is provided by the core. Adding product #2 means
// writing a new Collector, not a new application.
type Collector interface {
	// Describe returns static metadata. Called once at registration.
	Describe() ModuleInfo

	// ValidateTarget parses and normalises raw user input into a canonical
	// Target, or returns a user-facing error explaining what's wrong. Called
	// when a user adds a target — never during a scan.
	ValidateTarget(raw string) (Target, error)

	// Collect performs one check of one target and returns findings. This is
	// where ALL the product's intelligence lives. It MUST:
	//   - respect ctx cancellation/timeout,
	//   - be side-effect free with respect to the target beyond reading it,
	//   - fill only collector-owned Finding fields,
	//   - return a deterministic Fingerprint per finding.
	// An empty slice with nil error means "checked, all clear". A non-nil
	// error means the scan itself failed (host unreachable, timeout) — NOT
	// that a problem was found. A problem found is a Finding.
	Collect(ctx context.Context, t Target) ([]Finding, error)

	// Diff is OPTIONAL. Return nil to defer to the core's fingerprint-based
	// diff. Implement it only when "what changed since last scan" is a
	// first-class product output (e.g. Attack Surface Monitor).
	Diff(previous, current []Finding) []Change
}

// ModuleInfo is a collector's static metadata, read once at registration.
type ModuleInfo struct {
	ID              string        // "certwatch" — becomes Finding.Module
	Name            string        // "CertWatch"
	Version         string        // semver
	TargetKind      string        // human hint: "host:port", "domain", "device"
	DefaultInterval time.Duration // smart default; user may override (paid tier)
	ResolveAfter    int           // consecutive-absent scans before auto-resolve (>=1)
}

// ResolveAfterOrDefault returns the effective auto-resolve threshold, defaulting
// to 1 when a module leaves it unset. One is right for deterministic checks;
// flappy modules raise it to avoid resolve/reopen churn (decision #2).
func (m ModuleInfo) ResolveAfterOrDefault() int {
	if m.ResolveAfter < 1 {
		return 1
	}
	return m.ResolveAfter
}

// Target is a validated, canonicalised scan target.
type Target struct {
	Raw       string            // exactly what the user typed
	Canonical string            // normalised, e.g. "example.com:443"
	Meta      map[string]string // collector-specific parsed bits
}

// Change is an entry produced by an optional Collector.Diff implementation.
type Change struct {
	Kind    string // "added" | "removed" | "changed"
	Finding Finding
	Detail  string
}
