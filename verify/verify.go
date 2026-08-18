// Package verify implements domain-ownership verification — the authorization
// gate that lets Attack Surface Monitor (and any future active scanner) refuse
// to probe a domain until the user proves they control it. Scanning
// infrastructure you don't own is illegal in many jurisdictions and would get
// the product removed from its marketplace, so this gate is designed in, not
// bolted on.
//
// A user adds a domain → gets a Challenge (a unique token to place as a DNS TXT
// record or an HTTP file). The scanner re-checks the challenge on its normal
// cadence; only once satisfied does the domain become scannable. If the token
// later disappears, the domain reverts to pending and scanning pauses.
//
// The Verifier's network calls are injectable, so the whole gate is testable
// without real DNS or HTTP.
package verify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// State is a domain's verification lifecycle.
type State string

const (
	StatePending  State = "pending"  // token issued, not yet confirmed
	StateVerified State = "verified" // ownership confirmed; scanning allowed
)

// Method is how the user proves ownership.
type Method string

const (
	MethodDNS  Method = "dns"  // a TXT record
	MethodHTTP Method = "http" // a file at a well-known path
)

const (
	tokenPrefix = "sentinel-verify="
	dnsLabel    = "_sentinel-verify"
	httpPath    = "/.well-known/sentinel-verify.txt"
)

// Challenge is the ownership proof a domain must satisfy.
type Challenge struct {
	Domain     string
	Token      string // the raw token value (goes after the prefix)
	State      State
	CreatedAt  time.Time
	VerifiedAt *time.Time
}

// DNSRecordName is where the user places the TXT record.
func (c Challenge) DNSRecordName() string { return dnsLabel + "." + c.Domain }

// DNSRecordValue is the exact TXT value the user must set.
func (c Challenge) DNSRecordValue() string { return tokenPrefix + c.Token }

// HTTPURL is the file URL the user may instead serve (either method works).
func (c Challenge) HTTPURL() string { return "http://" + c.Domain + httpPath }

// HTTPFileContents is what that file must contain.
func (c Challenge) HTTPFileContents() string { return tokenPrefix + c.Token }

// Instructions returns a human-readable, copy-pasteable summary for the UI.
func (c Challenge) Instructions() string {
	return fmt.Sprintf(
		"Verify ownership of %s by EITHER:\n"+
			"  DNS  — add a TXT record at %q with value %q\n"+
			"  HTTP — serve %q containing %q\n"+
			"Then it verifies automatically on the next scan.",
		c.Domain, c.DNSRecordName(), c.DNSRecordValue(), c.HTTPURL(), c.HTTPFileContents())
}

// NewChallenge issues a fresh pending challenge for a domain.
func NewChallenge(domain string, now time.Time) (Challenge, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return Challenge{}, fmt.Errorf("empty domain")
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Challenge{}, err
	}
	return Challenge{
		Domain:    d,
		Token:     hex.EncodeToString(b[:]),
		State:     StatePending,
		CreatedAt: now,
	}, nil
}

// Verifier checks whether a challenge is satisfied. Its lookups are injectable.
type Verifier struct {
	// LookupTXT returns the TXT records for a name. Defaults to net.LookupTXT.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// FetchHTTP returns the body served at url. Defaults to a small HTTP GET.
	FetchHTTP func(ctx context.Context, url string) (string, error)
}

// Satisfied reports whether either proof (DNS or HTTP) currently holds. It never
// returns an error for "not found" — only for a lookup that genuinely failed in
// a way the caller might want to log. A false, nil result means "not yet".
func (v Verifier) Satisfied(ctx context.Context, c Challenge) (bool, Method, error) {
	want := c.DNSRecordValue()

	if v.LookupTXT != nil {
		if records, err := v.LookupTXT(ctx, c.DNSRecordName()); err == nil {
			for _, r := range records {
				if strings.TrimSpace(r) == want {
					return true, MethodDNS, nil
				}
			}
		}
	}
	if v.FetchHTTP != nil {
		if body, err := v.FetchHTTP(ctx, c.HTTPURL()); err == nil {
			if strings.TrimSpace(body) == c.HTTPFileContents() {
				return true, MethodHTTP, nil
			}
		}
	}
	return false, "", nil
}

// --- store ------------------------------------------------------------------

// Store persists challenges per module+domain so verification survives restarts.
type Store interface {
	Put(module string, c Challenge) error
	Get(module, domain string) (Challenge, bool, error)
	List(module string) ([]Challenge, error)
	Delete(module, domain string) error
}

// --- helpers ----------------------------------------------------------------

// normalizeDomain lowercases and strips a scheme, path, port, or trailing dot,
// so "HTTPS://Example.com:443/x" and "example.com." both become "example.com".
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
