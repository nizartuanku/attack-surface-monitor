// Package tlsprobe is the shared TLS grading engine for the Sentinel line.
// It dials a host, retrieves the certificate chain and negotiated parameters,
// and returns module-neutral Grade verdicts. CertWatch and Attack Surface
// Monitor both consume it: each maps Grade → its own core.Finding with its own
// module id, fingerprint, and framing. Improving a check here improves every
// product that grades TLS — one place to change, many products better.
//
// This package intentionally knows nothing about core.Finding, the scheduler,
// or the store. It is pure "dial + grade → verdicts".
package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Severity values mirror core.Severity's string form so a caller can wrap a
// Grade's Severity directly (core.Severity(g.Severity)) without a lookup.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// Grade is one TLS verdict, module-neutral. The caller turns it into a finding:
// Fingerprint = Fingerprint(module, target, Check, Discriminator).
type Grade struct {
	Check         string         // e.g. "tls.expiry", "tls.weak_cipher"
	Severity      string         // one of the Sev* constants
	Title         string         // one human-facing line
	Remediation   string         // what to do — never empty
	Discriminator string         // distinguishes two grades of the same Check on the same host
	Evidence      map[string]any // detail-view context
}

// Options tunes a probe.
type Options struct {
	// Roots overrides the trust store for chain verification. nil = system pool.
	Roots *x509.CertPool
	// ProbeLegacy adds a capped TLS 1.0/1.1 acceptance probe (one extra dial).
	ProbeLegacy bool
	// Now is injectable for deterministic expiry grading; nil = time.Now.
	Now func() time.Time
}

// Probe dials addr (host:port) with the given serverName (for SNI + hostname
// grading) and returns the graded verdicts. A dial failure is returned as an
// error — that means the scan itself failed (host unreachable), NOT that a
// problem was found. A found problem is a Grade.
func Probe(ctx context.Context, addr, serverName string, opts Options) ([]Grade, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	state, err := dial(ctx, addr, serverName, tls.VersionTLS10, 0)
	if err != nil {
		return nil, err
	}
	leaf := state.PeerCertificates[0]
	t := now()

	var out []Grade
	out = append(out, gradeExpiry(leaf, t)...)
	out = append(out, gradeHostname(leaf, serverName)...)
	out = append(out, gradeChain(state, opts.Roots, t)...)
	out = append(out, gradeProtocol(state)...)
	out = append(out, gradeCipher(state)...)
	out = append(out, gradeKeyStrength(leaf)...)
	out = append(out, gradeSignature(leaf)...)

	if opts.ProbeLegacy {
		out = append(out, probeLegacy(ctx, addr, serverName)...)
	}
	return out, nil
}

// --- dialing ----------------------------------------------------------------

func dial(ctx context.Context, addr, serverName string, minVer, maxVer uint16) (tls.ConnectionState, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // grading needs the chain even when invalid
			MinVersion:         minVer,
			MaxVersion:         maxVer,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tls.ConnectionState{}, fmt.Errorf("server presented no certificates")
	}
	return state, nil
}

// --- individual grades ------------------------------------------------------

func gradeExpiry(leaf *x509.Certificate, now time.Time) []Grade {
	if now.After(leaf.NotAfter) {
		days := int(now.Sub(leaf.NotAfter).Hours() / 24)
		return []Grade{{
			Check: "tls.expired", Severity: SevCritical,
			Title: fmt.Sprintf("Certificate EXPIRED %d day(s) ago", days),
			Remediation: "Replace this certificate immediately — clients are already failing. " +
				"If you use ACME/Let's Encrypt, the renewal automation has broken; check its logs.",
			Evidence: evidence(leaf, map[string]any{"expired_days_ago": days}),
		}}
	}
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	if daysLeft > 30 {
		return nil
	}
	sev := SevMedium
	switch {
	case daysLeft <= 1:
		sev = SevCritical
	case daysLeft <= 7:
		sev = SevHigh
	}
	return []Grade{{
		Check: "tls.expiry", Severity: sev,
		Title: fmt.Sprintf("Certificate expires in %d day(s)", daysLeft),
		Remediation: "Renew the certificate before it expires. " +
			"If renewal is automated (ACME), verify the timer/cron actually runs and can reach the CA.",
		Evidence: evidence(leaf, map[string]any{"days_left": daysLeft}),
	}}
}

func gradeHostname(leaf *x509.Certificate, host string) []Grade {
	if host == "" || net.ParseIP(host) != nil {
		return nil // IP targets rarely appear in SANs; skip to avoid noise
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return []Grade{{
			Check: "tls.hostname_mismatch", Severity: SevHigh,
			Title: fmt.Sprintf("Certificate does not cover %q", host),
			Remediation: "Reissue the certificate with this hostname in its SAN list, " +
				"or point the service at the certificate that actually covers it.",
			Evidence: evidence(leaf, map[string]any{"requested_host": host, "sans": leaf.DNSNames}),
		}}
	}
	return nil
}

func gradeChain(state tls.ConnectionState, roots *x509.CertPool, now time.Time) []Grade {
	leaf := state.PeerCertificates[0]
	selfSigned := len(state.PeerCertificates) == 1 &&
		leaf.Issuer.String() == leaf.Subject.String()

	intermediates := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}
	opts := x509.VerifyOptions{
		Roots:         roots, // nil → system pool
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err == nil {
		return nil
	}

	if !selfSigned && len(state.PeerCertificates) == 1 {
		return []Grade{{
			Check: "tls.incomplete_chain", Severity: SevMedium,
			Title: "Server sends no intermediate certificates",
			Remediation: "Configure the server to send the full chain (leaf + intermediates). " +
				"Most CAs ship a 'fullchain' bundle — deploy that file instead of the bare certificate.",
			Evidence: evidence(leaf, map[string]any{"presented_chain_length": 1}),
		}}
	}

	title := "Certificate chain is not trusted"
	if selfSigned {
		title = "Certificate is self-signed"
	}
	return []Grade{{
		Check: "tls.untrusted_chain", Severity: SevHigh,
		Title: title,
		Remediation: "Install a certificate from a trusted CA (e.g. via ACME/Let's Encrypt), " +
			"or distribute your private CA to every client that must trust this service.",
		Evidence: evidence(leaf, map[string]any{
			"self_signed":            selfSigned,
			"presented_chain_length": len(state.PeerCertificates),
		}),
	}}
}

func gradeProtocol(state tls.ConnectionState) []Grade {
	if state.Version >= tls.VersionTLS12 {
		return nil
	}
	v := VersionName(state.Version)
	return []Grade{{
		Check: "tls.weak_protocol", Severity: SevHigh, Discriminator: v,
		Title: fmt.Sprintf("Connection negotiated obsolete %s", v),
		Remediation: "Disable TLS 1.0/1.1 on this service and require TLS 1.2 or newer. " +
			"Modern clients have not needed legacy TLS since 2020.",
		Evidence: map[string]any{"negotiated": v},
	}}
}

func probeLegacy(ctx context.Context, addr, serverName string) []Grade {
	state, err := dial(ctx, addr, serverName, tls.VersionTLS10, tls.VersionTLS11)
	if err != nil {
		return nil // refusing legacy TLS is the GOOD outcome
	}
	v := VersionName(state.Version)
	return []Grade{{
		Check: "tls.legacy_protocol", Severity: SevMedium,
		Title: fmt.Sprintf("Server still accepts legacy %s", v),
		Remediation: "Raise the server's minimum TLS version to 1.2. The main connection may use " +
			"TLS 1.3, but accepting 1.0/1.1 leaves a downgrade path open and fails compliance scans.",
		Evidence: map[string]any{"accepted_version": v},
	}}
}

func gradeCipher(state tls.ConnectionState) []Grade {
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == state.CipherSuite {
			name := tls.CipherSuiteName(state.CipherSuite)
			return []Grade{{
				Check: "tls.weak_cipher", Severity: SevHigh, Discriminator: name,
				Title: fmt.Sprintf("Weak cipher suite negotiated: %s", name),
				Remediation: "Remove this cipher suite from the server configuration and prefer " +
					"AEAD suites (AES-GCM or ChaCha20-Poly1305).",
				Evidence: map[string]any{"cipher": name},
			}}
		}
	}
	return nil
}

func gradeKeyStrength(leaf *x509.Certificate) []Grade {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 2048 {
			return []Grade{{
				Check: "tls.weak_key", Severity: SevHigh, Discriminator: fmt.Sprintf("rsa-%d", bits),
				Title: fmt.Sprintf("RSA key too small: %d bits", bits),
				Remediation: "Reissue the certificate with an RSA key of at least 2048 bits " +
					"(or switch to an ECDSA P-256 key).",
				Evidence: map[string]any{"algorithm": "RSA", "bits": bits},
			}}
		}
	case *ecdsa.PublicKey:
		_ = pub // P-256+ curves are currently fine
	}
	return nil
}

func gradeSignature(leaf *x509.Certificate) []Grade {
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
		alg := leaf.SignatureAlgorithm.String()
		return []Grade{{
			Check: "tls.legacy_signature", Severity: SevHigh, Discriminator: alg,
			Title: fmt.Sprintf("Certificate signed with obsolete algorithm: %s", alg),
			Remediation: "Reissue the certificate — SHA-1/MD5 signatures are forgeable and rejected " +
				"by modern clients. Any current CA will sign with SHA-256 or better.",
			Evidence: map[string]any{"signature_algorithm": alg},
		}}
	}
	return nil
}

// --- helpers ----------------------------------------------------------------

func evidence(leaf *x509.Certificate, extra map[string]any) map[string]any {
	ev := map[string]any{
		"subject":    leaf.Subject.String(),
		"issuer":     leaf.Issuer.String(),
		"not_before": leaf.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  leaf.NotAfter.UTC().Format(time.RFC3339),
		"serial":     leaf.SerialNumber.String(),
	}
	for k, v := range extra {
		ev[k] = v
	}
	return ev
}

// VersionName renders a TLS version constant as a human string. Exported so
// callers can reuse it in their own evidence/labels.
func VersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
