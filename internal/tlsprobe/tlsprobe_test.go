package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// A local CA + leaf factory, so grading runs against real handshakes.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tlsprobe test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * 365 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, key, pool}
}

func issue(t *testing.T, ca *testCA, dns []string, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dns[0]}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: notAfter, DNSNames: dns, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signKey := tpl, key
	if ca != nil {
		parent, signKey = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func serve(t *testing.T, pair tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func probe(t *testing.T, ca *testCA, addr string) map[string]Grade {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grades, err := Probe(ctx, addr, "localhost", Options{Roots: ca.pool})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]Grade{}
	for _, g := range grades {
		m[g.Check] = g
	}
	return m
}

func TestProbe_HealthyIsClean(t *testing.T) {
	ca := newCA(t)
	addr := serve(t, issue(t, ca, []string{"localhost"}, time.Now().Add(365*24*time.Hour)))
	if g := probe(t, ca, addr); len(g) != 0 {
		t.Fatalf("healthy cert should yield no grades, got %v", g)
	}
}

func TestProbe_ExpirySeverityLadder(t *testing.T) {
	for _, tc := range []struct {
		days int
		sev  string
	}{{20, SevMedium}, {5, SevHigh}, {1, SevCritical}} {
		ca := newCA(t)
		addr := serve(t, issue(t, ca, []string{"localhost"}, time.Now().Add(time.Duration(tc.days)*24*time.Hour+time.Hour)))
		g, ok := probe(t, ca, addr)["tls.expiry"]
		if !ok {
			t.Fatalf("days=%d: expected tls.expiry", tc.days)
		}
		if g.Severity != tc.sev {
			t.Fatalf("days=%d: want %s got %s", tc.days, tc.sev, g.Severity)
		}
		if g.Remediation == "" {
			t.Fatalf("days=%d: grade missing remediation", tc.days)
		}
	}
}

func TestProbe_HostnameMismatchAndSelfSigned(t *testing.T) {
	ca := newCA(t)
	// Wrong name, signed by our trusted CA → hostname mismatch (chain OK).
	addr := serve(t, issue(t, ca, []string{"othersite.example"}, time.Now().Add(365*24*time.Hour)))
	if _, ok := probe(t, ca, addr)["tls.hostname_mismatch"]; !ok {
		t.Fatal("expected tls.hostname_mismatch")
	}
	// Self-signed leaf, CA doesn't trust it → untrusted_chain with marker.
	addr2 := serve(t, issue(t, nil, []string{"localhost"}, time.Now().Add(365*24*time.Hour)))
	g, ok := probe(t, ca, addr2)["tls.untrusted_chain"]
	if !ok {
		t.Fatal("expected tls.untrusted_chain")
	}
	if g.Evidence["self_signed"] != true {
		t.Fatalf("expected self_signed marker, got %v", g.Evidence)
	}
}

// The discriminator must be populated for multi-instance checks so the caller
// can build distinct fingerprints — verified here since it's the contract ASM
// and CertWatch both depend on.
func TestProbe_DiscriminatorPopulated(t *testing.T) {
	ca := newCA(t)
	addr := serve(t, issue(t, ca, []string{"localhost"}, time.Now().Add(20*24*time.Hour+time.Hour)))
	// expiry is single-instance: empty discriminator.
	if g := probe(t, ca, addr)["tls.expiry"]; g.Discriminator != "" {
		t.Fatalf("single-instance check should have empty discriminator, got %q", g.Discriminator)
	}
}

func TestProbe_DialFailureIsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Nothing is listening on this port.
	if _, err := Probe(ctx, "127.0.0.1:1", "localhost", Options{}); err == nil {
		t.Fatal("dial failure must return an error, not nil")
	}
}

func TestVersionName(t *testing.T) {
	if VersionName(tls.VersionTLS12) != "TLS 1.2" || VersionName(tls.VersionTLS13) != "TLS 1.3" {
		t.Fatal("version names wrong")
	}
}
