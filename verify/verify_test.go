package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func TestNewChallenge_NormalizesAndIssues(t *testing.T) {
	c, err := NewChallenge("HTTPS://Example.com:443/path", t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Domain != "example.com" {
		t.Fatalf("domain not normalized: %q", c.Domain)
	}
	if c.State != StatePending || c.Token == "" {
		t.Fatalf("challenge malformed: %+v", c)
	}
	if !strings.HasPrefix(c.DNSRecordName(), "_sentinel-verify.") {
		t.Fatalf("bad DNS record name: %s", c.DNSRecordName())
	}
	if c.DNSRecordValue() != "sentinel-verify="+c.Token {
		t.Fatalf("bad DNS value: %s", c.DNSRecordValue())
	}
}

func TestSatisfied_DNS(t *testing.T) {
	c, _ := NewChallenge("example.com", t0)
	v := Verifier{
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			if name != c.DNSRecordName() {
				return nil, errors.New("nxdomain")
			}
			return []string{"unrelated-record", c.DNSRecordValue()}, nil
		},
	}
	ok, method, err := v.Satisfied(context.Background(), c)
	if err != nil || !ok || method != MethodDNS {
		t.Fatalf("DNS proof should satisfy: ok=%v method=%v err=%v", ok, method, err)
	}
}

func TestSatisfied_HTTP(t *testing.T) {
	c, _ := NewChallenge("example.com", t0)
	v := Verifier{
		FetchHTTP: func(ctx context.Context, url string) (string, error) {
			if url != c.HTTPURL() {
				return "", errors.New("404")
			}
			return c.HTTPFileContents() + "\n", nil // trailing whitespace tolerated
		},
	}
	ok, method, err := v.Satisfied(context.Background(), c)
	if err != nil || !ok || method != MethodHTTP {
		t.Fatalf("HTTP proof should satisfy: ok=%v method=%v err=%v", ok, method, err)
	}
}

func TestSatisfied_WrongTokenIsNotSatisfied(t *testing.T) {
	c, _ := NewChallenge("example.com", t0)
	v := Verifier{
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return []string{"sentinel-verify=the-wrong-token"}, nil
		},
		FetchHTTP: func(ctx context.Context, url string) (string, error) {
			return "sentinel-verify=also-wrong", nil
		},
	}
	ok, _, err := v.Satisfied(context.Background(), c)
	if err != nil || ok {
		t.Fatalf("wrong token must not satisfy: ok=%v err=%v", ok, err)
	}
}

func TestSatisfied_MissingIsFalseNotError(t *testing.T) {
	c, _ := NewChallenge("example.com", t0)
	v := Verifier{
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return nil, errors.New("no such host")
		},
	}
	ok, _, err := v.Satisfied(context.Background(), c)
	if ok || err != nil {
		t.Fatalf("missing record should be (false, nil), got ok=%v err=%v", ok, err)
	}
}

func TestMemStore_Roundtrip(t *testing.T) {
	s := NewMemStore()
	c, _ := NewChallenge("example.com", t0)
	if err := s.Put("asm", c); err != nil {
		t.Fatal(err)
	}
	// Another module's domain is isolated.
	other, _ := NewChallenge("example.com", t0)
	s.Put("othermod", other)

	got, ok, _ := s.Get("asm", "example.com")
	if !ok || got.Token != c.Token {
		t.Fatalf("roundtrip failed: %+v ok=%v", got, ok)
	}
	list, _ := s.List("asm")
	if len(list) != 1 {
		t.Fatalf("cross-module leak: %v", list)
	}
	s.Delete("asm", "example.com")
	if _, ok, _ := s.Get("asm", "example.com"); ok {
		t.Fatal("delete failed")
	}
}
