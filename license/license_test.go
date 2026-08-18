package license

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func issueKey(t *testing.T, tier Tier, product string, expires time.Time) (string, []byte) {
	t.Helper()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := Sign(priv, License{
		Product: product, Tier: tier, Email: "buyer@example.com",
		IssuedAt: now.AddDate(0, -1, 0), ExpiresAt: expires, KeyID: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func TestSignVerifyRoundtrip(t *testing.T) {
	key, pub := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	lic, err := Verify(pub, "certwatch", key, now)
	if err != nil {
		t.Fatal(err)
	}
	if lic.Tier != TierPro || lic.Email != "buyer@example.com" {
		t.Fatalf("payload mangled: %+v", lic)
	}
}

// One flipped character anywhere must invalidate the key.
func TestTamperedKeyIsRejected(t *testing.T) {
	key, pub := issueKey(t, TierTeam, "certwatch", now.AddDate(1, 0, 0))
	// Tamper with a payload byte (after the prefix).
	i := len(key) / 2
	tampered := key[:i] + flip(key[i:i+1]) + key[i+1:]
	if _, err := Verify(pub, "certwatch", tampered, now); err == nil {
		t.Fatal("tampered key must not verify")
	}
}

func flip(s string) string {
	if s == "A" {
		return "B"
	}
	return "A"
}

// A key signed by someone else's private key must fail against our public key.
func TestForeignSignatureIsRejected(t *testing.T) {
	key, _ := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	otherPub, _, _ := GenerateKeypair()
	if _, err := Verify(otherPub, "certwatch", key, now); err == nil {
		t.Fatal("key signed by a different issuer must not verify")
	}
}

// A CertWatch key must not activate a different product.
func TestWrongProductIsRejected(t *testing.T) {
	key, pub := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	if _, err := Verify(pub, "attack-surface", key, now); err == nil {
		t.Fatal("key for another product must not verify")
	}
}

// THE never-brick rule: an expired key downgrades to free limits with a human
// notice — scanning continues, nothing is deleted, nothing stops.
func TestActivate_ExpiredKeyFallsBackToFree(t *testing.T) {
	key, pub := issueKey(t, TierTeam, "certwatch", now.AddDate(0, 0, -3)) // expired 3 days ago
	a := Activate(pub, "certwatch", key, now)
	if a.Tier != TierFree {
		t.Fatalf("expired key must fall back to free, got %s", a.Tier)
	}
	if a.Limits.MaxTargets != TierLimits[TierFree].MaxTargets {
		t.Fatalf("free limits must apply: %+v", a.Limits)
	}
	if !strings.Contains(a.Notice, "expired") {
		t.Fatalf("user must be told why: %q", a.Notice)
	}
}

func TestActivate_EmptyAndGarbageKeys(t *testing.T) {
	_, pub := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	for _, key := range []string{"", "   ", "not-a-key", "SNTL1-zzz"} {
		a := Activate(pub, "certwatch", key, now)
		if a.Tier != TierFree {
			t.Fatalf("key %q must resolve to free tier, got %s", key, a.Tier)
		}
	}
	// Empty key is the legitimate free edition — no scary notice.
	if a := Activate(pub, "certwatch", "", now); a.Notice != "" {
		t.Fatalf("free edition must not show a warning, got %q", a.Notice)
	}
	// Garbage key IS worth a notice.
	if a := Activate(pub, "certwatch", "garbage", now); a.Notice == "" {
		t.Fatal("invalid key should surface a notice")
	}
}

// The free/open-source edition bakes no issuer key (empty pub). A user pasting
// any license key must downgrade to free limits, never panic ed25519.Verify.
func TestActivate_EmptyPubkeyDoesNotPanic(t *testing.T) {
	key, _ := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	for _, pub := range [][]byte{nil, {}, make([]byte, 5)} {
		a := Activate(pub, "certwatch", key, now) // must not panic
		if a.Tier != TierFree {
			t.Fatalf("empty/short pubkey must resolve to free tier, got %s", a.Tier)
		}
		if a.Notice == "" {
			t.Fatal("a real key that can't be verified should surface a notice")
		}
	}
}

func TestActivate_ValidProUnlocks(t *testing.T) {
	key, pub := issueKey(t, TierPro, "certwatch", now.AddDate(0, 1, 0))
	a := Activate(pub, "certwatch", key, now)
	if a.Tier != TierPro || a.License == nil || a.Notice != "" {
		t.Fatalf("valid pro key should activate cleanly: %+v", a)
	}
	if !a.Limits.ScanNow || !a.Limits.CustomInterval {
		t.Fatalf("pro features missing: %+v", a.Limits)
	}
}

func TestEnforcement_TargetsChannelsRetention(t *testing.T) {
	free := Activation{Tier: TierFree, Limits: TierLimits[TierFree]}
	team := Activation{Tier: TierTeam, Limits: TierLimits[TierTeam]}

	// Targets: free caps at 10; team unlimited.
	if !free.CanAddTarget(9) || free.CanAddTarget(10) {
		t.Fatal("free tier must cap at exactly 10 targets")
	}
	if !team.CanAddTarget(1_000_000) {
		t.Fatal("team tier targets must be unlimited")
	}

	// Channels: free gets webhook only.
	if !free.AllowsChannel("webhook") || free.AllowsChannel("slack") {
		t.Fatal("free tier channels wrong")
	}
	if !team.AllowsChannel("pagerduty") {
		t.Fatal("team should allow pagerduty")
	}

	// Retention: free = 7 days; team unlimited (zero cutoff).
	cut := free.RetentionCutoff(now)
	if want := now.AddDate(0, 0, -7); !cut.Equal(want) {
		t.Fatalf("free retention cutoff wrong: %v", cut)
	}
	if !team.RetentionCutoff(now).IsZero() {
		t.Fatal("team retention must be unlimited")
	}
}

// An unknown tier inside a validly signed key (e.g. issued by a future
// version) must floor to free limits, never explode.
func TestActivate_UnknownTierFloorsToFree(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	key, _ := Sign(priv, License{
		Product: "certwatch", Tier: Tier("platinum"), Email: "x@y.z",
		IssuedAt: now, ExpiresAt: now.AddDate(0, 1, 0),
	})
	a := Activate(pub, "certwatch", key, now)
	if a.Tier != Tier("platinum") {
		t.Fatalf("tier passes through, got %s", a.Tier)
	}
	if a.Limits.MaxTargets != TierLimits[TierFree].MaxTargets {
		t.Fatalf("unknown tier must get free limits: %+v", a.Limits)
	}
}
