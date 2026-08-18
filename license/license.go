// Package license implements offline-first activation for all Sentinel
// products. A license key is a signed statement — "this email bought this tier
// of this product until this date" — verified locally with Ed25519. No phone
// home, ever: a security product that stops working when it cannot reach the
// vendor's server will not be trusted in an isolated network, and running in
// isolated networks is the whole pitch.
//
// Design rules (from the framework spec §6):
//
//   - Keys are cryptographically signed; verification is pure local math.
//   - An EXPIRED key never bricks the product: enforcement falls back to the
//     free tier's limits. Data is never deleted, scanning never stops.
//   - A TAMPERED or foreign key is simply invalid → free tier.
//   - Limits (targets, channels, retention) are enforced by the core through
//     one Enforcer, so individual modules never re-implement policy.
//
// Key wire format:
//
//	SNTL1-<base64url(payload JSON)>.<base64url(ed25519 signature)>
//
// The "SNTL1" prefix versions the whole scheme; a future format bumps it.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tier is the commercial level a license grants.
type Tier string

const (
	TierFree Tier = "free" // no key at all, or any invalid/expired key
	TierPro  Tier = "pro"
	TierTeam Tier = "team"
)

// Limits is what a tier concretely allows. Enforced centrally by Enforcer.
type Limits struct {
	MaxTargets     int      // 0 = unlimited
	RetentionDays  int      // 0 = unlimited
	Channels       []string // notification channels allowed
	MultiUser      bool
	CustomInterval bool // may override the module's default scan interval
	ScanNow        bool // may trigger on-demand scans
}

// TierLimits is the single source of truth for what each tier buys.
// CertWatch's product page must match this table — one place to change.
var TierLimits = map[Tier]Limits{
	TierFree: {
		MaxTargets:    10,
		RetentionDays: 7,
		Channels:      []string{"webhook"},
	},
	TierPro: {
		MaxTargets:     100,
		RetentionDays:  365,
		Channels:       []string{"webhook", "email", "slack", "telegram"},
		CustomInterval: true,
		ScanNow:        true,
	},
	TierTeam: {
		MaxTargets:     0, // unlimited
		RetentionDays:  0, // unlimited
		Channels:       []string{"webhook", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser:      true,
		CustomInterval: true,
		ScanNow:        true,
	},
}

// License is the signed payload inside a key.
type License struct {
	Product   string    `json:"product"` // module id, e.g. "certwatch"
	Tier      Tier      `json:"tier"`    // pro | team
	Email     string    `json:"email"`   // buyer identity (matches Whop order)
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"` // subscription end + grace, baked in at issue time
	// KeyID lets a specific key be superseded (reissue) without a revocation
	// server: the newest IssuedAt wins if a user pastes several keys.
	KeyID string `json:"key_id"`
}

const prefix = "SNTL1-"

// --- issuing (seller side: runs on YOUR machine, never ships) ---------------

// Sign serialises and signs a license, returning the wire-format key string.
func Sign(priv ed25519.PrivateKey, lic License) (string, error) {
	if lic.Product == "" || lic.Tier == "" {
		return "", errors.New("license needs product and tier")
	}
	payload, err := json.Marshal(lic)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return prefix +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// GenerateKeypair creates the issuer keypair. The private key stays with the
// seller; the public key is embedded in each product build.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// --- verifying (product side: pure local math) ------------------------------

var (
	ErrMalformed    = errors.New("license key is malformed")
	ErrBadSignature = errors.New("license signature is invalid")
	ErrWrongProduct = errors.New("license is for a different product")
	ErrExpired      = errors.New("license has expired")
)

// Verify checks a key against the embedded public key and the running product.
// On success it returns the License. All failures return an error; callers use
// Activate for the never-brick fallback behaviour.
func Verify(pub ed25519.PublicKey, product, key string, now time.Time) (License, error) {
	if !strings.HasPrefix(key, prefix) {
		return License{}, ErrMalformed
	}
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(key), prefix), ".", 2)
	if len(parts) != 2 {
		return License{}, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return License{}, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return License{}, ErrMalformed
	}
	// A free/open-source build bakes no issuer key (empty pub). ed25519.Verify
	// panics on a wrong-length key, so treat any non-standard key as a plain
	// signature failure — the caller downgrades to free limits, never crashes.
	if len(pub) != ed25519.PublicKeySize {
		return License{}, ErrBadSignature
	}
	if !ed25519.Verify(pub, payload, sig) {
		return License{}, ErrBadSignature
	}
	var lic License
	if err := json.Unmarshal(payload, &lic); err != nil {
		return License{}, ErrMalformed
	}
	if lic.Product != product {
		return License{}, fmt.Errorf("%w (key is for %q)", ErrWrongProduct, lic.Product)
	}
	if now.After(lic.ExpiresAt) {
		return lic, ErrExpired // return the license too: caller may show "expired on <date>"
	}
	return lic, nil
}

// --- enforcement ------------------------------------------------------------

// Activation is the resolved state the product runs under.
type Activation struct {
	Tier    Tier
	Limits  Limits
	License *License // nil on free tier
	// Notice is a human sentence worth showing in the UI ("license expired on
	// …, running on free limits"). Empty when nothing needs saying.
	Notice string
}

// Activate resolves a (possibly empty/invalid/expired) key into the activation
// the product runs under. It NEVER returns an error: the philosophy is that a
// licensing problem downgrades gracefully to free, it never stops the product.
func Activate(pub ed25519.PublicKey, product, key string, now time.Time) Activation {
	if strings.TrimSpace(key) == "" {
		return Activation{Tier: TierFree, Limits: TierLimits[TierFree]}
	}
	lic, err := Verify(pub, product, key, now)
	switch {
	case err == nil:
		return Activation{Tier: lic.Tier, Limits: limitsFor(lic.Tier), License: &lic}
	case errors.Is(err, ErrExpired):
		return Activation{
			Tier: TierFree, Limits: TierLimits[TierFree],
			Notice: fmt.Sprintf("License expired on %s — running on free limits. Renew to restore your tier.",
				lic.ExpiresAt.Format("2 Jan 2006")),
		}
	default:
		return Activation{
			Tier: TierFree, Limits: TierLimits[TierFree],
			Notice: "License key is not valid for this product — running on free limits.",
		}
	}
}

func limitsFor(t Tier) Limits {
	if l, ok := TierLimits[t]; ok {
		return l
	}
	return TierLimits[TierFree] // unknown tier in a signed key → safest floor
}

// CanAddTarget reports whether one more target fits within the activation.
func (a Activation) CanAddTarget(current int) bool {
	return a.Limits.MaxTargets == 0 || current < a.Limits.MaxTargets
}

// AllowsChannel reports whether a notification channel may be configured.
func (a Activation) AllowsChannel(name string) bool {
	for _, c := range a.Limits.Channels {
		if c == name {
			return true
		}
	}
	return false
}

// RetentionCutoff returns the earliest resolved_at the store should keep, or
// zero time for unlimited retention. Feed this to store.PruneResolvedBefore.
func (a Activation) RetentionCutoff(now time.Time) time.Time {
	if a.Limits.RetentionDays == 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -a.Limits.RetentionDays)
}
