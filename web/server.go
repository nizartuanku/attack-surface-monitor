// Package web serves the dashboard: a JSON API plus an embedded single-file
// UI. The design rule from the framework spec §7 is enforced here — the home
// screen is decisions, not data: the API's /summary endpoint answers "how bad
// is it, what changed, what do I do", and raw evidence sits one click deeper.
//
// v0 scope: single-user, bind to localhost by default. Multi-user auth is a
// Team-tier feature that layers on later without changing the API shape.
package web

import (
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/license"
	"github.com/nizartuanku/attack-surface-monitor/sched"
	"github.com/nizartuanku/attack-surface-monitor/store"
	"github.com/nizartuanku/attack-surface-monitor/verify"
)

//go:embed static
var staticFS embed.FS

// Server wires the dashboard over the running system.
type Server struct {
	Module    core.ModuleInfo // the product this binary ships
	Store     store.Store
	Scheduler *sched.Scheduler

	// Targets, when set, persists target add/remove so a restart restores the
	// user's configuration. nil = in-memory only (tests, ephemeral runs).
	Targets store.TargetStore

	// TierLimits, when set, overrides the license package's global limits with
	// this product's own per-tier caps (e.g. ASM free = 1 domain, not 10). nil
	// falls back to the activation's limits — CertWatch keeps working unchanged.
	TierLimits map[license.Tier]license.Limits

	// Verify, when set, exposes GET /api/verification so the dashboard can show
	// pending domain-ownership challenges with copy-paste instructions. Only
	// products that gate on ownership (ASM) set this; others leave it nil and
	// the endpoint reports "not applicable".
	Verify verify.Store

	// Licensing: the issuer public key baked into the build, and where the
	// user's key is persisted. Activation is resolved at construction and
	// refreshed when a new key is submitted.
	IssuerPub   ed25519.PublicKey
	LicenseFile string

	mu         sync.RWMutex
	activation license.Activation
}

// NewServer resolves the initial activation (reading LicenseFile if present)
// and returns a ready Server.
func NewServer(mod core.ModuleInfo, st store.Store, sc *sched.Scheduler, pub ed25519.PublicKey, licenseFile string) *Server {
	s := &Server{
		Module: mod, Store: st, Scheduler: sc,
		IssuerPub: pub, LicenseFile: licenseFile,
	}
	key := ""
	if licenseFile != "" {
		if b, err := os.ReadFile(licenseFile); err == nil {
			key = strings.TrimSpace(string(b))
		}
	}
	s.activation = license.Activate(pub, mod.ID, key, time.Now())
	return s
}

// Activation returns the current resolved activation.
func (s *Server) Activation() license.Activation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activation
}

// effLimits resolves the limits in force: this product's per-tier table if set,
// otherwise the activation's own limits.
func (s *Server) effLimits() license.Limits {
	act := s.Activation()
	if s.TierLimits != nil {
		if l, ok := s.TierLimits[act.Tier]; ok {
			return l
		}
	}
	return act.Limits
}

func canAdd(l license.Limits, current int) bool {
	return l.MaxTargets == 0 || current < l.MaxTargets
}

// Handler builds the full http.Handler (API + static UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("POST /api/findings/status", s.handleFindingStatus)
	mux.HandleFunc("GET /api/targets", s.handleListTargets)
	mux.HandleFunc("POST /api/targets", s.handleAddTarget)
	mux.HandleFunc("DELETE /api/targets", s.handleRemoveTarget)
	mux.HandleFunc("POST /api/scan", s.handleScanNow)
	mux.HandleFunc("GET /api/license", s.handleGetLicense)
	mux.HandleFunc("POST /api/license", s.handleSetLicense)
	mux.HandleFunc("GET /api/verification", s.handleVerification)

	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	return mux
}

// --- handlers ---------------------------------------------------------------

type summaryResponse struct {
	Product    string         `json:"product"`
	Tier       string         `json:"tier"`
	Notice     string         `json:"notice,omitempty"`
	Counts     map[string]int `json:"counts"` // by severity, open only
	OpenTotal  int            `json:"open_total"`
	Targets    int            `json:"targets"`
	MaxTargets int            `json:"max_targets"` // 0 = unlimited
	CanScanNow bool           `json:"can_scan_now"`
	TargetKind string         `json:"target_kind"` // UI input placeholder hint
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	open, err := s.Store.ListOpen(s.Module.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "store error")
		return
	}
	counts := map[string]int{}
	for _, rec := range open {
		counts[string(rec.Severity)]++
	}
	act := s.Activation()
	lim := s.effLimits()
	writeJSON(w, summaryResponse{
		Product:    s.Module.Name,
		Tier:       string(act.Tier),
		Notice:     act.Notice,
		Counts:     counts,
		OpenTotal:  len(open),
		Targets:    len(s.Scheduler.ListTargets(s.Module.ID)),
		MaxTargets: lim.MaxTargets,
		CanScanNow: lim.ScanNow,
		TargetKind: s.Module.TargetKind,
	})
}

// handleVerification lists domain-ownership challenges (ASM). Products without
// a Verify store report an empty, not-applicable result so the shared UI simply
// hides its verification panel.
func (s *Server) handleVerification(w http.ResponseWriter, r *http.Request) {
	if s.Verify == nil {
		writeJSON(w, map[string]any{"applicable": false, "challenges": []any{}})
		return
	}
	challenges, err := s.Verify.List(s.Module.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "verification store error")
		return
	}
	out := make([]map[string]any, 0, len(challenges))
	for _, c := range challenges {
		out = append(out, map[string]any{
			"domain":        c.Domain,
			"state":         string(c.State),
			"dns_record":    c.DNSRecordName(),
			"dns_value":     c.DNSRecordValue(),
			"http_url":      c.HTTPURL(),
			"http_contents": c.HTTPFileContents(),
			"instructions":  c.Instructions(),
		})
	}
	writeJSON(w, map[string]any{"applicable": true, "challenges": out})
}

type findingJSON struct {
	Fingerprint string         `json:"fingerprint"`
	Target      string         `json:"target"`
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Status      string         `json:"status"`
	Remediation string         `json:"remediation"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	recs, err := s.Store.ListAll(s.Module.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "store error")
		return
	}
	out := make([]findingJSON, 0, len(recs))
	for _, rec := range recs {
		// Hide resolved findings older than a day; closure is news, not history.
		if rec.Status == core.StatusResolved &&
			(rec.ResolvedAt == nil || time.Since(*rec.ResolvedAt) > 24*time.Hour) {
			continue
		}
		out = append(out, findingJSON{
			Fingerprint: rec.Fingerprint, Target: rec.Target, Check: rec.Check,
			Title: rec.Title, Severity: string(rec.Severity), Status: string(rec.Status),
			Remediation: rec.Remediation, Evidence: rec.Evidence,
			FirstSeen: rec.FirstSeen, LastSeen: rec.LastSeen,
		})
	}
	writeJSON(w, out)
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"` // acknowledged | suppressed | open
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	next := core.FindingStatus(req.Status)
	switch next {
	case core.StatusAcknowledged, core.StatusSuppressed, core.StatusOpen:
	default:
		httpError(w, http.StatusBadRequest, "status must be acknowledged, suppressed, or open")
		return
	}
	rec, ok, err := s.Store.Get(s.Module.ID, req.Fingerprint)
	if err != nil || !ok {
		httpError(w, http.StatusNotFound, "finding not found")
		return
	}
	rec.Status = next
	if err := s.Store.Upsert(rec); err != nil {
		httpError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, map[string]string{"ok": "true"})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets := s.Scheduler.ListTargets(s.Module.ID)
	type tj struct{ Raw, Canonical string }
	out := make([]tj, 0, len(targets))
	for _, t := range targets {
		out = append(out, tj{Raw: t.Raw, Canonical: t.Canonical})
	}
	writeJSON(w, out)
}

func (s *Server) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	current := len(s.Scheduler.ListTargets(s.Module.ID))
	if !canAdd(s.effLimits(), current) {
		httpError(w, http.StatusPaymentRequired,
			"target limit reached for your tier — upgrade to add more")
		return
	}
	t, err := s.Scheduler.AddTarget(s.Module.ID, req.Target)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.Targets != nil {
		if err := s.Targets.SaveTarget(s.Module.ID, t.Raw, t.Canonical); err != nil {
			// The scan is already scheduled; losing persistence deserves a
			// loud error so the user knows a restart would forget this target.
			httpError(w, http.StatusInternalServerError, "target added but could not be persisted")
			return
		}
	}
	writeJSON(w, map[string]string{"canonical": t.Canonical})
}

func (s *Server) handleRemoveTarget(w http.ResponseWriter, r *http.Request) {
	canonical := r.URL.Query().Get("canonical")
	if canonical == "" {
		httpError(w, http.StatusBadRequest, "canonical query parameter required")
		return
	}
	s.Scheduler.RemoveTarget(s.Module.ID, canonical)
	if s.Targets != nil {
		s.Targets.DeleteTarget(s.Module.ID, canonical)
	}
	writeJSON(w, map[string]string{"ok": "true"})
}

func (s *Server) handleScanNow(w http.ResponseWriter, r *http.Request) {
	if !s.effLimits().ScanNow {
		httpError(w, http.StatusPaymentRequired,
			"on-demand scans are a Pro feature — scheduled scans continue as normal")
		return
	}
	if err := s.Scheduler.ScanNow(r.Context(), s.Module.ID); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": "true"})
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	act := s.Activation()
	resp := map[string]any{"tier": string(act.Tier), "notice": act.Notice}
	if act.License != nil {
		resp["email"] = act.License.Email
		resp["expires_at"] = act.License.ExpiresAt
	}
	writeJSON(w, resp)
}

func (s *Server) handleSetLicense(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	key := strings.TrimSpace(req.Key)
	act := license.Activate(s.IssuerPub, s.Module.ID, key, time.Now())
	if act.Tier == license.TierFree && key != "" {
		// Don't persist a bad key; tell the user what happened instead.
		httpError(w, http.StatusBadRequest, act.Notice)
		return
	}
	if s.LicenseFile != "" {
		if err := os.WriteFile(s.LicenseFile, []byte(key+"\n"), 0o600); err != nil {
			httpError(w, http.StatusInternalServerError, "could not persist license key")
			return
		}
	}
	s.mu.Lock()
	s.activation = act
	s.mu.Unlock()
	writeJSON(w, map[string]string{"tier": string(act.Tier)})
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
