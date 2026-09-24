package web

// AI Assist — the optional "Explain this finding" button, backed by the
// hexward-ai sidecar (github.com/nizartuanku/hexward-ai).
//
// The rules this file exists to enforce:
//
//   - The product's own engine stays the ONLY source of findings and
//     severity. Nothing here creates, edits, re-scores or closes a finding;
//     it only asks a local model to narrate one the store already holds.
//   - AI Assist is off unless the operator starts the binary with
//     -ai-assist-url. Off, unreachable, slow, or answering garbage all look
//     the same to the dashboard: {"available": false} with HTTP 200, and the
//     finding list is untouched.
//   - Only a bounded, sanitised copy of one finding leaves the process
//     (aiclient.NewFindingPacket drops secret-like evidence keys and caps
//     strings, lists and nesting). No config files, no credentials.
//   - Edition gating: the free edition talks to a sidecar without an API
//     key (same host or same Docker network). An endpoint that needs a key
//     (a dedicated AI host serving several products, or your own
//     OpenAI-compatible endpoint) is a Pro/Team capability. The check runs
//     on every request, so a licence added at runtime takes effect at once.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/internal/aiclient"
	"github.com/nizartuanku/attack-surface-monitor/license"
)

// AIConfig is what cmd/ passes in from its flags.
type AIConfig struct {
	URL        string // sidecar or endpoint base URL; "" = AI Assist off
	KeyFile    string // file holding an API key; set = keyed endpoint (Pro/Team)
	Language   string // "en" (default) or "id"
	NoThinking bool   // Qwen3 enterprise profiles: skip reasoning mode
}

// AIAssist is the resolved, ready-to-use AI configuration of a Server.
type AIAssist struct {
	Client   *aiclient.Client
	Endpoint string
	Keyed    bool
	Language string
}

// NewAIAssist validates cfg and builds the client. It returns (nil, nil)
// when cfg.URL is empty — AI Assist off is the default, not an error. It
// never dials: an absent sidecar is discovered per request and degrades
// quietly.
func NewAIAssist(cfg AIConfig) (*AIAssist, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("ai-assist-url must be an http(s) base URL such as http://127.0.0.1:8435, got %q", raw)
	}
	opts := []aiclient.Option{
		// CPU inference of a 3-8B model takes tens of seconds; measured
		// 13-53 s per explanation on a CPU-only VM (hexward-ai docs/TIERS.md).
		aiclient.WithTimeout(120 * time.Second),
		// No retries: a timed-out narration retried is another two minutes
		// of a person waiting, not a better answer.
		aiclient.WithMaxRetries(0),
		aiclient.WithMaxTokens(300),
	}
	a := &AIAssist{Endpoint: strings.TrimRight(raw, "/"), Language: aiclient.NormalizeLanguage(cfg.Language)}
	if cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read ai-assist-key-file: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return nil, fmt.Errorf("ai-assist-key-file %s is empty", cfg.KeyFile)
		}
		opts = append(opts, aiclient.WithAPIKey(key))
		a.Keyed = true
	}
	if cfg.NoThinking {
		opts = append(opts, aiclient.WithDisableThinking())
	}
	a.Client = aiclient.New(a.Endpoint, opts...)
	return a, nil
}

func (s *Server) registerAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai", s.handleAIStatus)
	mux.HandleFunc("POST /api/findings/explain", s.handleExplainFinding)
}

// aiAllowed reports whether AI Assist may be used right now, and if not,
// the sentence the dashboard shows instead of the button.
func (s *Server) aiAllowed() (bool, string) {
	if s.AI == nil || s.AI.Client == nil {
		return false, "AI Assist is off. Start with -ai-assist-url to enable it."
	}
	if t := s.Activation().Tier; s.AI.Keyed && t != license.TierPro && t != license.TierTeam {
		return false, "A dedicated AI host or your own endpoint (API key) needs a Pro or Team licence. The free edition works with a hexward-ai sidecar on the same host."
	}
	return true, ""
}

type aiStatusResponse struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
	Language string `json:"language,omitempty"`
	Keyed    bool   `json:"keyed,omitempty"`
}

func (s *Server) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	ok, reason := s.aiAllowed()
	resp := aiStatusResponse{Enabled: ok, Reason: reason}
	if s.AI != nil {
		resp.Language, resp.Keyed = s.AI.Language, s.AI.Keyed
	}
	writeJSON(w, resp)
}

type explainResponse struct {
	Available    bool     `json:"available"`
	Reason       string   `json:"reason,omitempty"`
	Explanation  string   `json:"explanation,omitempty"`
	WhatToVerify []string `json:"what_to_verify,omitempty"`
	Disclaimer   string   `json:"disclaimer,omitempty"`
}

// handleExplainFinding narrates one stored finding. Every failure after the
// request itself is validated answers {"available": false} with HTTP 200 —
// the dashboard shows a quiet note and the finding is never affected.
func (s *Server) handleExplainFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || strings.TrimSpace(req.Fingerprint) == "" {
		httpError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}
	rec, found, err := s.Store.Get(s.Module.ID, req.Fingerprint)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "store error")
		return
	}
	if !found {
		httpError(w, http.StatusNotFound, "no such finding")
		return
	}
	if ok, reason := s.aiAllowed(); !ok {
		writeJSON(w, explainResponse{Available: false, Reason: reason})
		return
	}
	packet, err := aiclient.NewFindingPacket(s.Module.ID, s.AI.Language, aiclient.CoreFinding{
		Fingerprint: rec.Fingerprint,
		Module:      s.Module.ID,
		Check:       rec.Check,
		Title:       rec.Title,
		Target:      rec.Target,
		Severity:    string(rec.Severity),
		Status:      string(rec.Status),
		Remediation: rec.Remediation,
		Evidence:    rec.Evidence,
	})
	if err != nil {
		writeJSON(w, explainResponse{Available: false, Reason: "This finding has no title or severity to explain."})
		return
	}
	exp, err := s.AI.Client.Explain(r.Context(), packet)
	if err != nil {
		writeJSON(w, explainResponse{Available: false, Reason: "The AI Assist sidecar did not answer. The finding is unaffected."})
		return
	}
	writeJSON(w, explainResponse{
		Available:    true,
		Explanation:  exp.ExplanationText,
		WhatToVerify: exp.WhatToVerify,
		Disclaimer:   exp.Disclaimer,
	})
}
