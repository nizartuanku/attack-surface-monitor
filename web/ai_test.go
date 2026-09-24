package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/license"
	"github.com/nizartuanku/attack-surface-monitor/store"
)

// fakeSidecar answers like a grammar-constrained hexward-ai sidecar and
// records the last request it received.
type fakeSidecar struct {
	srv      *httptest.Server
	calls    atomic.Int32
	lastBody atomic.Value // string
	lastAuth atomic.Value // string
	status   int
}

func newFakeSidecar(t *testing.T) *fakeSidecar {
	t.Helper()
	f := &fakeSidecar{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		f.lastBody.Store(b.String())
		f.lastAuth.Store(r.Header.Get("Authorization"))
		if f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		content, _ := json.Marshal(map[string]any{
			"explanation":    "The certificate on this target expires soon.",
			"what_to_verify": []string{"Confirm the renewal date."},
			"disclaimer":     "model-authored text that must be overwritten",
		})
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": string(content)}}},
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func aiTestServer(t *testing.T, ai *AIAssist, tier license.Tier) (*Server, *httptest.Server) {
	t.Helper()
	ms := store.NewMemStore()
	rec := store.Record{Finding: core.Finding{
		Module: "aitest", Fingerprint: "fp1", Target: "mail.example.com:443",
		Check: "demo.check", Title: "Demo finding", Severity: core.SeverityHigh,
		Status: core.StatusOpen, Remediation: "Fix it.",
		Evidence: map[string]any{"days_left": 12, "api_token": "SECRET-DO-NOT-SEND"},
	}}
	if err := ms.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	s := &Server{Module: core.ModuleInfo{ID: "aitest", Name: "AI Test"}, Store: ms, AI: ai}
	s.activation = license.Activation{Tier: tier}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return s, api
}

func postExplain(t *testing.T, api *httptest.Server, body string) (int, explainResponse) {
	t.Helper()
	resp, err := http.Post(api.URL+"/api/findings/explain", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out explainResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAI_OffByDefault(t *testing.T) {
	ai, err := NewAIAssist(AIConfig{})
	if err != nil || ai != nil {
		t.Fatalf("empty URL must mean AI off, got %v, %v", ai, err)
	}
	_, api := aiTestServer(t, nil, license.TierFree)
	code, out := postExplain(t, api, `{"fingerprint":"fp1"}`)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("AI off: want 200 available=false with a reason, got %d %+v", code, out)
	}
	resp, _ := http.Get(api.URL + "/api/ai")
	var st aiStatusResponse
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Enabled {
		t.Error("/api/ai must report enabled=false when AI Assist is off")
	}
}

func TestAI_RejectsBadURLAndEmptyKey(t *testing.T) {
	if _, err := NewAIAssist(AIConfig{URL: "127.0.0.1:8435"}); err == nil {
		t.Error("URL without scheme must be rejected")
	}
	empty := filepath.Join(t.TempDir(), "k")
	os.WriteFile(empty, []byte("  \n"), 0o600)
	if _, err := NewAIAssist(AIConfig{URL: "http://127.0.0.1:8435", KeyFile: empty}); err == nil {
		t.Error("empty key file must be rejected")
	}
}

func TestAI_ExplainHappyPathSanitisesEvidence(t *testing.T) {
	side := newFakeSidecar(t)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, Language: "id"})
	if err != nil {
		t.Fatal(err)
	}
	_, api := aiTestServer(t, ai, license.TierFree)
	code, out := postExplain(t, api, `{"fingerprint":"fp1"}`)
	if code != http.StatusOK || !out.Available {
		t.Fatalf("want available explanation, got %d %+v", code, out)
	}
	if out.Disclaimer != "AI-generated summary — verify against raw findings" {
		t.Errorf("disclaimer not canonical: %q", out.Disclaimer)
	}
	body, _ := side.lastBody.Load().(string)
	if strings.Contains(body, "SECRET-DO-NOT-SEND") || strings.Contains(body, "api_token") {
		t.Error("secret-like evidence reached the sidecar")
	}
	for _, want := range []string{"hexward.explain_finding", "Demo finding", "days_left", "Bahasa Indonesia"} {
		if !strings.Contains(body, want) {
			t.Errorf("request to sidecar lacks %q", want)
		}
	}
}

func TestAI_KeyedEndpointNeedsPaidTier(t *testing.T) {
	side := newFakeSidecar(t)
	kf := filepath.Join(t.TempDir(), "ai_api_key")
	os.WriteFile(kf, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}

	_, freeAPI := aiTestServer(t, ai, license.TierFree)
	code, out := postExplain(t, freeAPI, `{"fingerprint":"fp1"}`)
	if code != http.StatusOK || out.Available || !strings.Contains(out.Reason, "Pro or Team") {
		t.Fatalf("free tier + keyed endpoint must be refused with a reason, got %d %+v", code, out)
	}
	if side.calls.Load() != 0 {
		t.Fatal("free tier must not send anything to a keyed endpoint")
	}

	_, proAPI := aiTestServer(t, ai, license.TierPro)
	if _, out := postExplain(t, proAPI, `{"fingerprint":"fp1"}`); !out.Available {
		t.Fatalf("pro tier + keyed endpoint must work, got %+v", out)
	}
	if auth, _ := side.lastAuth.Load().(string); auth != "Bearer 0123456789abcdef0123456789abcdef" {
		t.Errorf("Authorization header = %q", auth)
	}
}

func TestAI_SidecarDownDegradesQuietly(t *testing.T) {
	side := newFakeSidecar(t)
	side.status = http.StatusServiceUnavailable
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	s, api := aiTestServer(t, ai, license.TierFree)
	code, out := postExplain(t, api, `{"fingerprint":"fp1"}`)
	if code != http.StatusOK || out.Available {
		t.Fatalf("sidecar 503 must give 200 available=false, got %d %+v", code, out)
	}
	rec, ok, _ := s.Store.Get("aitest", "fp1")
	if !ok || rec.Status != core.StatusOpen || rec.Severity != core.SeverityHigh {
		t.Fatalf("finding must be untouched after an AI failure, got %+v", rec)
	}
}

func TestAI_BadRequests(t *testing.T) {
	side := newFakeSidecar(t)
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	_, api := aiTestServer(t, ai, license.TierFree)
	if code, _ := postExplain(t, api, `{}`); code != http.StatusBadRequest {
		t.Errorf("missing fingerprint: got %d, want 400", code)
	}
	if code, _ := postExplain(t, api, `{"fingerprint":"nope"}`); code != http.StatusNotFound {
		t.Errorf("unknown fingerprint: got %d, want 404", code)
	}
	if side.calls.Load() != 0 {
		t.Error("invalid requests must never reach the sidecar")
	}
}
