package aiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validEvidence() EvidencePacket {
	finding, _ := json.Marshal(RuleHawkFinding{
		ID:               "f-0142",
		Kind:             "rule.shadowed",
		RuleIndex:        14,
		RuleText:         "permit ip 172.16.8.0/21 any",
		ShadowsRuleIndex: 8,
		ShadowedRuleText: "deny ip host 172.16.9.31 any",
	})
	return EvidencePacket{
		Feature:  FeatureRuleHawkExplainFinding,
		Product:  "rulehawk",
		Finding:  finding,
		Language: "en",
	}
}

// chatCompletionFixture builds a minimal, valid OpenAI-shaped response
// whose message content is the given Explanation, matching what a real
// llama.cpp server constrained by the grammar would send.
func chatCompletionFixture(t *testing.T, exp Explanation) []byte {
	t.Helper()
	content, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal fixture explanation: %v", err)
	}
	resp := chatCompletionResponse{
		Choices: []struct {
			Message chatMessage `json:"message"`
		}{
			{Message: chatMessage{Role: "assistant", Content: string(content)}},
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal fixture response: %v", err)
	}
	return body
}

func TestExplain_HappyPath_OverwritesDisclaimer(t *testing.T) {
	var gotBody chatCompletionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(chatCompletionFixture(t, Explanation{
			ExplanationText: "Rule 14 is never reached because rule 8 already denies the same host.",
			WhatToVerify:    []string{"Confirm host 172.16.9.31 is still the one that must stay blocked."},
			// Deliberately wrong/paraphrased — the client must not trust this.
			Disclaimer: "this is fine, trust me",
		}))
	}))
	defer srv.Close()

	c := New(srv.URL, WithGrammar("root ::= object"))
	exp, err := c.Explain(context.Background(), validEvidence())
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if exp.Disclaimer != CanonicalDisclaimer {
		t.Errorf("Disclaimer = %q, want the canonical disclaimer regardless of model output", exp.Disclaimer)
	}
	if exp.ExplanationText == "" {
		t.Error("ExplanationText is empty")
	}
	if len(exp.WhatToVerify) == 0 {
		t.Error("WhatToVerify is empty")
	}

	// The request actually sent must carry the grounding system prompt,
	// the grammar, and the evidence packet as the user message — this is
	// what makes spec §7 real rather than aspirational.
	if len(gotBody.Messages) != 2 || gotBody.Messages[0].Role != "system" {
		t.Fatalf("expected [system, user] messages, got %+v", gotBody.Messages)
	}
	if !strings.Contains(gotBody.Messages[0].Content, "Use ONLY the fields inside the evidence packet") {
		t.Error("system prompt missing the grounding rule")
	}
	if !strings.Contains(gotBody.Messages[1].Content, "f-0142") {
		t.Error("user message does not contain the evidence packet")
	}
	if gotBody.Grammar != "root ::= object" {
		t.Errorf("Grammar = %q, want the grammar passed via WithGrammar", gotBody.Grammar)
	}
}

func TestExplain_SidecarUnreachable_IsUnavailable(t *testing.T) {
	// Nothing listens here: a closed httptest server's address is
	// guaranteed free immediately after Close().
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close()

	c := New(addr, WithMaxRetries(1), WithRetryBackoff(10*time.Millisecond))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true", err)
	}
}

func TestExplain_ServerError_RetriesThenUnavailable(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(2), WithRetryBackoff(5*time.Millisecond))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true for repeated HTTP 500", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 { // initial attempt + 2 retries
		t.Errorf("server received %d calls, want 3 (1 initial + MaxRetries=2)", got)
	}
}

func TestExplain_BadRequest_DoesNotRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"unknown feature"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(3), WithRetryBackoff(5*time.Millisecond))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if IsUnavailable(err) {
		t.Errorf("HTTP 400 must not be classified as unavailable (it is a caller bug, not a down sidecar): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("server received %d calls, want exactly 1 — a 4xx must never be retried", got)
	}
}

func TestExplain_MalformedTopLevelJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(0))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if IsUnavailable(err) {
		t.Error("malformed JSON from an answering server is not 'unavailable'")
	}
}

func TestExplain_ModelContentNotSchemaJSON(t *testing.T) {
	// This is exactly the failure mode the GBNF grammar exists to
	// prevent server-side — the client must still not trust it blindly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := chatCompletionResponse{
			Choices: []struct {
				Message chatMessage `json:"message"`
			}{
				{Message: chatMessage{Role: "assistant", Content: "Sure! Here is my explanation in plain prose, not JSON."}},
			},
		}
		body, _ := json.Marshal(resp)
		w.Write(body)
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(0))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error when model content is not the required JSON schema")
	}
}

func TestExplain_EmptyExplanationField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(chatCompletionFixture(t, Explanation{ExplanationText: "   "}))
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxRetries(0))
	_, err := c.Explain(context.Background(), validEvidence())
	if err == nil {
		t.Fatal("expected an error for a blank explanation field")
	}
}

func TestExplain_ValidatesEvidencePacket(t *testing.T) {
	c := New("http://127.0.0.1:1") // never dialed — validation fails first
	cases := []struct {
		name string
		ev   EvidencePacket
	}{
		{"missing feature", EvidencePacket{Product: "rulehawk", Finding: json.RawMessage(`{}`)}},
		{"missing product", EvidencePacket{Feature: FeatureRuleHawkExplainFinding, Finding: json.RawMessage(`{}`)}},
		{"missing finding", EvidencePacket{Feature: FeatureRuleHawkExplainFinding, Product: "rulehawk"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Explain(context.Background(), tc.ev); err == nil {
				t.Error("expected a validation error, got nil")
			}
		})
	}
}

func TestExplain_DefaultMaxTokensIsSent(t *testing.T) {
	// Regression test for a real bug found by testing this client against
	// a live sidecar: with no cap, a slow CPU-bound model can generate
	// past the caller's own timeout even though the grammar guarantees
	// it eventually stops. New must set a non-zero default so this never
	// silently regresses to "unbounded" again.
	var gotBody chatCompletionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write(chatCompletionFixture(t, Explanation{ExplanationText: "ok"}))
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.Explain(context.Background(), validEvidence()); err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if gotBody.MaxTokens <= 0 {
		t.Errorf("MaxTokens = %d, want a positive default", gotBody.MaxTokens)
	}
}

func TestExplain_WithMaxTokensOverride(t *testing.T) {
	var gotBody chatCompletionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write(chatCompletionFixture(t, Explanation{ExplanationText: "ok"}))
	}))
	defer srv.Close()

	c := New(srv.URL, WithMaxTokens(64))
	if _, err := c.Explain(context.Background(), validEvidence()); err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if gotBody.MaxTokens != 64 {
		t.Errorf("MaxTokens = %d, want 64 (from WithMaxTokens)", gotBody.MaxTokens)
	}
}

func TestExplain_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(srv.URL, WithMaxRetries(2), WithRetryBackoff(5*time.Millisecond))
	_, err := c.Explain(ctx, validEvidence())
	if err == nil {
		t.Fatal("expected an error for an already-canceled context")
	}
}

func TestClient_NewNeverDials(t *testing.T) {
	// Constructing a client for an address nothing listens on must not
	// block or panic — spec §3: "if hexward-ai is absent [...] the
	// product functions exactly as it does today."
	done := make(chan struct{})
	go func() {
		_ = New("http://127.0.0.1:1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("New() blocked — it must never dial the sidecar")
	}
}
