package aiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeLanguage(t *testing.T) {
	cases := map[string]string{
		"": "en", "en": "en", "EN-us": "en", "fr": "en",
		"id": "id", "ID": "id", "id-ID": "id", "id_ID": "id", "in": "id",
		"ind": "id", "Indonesian": "id", "bahasa": "id", " Bahasa Indonesia ": "id",
	}
	for in, want := range cases {
		if got := NormalizeLanguage(in); got != want {
			t.Errorf("NormalizeLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeEvidence_DropsSecretsAtEveryLevel(t *testing.T) {
	in := map[string]any{
		"host":         "mail.example.com",
		"Password":     "hunter2",
		"api_key":      "sk-123",
		"AuthToken":    "abc",
		"sessionID":    "s1",
		"PrivateKey":   "-----BEGIN",
		"days_left":    12,
		"nested":       map[string]any{"client_secret": "x", "port": 443},
		"certificates": []any{map[string]any{"cn": "a", "signature": "zz"}},
	}
	out := SanitizeEvidence(in)
	b, _ := json.Marshal(out)
	s := string(b)
	for _, leak := range []string{"hunter2", "sk-123", "abc", "s1", "BEGIN", "client_secret", "signature", "zz"} {
		if strings.Contains(s, leak) {
			t.Errorf("sanitised evidence still contains %q: %s", leak, s)
		}
	}
	for _, keep := range []string{"mail.example.com", "days_left", "443", `"cn":"a"`} {
		if !strings.Contains(s, keep) {
			t.Errorf("sanitised evidence lost harmless value %q: %s", keep, s)
		}
	}
	if _, ok := in["Password"]; !ok {
		t.Error("SanitizeEvidence must not modify its input")
	}
}

func TestSanitizeEvidence_Bounds(t *testing.T) {
	in := map[string]any{}
	for i := 0; i < 40; i++ {
		in[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = i
	}
	in["long"] = strings.Repeat("é", 1000)
	list := make([]any, 50)
	for i := range list {
		list[i] = i
	}
	in["aaa_list"] = list
	in["aab_deep"] = map[string]any{"l2": map[string]any{"l3": map[string]any{"l4": "x"}}}

	out := SanitizeEvidence(in)
	if len(out) != maxEvidenceKeys {
		t.Fatalf("kept %d keys, want %d", len(out), maxEvidenceKeys)
	}
	if l, ok := out["aaa_list"].([]any); !ok || len(l) != maxEvidenceList {
		t.Errorf("list not capped to %d: %#v", maxEvidenceList, out["aaa_list"])
	}
	deep, _ := json.Marshal(out["aab_deep"])
	if !strings.Contains(string(deep), "nested too deep") {
		t.Errorf("deep nesting not cut: %s", deep)
	}
	if SanitizeEvidence(nil) != nil || SanitizeEvidence(map[string]any{"token": "x"}) != nil {
		t.Error("empty or all-secret evidence must sanitise to nil")
	}
	if got := len([]rune(truncateRunes(strings.Repeat("é", 1000), maxEvidenceString))); got != maxEvidenceString+1 {
		t.Errorf("truncateRunes kept %d runes, want %d (+ ellipsis)", got, maxEvidenceString+1)
	}
}

func TestNewFindingPacket(t *testing.T) {
	if _, err := NewFindingPacket("", "en", CoreFinding{Check: "c", Title: "t", Severity: "high"}); err == nil {
		t.Error("empty product must be rejected")
	}
	if _, err := NewFindingPacket("certlight", "en", CoreFinding{Check: "c", Severity: "high"}); err == nil {
		t.Error("missing title must be rejected")
	}
	p, err := NewFindingPacket("certlight", "id-ID", CoreFinding{
		Check: "cert.expiry", Title: "Certificate expires in 12 days", Severity: "high",
		Target:   "mail.example.com:443",
		Evidence: map[string]any{"days_left": 12, "private_key_path": "/etc/ssl/k.pem"},
	})
	if err != nil {
		t.Fatalf("NewFindingPacket: %v", err)
	}
	if p.Feature != FeatureExplainFinding || p.Product != "certlight" || p.Language != "id" {
		t.Errorf("unexpected packet header: %+v", p)
	}
	if strings.Contains(string(p.Finding), "k.pem") {
		t.Errorf("secret-like evidence leaked into packet: %s", p.Finding)
	}
}

func TestExplain_LanguageInstructionAPIKeyAndThinking(t *testing.T) {
	var got chatCompletionRequest
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(chatCompletionFixture(t, Explanation{ExplanationText: "Sertifikat hampir kedaluwarsa.", WhatToVerify: []string{"Cek jadwal perpanjangan."}}))
	}))
	defer srv.Close()

	p, _ := NewFindingPacket("certlight", "id", CoreFinding{Check: "cert.expiry", Title: "Expiring", Severity: "high"})
	c := New(srv.URL, WithAPIKey(" k-123 "), WithDisableThinking())
	if _, err := c.Explain(context.Background(), p); err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if auth != "Bearer k-123" {
		t.Errorf("Authorization = %q, want Bearer k-123", auth)
	}
	if v, ok := got.ChatTemplateKwargs["enable_thinking"]; !ok || v != false {
		t.Errorf("chat_template_kwargs = %#v, want enable_thinking=false", got.ChatTemplateKwargs)
	}
	if len(got.Messages) != 2 || !strings.Contains(got.Messages[0].Content, "Bahasa Indonesia") ||
		!strings.HasSuffix(got.Messages[1].Content, languageInstruction("id")) {
		t.Errorf("Indonesian instruction missing from system prompt or end of user turn: %#v", got.Messages)
	}
	if !strings.Contains(got.Messages[0].Content, "hexward.explain_finding") {
		t.Error("system prompt lacks the generic feature rule")
	}
}

func TestExplain_DefaultsSendNoAuthNoKwargs(t *testing.T) {
	var raw map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&raw)
		w.Write(chatCompletionFixture(t, Explanation{ExplanationText: "ok"}))
	}))
	defer srv.Close()
	if _, err := New(srv.URL).Explain(context.Background(), validEvidence()); err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if auth != "" {
		t.Errorf("unexpected Authorization header %q", auth)
	}
	if _, ok := raw["chat_template_kwargs"]; ok {
		t.Error("chat_template_kwargs must be omitted unless WithDisableThinking is set (strict endpoints reject unknown fields)")
	}
}

func TestSeverityInstruction(t *testing.T) {
	p, _ := NewFindingPacket("dmarcwatch", "en", CoreFinding{Check: "dmarc.no-data", Title: "No reports", Severity: "info"})
	if got := severityInstruction(p); !strings.Contains(got, `"info"`) {
		t.Errorf("severityInstruction = %q, want the exact engine word", got)
	}
	if got := severityInstruction(validEvidence()); got != "" {
		t.Errorf("pilot features must not get a severity instruction, got %q", got)
	}
}
