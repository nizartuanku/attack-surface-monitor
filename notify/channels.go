package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// httpClient is shared by all HTTP channels; kept injectable for tests.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// --- Generic webhook (the free-tier channel) --------------------------------

// WebhookChannel POSTs a structured JSON payload to any URL. This is the free
// edition's one channel: maximally composable, zero vendor lock.
type WebhookChannel struct {
	URL string
	// Secret, when set, is sent as the X-Sentinel-Token header so receivers
	// can authenticate the caller.
	Secret string
}

func (w *WebhookChannel) Name() string { return "webhook" }

// webhookPayload is the stable wire format. Versioned so future fields never
// break existing receivers.
type webhookPayload struct {
	Version  int              `json:"version"`
	Module   string           `json:"module"`
	At       time.Time        `json:"at"`
	Opened   []webhookFinding `json:"opened,omitempty"`
	Resolved []webhookFinding `json:"resolved,omitempty"`
}

type webhookFinding struct {
	Target      string         `json:"target"`
	Check       string         `json:"check"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Remediation string         `json:"remediation"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

func (w *WebhookChannel) Send(ctx context.Context, d Digest) error {
	payload := webhookPayload{Version: 1, Module: d.Module, At: d.At}
	for _, f := range d.Opened {
		payload.Opened = append(payload.Opened, toWire(f))
	}
	for _, f := range d.Resolved {
		payload.Resolved = append(payload.Resolved, toWire(f))
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		req.Header.Set("X-Sentinel-Token", w.Secret)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func toWire(f core.Finding) webhookFinding {
	return webhookFinding{
		Target: f.Target, Check: f.Check, Severity: string(f.Severity),
		Title: f.Title, Remediation: f.Remediation, Evidence: f.Evidence,
	}
}

// --- Slack (paid tier) ------------------------------------------------------

// SlackChannel posts the shared text rendering to a Slack incoming webhook.
type SlackChannel struct {
	WebhookURL string
}

func (s *SlackChannel) Name() string { return "slack" }

func (s *SlackChannel) Send(ctx context.Context, d Digest) error {
	body, err := json.Marshal(map[string]string{"text": FormatText(d)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("slack returned %s", resp.Status)
	}
	return nil
}

// --- Telegram (paid tier) ---------------------------------------------------

// TelegramChannel sends the shared text rendering via the Bot API.
type TelegramChannel struct {
	BotToken string
	ChatID   string
	// BaseURL overrides the API host (tests). Empty = api.telegram.org.
	BaseURL string
}

func (t *TelegramChannel) Name() string { return "telegram" }

func (t *TelegramChannel) Send(ctx context.Context, d Digest) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", base, t.BotToken)
	body, err := json.Marshal(map[string]string{
		"chat_id": t.ChatID,
		"text":    FormatText(d),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("telegram returned %s", resp.Status)
	}
	return nil
}
