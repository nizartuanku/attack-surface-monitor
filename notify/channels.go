package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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

// --- Syslog (free tier) -----------------------------------------------------

// SyslogChannel emits one RFC 3164 line per finding to a syslog collector over
// UDP or TCP.
//
// This is the channel that lets the Sentinel tools feed each other. Every
// product already speaks findings; Loglight already ingests syslog. Pointing
// one at the other means a Decoy trip and a port scan Loglight saw from the
// same address arrive as one correlated incident instead of two unrelated
// alerts — without anyone writing glue.
//
// One line per finding is deliberate. A single digest line would be one event
// to a log pipeline no matter how many findings it carried, and per-finding
// fields (severity, check, source address) are what downstream correlation
// keys on.
type SyslogChannel struct {
	// Addr is host:port of the collector, e.g. "127.0.0.1:5514".
	Addr string
	// Network is "udp" (default) or "tcp".
	Network string
	// Hostname overrides the HOSTNAME field; empty uses the OS hostname.
	Hostname string
	// Tag overrides the APP-NAME field; empty uses the digest's module.
	Tag string
	// Facility is the syslog facility number; 0 selects local0 (16), which is
	// the conventional range for application logs.
	Facility int
}

func (s *SyslogChannel) Name() string { return "syslog" }

func (s *SyslogChannel) Send(ctx context.Context, d Digest) error {
	if d.Empty() {
		return nil
	}
	network := s.Network
	if network == "" {
		network = "udp"
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, s.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}

	for _, line := range s.lines(d) {
		if _, err := io.WriteString(conn, line); err != nil {
			return err
		}
	}
	return nil
}

// lines renders the digest as syslog frames, newline-terminated so a TCP
// collector can frame them.
func (s *SyslogChannel) lines(d Digest) []string {
	host := s.Hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			host = h
		} else {
			host = "-"
		}
	}
	tag := s.Tag
	if tag == "" {
		tag = d.Module
	}
	facility := s.Facility
	if facility == 0 {
		facility = 16 // local0
	}
	stamp := d.At
	if stamp.IsZero() {
		stamp = time.Now()
	}
	ts := stamp.Format(time.Stamp)
	pid := os.Getpid()

	out := make([]string, 0, len(d.Opened)+len(d.Resolved))
	for _, f := range d.Opened {
		pri := facility*8 + syslogSeverity(string(f.Severity))
		out = append(out, fmt.Sprintf("<%d>%s %s %s[%d]: %s\n",
			pri, ts, host, tag, pid, syslogMessage(d.Module, f, false)))
	}
	for _, f := range d.Resolved {
		// A resolution is good news; notice keeps it out of the alerting path.
		pri := facility*8 + 5
		out = append(out, fmt.Sprintf("<%d>%s %s %s[%d]: %s\n",
			pri, ts, host, tag, pid, syslogMessage(d.Module, f, true)))
	}
	return out
}

// syslogMessage renders one finding as a human-readable sentence followed by
// the key=value pairs a collector keys on. src= is emitted only when the
// evidence actually holds an IP address, so a receiver never has to guess
// whether it is looking at an address or a hostname.
func syslogMessage(module string, f core.Finding, resolved bool) string {
	var b strings.Builder
	if resolved {
		b.WriteString("RESOLVED: ")
	}
	b.WriteString(f.Title)
	fmt.Fprintf(&b, " | product=%s severity=%s check=%s target=%s status=%s",
		module, f.Severity, f.Check, f.Target, statusWord(resolved))
	if ip := evidenceIP(f.Evidence); ip != "" {
		fmt.Fprintf(&b, " src=%s", ip)
	}
	return sanitizeSyslog(b.String())
}

func statusWord(resolved bool) string {
	if resolved {
		return "resolved"
	}
	return "open"
}

// evidenceIP finds a source address in a finding's evidence, if there is one.
func evidenceIP(ev map[string]any) string {
	for _, key := range []string{"source_ip", "src_ip", "src", "actor", "client_ip", "ip"} {
		v, ok := ev[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if net.ParseIP(strings.TrimSpace(s)) != nil {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// syslogSeverity maps a finding severity onto the syslog numeric severity, so
// existing collector routing rules ("page me on crit") work unchanged.
func syslogSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	default:
		return 6 // info
	}
}

// sanitizeSyslog keeps one finding on one line and bounds its length, so a
// hostile value in a title or evidence field cannot inject extra frames.
func sanitizeSyslog(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == 0 {
			return ' '
		}
		return r
	}, s)
	const max = 1600
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
