package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// captureChannel records digests it receives.
type captureChannel struct {
	mu      sync.Mutex
	digests []Digest
	fail    int32 // number of times to fail before succeeding
}

func (c *captureChannel) Name() string { return "capture" }

func (c *captureChannel) Send(ctx context.Context, d Digest) error {
	if atomic.LoadInt32(&c.fail) > 0 {
		atomic.AddInt32(&c.fail, -1)
		return errors.New("simulated failure")
	}
	c.mu.Lock()
	c.digests = append(c.digests, d)
	c.mu.Unlock()
	return nil
}

func (c *captureChannel) got() []Digest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Digest, len(c.digests))
	copy(out, c.digests)
	return out
}

func finding(fp, target string, sev core.Severity) core.Finding {
	return core.Finding{
		Fingerprint: fp, Target: target, Check: "demo", Title: "t: " + fp,
		Severity: sev, Remediation: "fix it",
	}
}

// A burst of events within one window must produce exactly ONE digest — the
// "200 events do not become 200 messages" rule, proven.
func TestDispatcher_BurstBecomesOneDigest(t *testing.T) {
	ch := &captureChannel{}
	d := NewDispatcher(Config{FlushInterval: 40 * time.Millisecond}, ch)

	for i := 0; i < 50; i++ {
		d.Enqueue(Event{Kind: KindOpened, Module: "certwatch",
			Finding: finding(itoa(i), "host-"+itoa(i), core.SeverityMedium)})
	}
	time.Sleep(120 * time.Millisecond)
	d.Close()

	got := ch.got()
	if len(got) != 1 {
		t.Fatalf("50 events in one window must yield 1 digest, got %d", len(got))
	}
	if len(got[0].Opened) != 50 {
		t.Fatalf("digest should carry all 50 findings, got %d", len(got[0].Opened))
	}
}

// The same fingerprint enqueued twice within a window must appear once.
func TestDispatcher_DedupWithinWindow(t *testing.T) {
	ch := &captureChannel{}
	d := NewDispatcher(Config{FlushInterval: 30 * time.Millisecond}, ch)
	f := finding("same-fp", "host", core.SeverityHigh)
	d.Enqueue(Event{Kind: KindOpened, Module: "certwatch", Finding: f})
	d.Enqueue(Event{Kind: KindOpened, Module: "certwatch", Finding: f})
	time.Sleep(90 * time.Millisecond)
	d.Close()

	got := ch.got()
	if len(got) != 1 || len(got[0].Opened) != 1 {
		t.Fatalf("duplicate fingerprint must collapse to one, got %+v", got)
	}
}

// MinSeverity filters opened events but must never filter resolved ones.
func TestDispatcher_SeverityFilterSparesResolved(t *testing.T) {
	ch := &captureChannel{}
	d := NewDispatcher(Config{FlushInterval: 30 * time.Millisecond, MinSeverity: core.SeverityHigh}, ch)

	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("low", "h1", core.SeverityLow)})
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("crit", "h2", core.SeverityCritical)})
	d.Enqueue(Event{Kind: KindResolved, Module: "m", Finding: finding("low2", "h3", core.SeverityLow)})
	time.Sleep(90 * time.Millisecond)
	d.Close()

	got := ch.got()
	if len(got) != 1 {
		t.Fatalf("want 1 digest, got %d", len(got))
	}
	if len(got[0].Opened) != 1 || got[0].Opened[0].Fingerprint != "crit" {
		t.Fatalf("low-severity opened must be filtered: %+v", got[0].Opened)
	}
	if len(got[0].Resolved) != 1 {
		t.Fatalf("resolved must always pass the filter: %+v", got[0].Resolved)
	}
}

// Digest ordering: most severe first, so the reader's first line is the worst.
func TestDispatcher_DigestOrderedBySeverity(t *testing.T) {
	ch := &captureChannel{}
	d := NewDispatcher(Config{FlushInterval: 30 * time.Millisecond}, ch)
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("a", "h", core.SeverityLow)})
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("b", "h", core.SeverityCritical)})
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("c", "h", core.SeverityMedium)})
	time.Sleep(90 * time.Millisecond)
	d.Close()

	got := ch.got()
	if len(got) != 1 {
		t.Fatalf("want 1 digest, got %d", len(got))
	}
	order := []core.Severity{got[0].Opened[0].Severity, got[0].Opened[1].Severity, got[0].Opened[2].Severity}
	if order[0] != core.SeverityCritical || order[1] != core.SeverityMedium || order[2] != core.SeverityLow {
		t.Fatalf("wrong order: %v", order)
	}
}

// MaxBatch must flush early instead of waiting out the window.
func TestDispatcher_MaxBatchFlushesEarly(t *testing.T) {
	ch := &captureChannel{}
	d := NewDispatcher(Config{FlushInterval: 10 * time.Second, MaxBatch: 5}, ch)
	for i := 0; i < 5; i++ {
		d.Enqueue(Event{Kind: KindOpened, Module: "m",
			Finding: finding(itoa(i), "h", core.SeverityMedium)})
	}
	// No sleep long enough for the 10s window — the early flush must fire.
	deadline := time.Now().Add(2 * time.Second)
	for len(ch.got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	d.Close()
	if got := ch.got(); len(got) != 1 || len(got[0].Opened) != 5 {
		t.Fatalf("MaxBatch should have flushed 1 digest of 5, got %+v", got)
	}
}

// A failing channel must be retried and eventually succeed.
func TestDispatcher_RetriesFailedSend(t *testing.T) {
	ch := &captureChannel{fail: 2} // fail twice, succeed on third
	d := NewDispatcher(Config{
		FlushInterval: 20 * time.Millisecond,
		Retries:       3, RetryDelay: 10 * time.Millisecond,
	}, ch)
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("x", "h", core.SeverityHigh)})
	time.Sleep(60 * time.Millisecond)
	d.Close()
	if got := ch.got(); len(got) != 1 {
		t.Fatalf("send should succeed on retry, got %d digests", len(got))
	}
}

// Exhausted retries must surface through OnSendError, never panic or hang.
func TestDispatcher_ReportsExhaustedRetries(t *testing.T) {
	ch := &captureChannel{fail: 99}
	d := NewDispatcher(Config{
		FlushInterval: 20 * time.Millisecond,
		Retries:       2, RetryDelay: 5 * time.Millisecond,
	}, ch)
	errs := make(chan string, 1)
	d.OnSendError = func(channel string, err error) { errs <- channel }
	d.Enqueue(Event{Kind: KindOpened, Module: "m", Finding: finding("x", "h", core.SeverityHigh)})
	time.Sleep(50 * time.Millisecond)
	d.Close()
	select {
	case c := <-errs:
		if c != "capture" {
			t.Fatalf("wrong channel reported: %s", c)
		}
	default:
		t.Fatal("exhausted retries were not reported")
	}
}

// The webhook channel must POST the documented JSON shape with the token header.
func TestWebhookChannel_PayloadShape(t *testing.T) {
	var gotBody []byte
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotToken = r.Header.Get("X-Sentinel-Token")
	}))
	defer srv.Close()

	wh := &WebhookChannel{URL: srv.URL, Secret: "s3cret"}
	err := wh.Send(context.Background(), Digest{
		Module: "certwatch", At: time.Now(),
		Opened: []core.Finding{finding("fp", "example.com:443", core.SeverityHigh)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "s3cret" {
		t.Fatalf("missing auth header, got %q", gotToken)
	}
	var p map[string]any
	if err := json.Unmarshal(gotBody, &p); err != nil {
		t.Fatal(err)
	}
	if p["version"] != float64(1) || p["module"] != "certwatch" {
		t.Fatalf("payload envelope wrong: %v", p)
	}
	opened := p["opened"].([]any)
	first := opened[0].(map[string]any)
	if first["remediation"] != "fix it" || first["severity"] != "high" {
		t.Fatalf("finding fields wrong: %v", first)
	}
}

// A non-2xx response must be an error (so the dispatcher retries it).
func TestWebhookChannel_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	wh := &WebhookChannel{URL: srv.URL}
	if err := wh.Send(context.Background(), Digest{Module: "m", Opened: []core.Finding{finding("f", "h", core.SeverityLow)}}); err == nil {
		t.Fatal("502 must be reported as an error")
	}
}

// The shared text format: severity-ordered, remediation included, resolved last.
func TestFormatText(t *testing.T) {
	d := Digest{
		Module: "certwatch",
		Opened: []core.Finding{
			finding("a", "example.com:443", core.SeverityCritical),
		},
		Resolved: []core.Finding{
			finding("b", "old.example.com:443", core.SeverityMedium),
		},
	}
	text := FormatText(d)
	for _, want := range []string{"CertWatch", "CRITICAL", "example.com:443", "→ fix it", "resolved", "old.example.com:443"} {
		if !strings.Contains(text, want) {
			t.Fatalf("formatted text missing %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "CRITICAL") > strings.Index(text, "resolved") {
		t.Fatal("opened findings must come before resolved news")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
