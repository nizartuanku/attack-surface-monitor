// Package notify turns reconcile results into human notifications, correctly.
// The hard part is not sending an HTTP POST — it is NOT sending two hundred of
// them. The Dispatcher batches events over a short window, deduplicates, and
// emits one digest per flush to every configured channel. Channels are
// pluggable behind a two-method interface, so webhook/Slack/Telegram/email all
// share the batching, filtering, and retry logic. Built once, used by all six
// products.
package notify

import (
	"context"
	"sync"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// EventKind says why a finding is being announced.
type EventKind string

const (
	KindOpened   EventKind = "opened"   // new or reopened problem
	KindResolved EventKind = "resolved" // problem stopped appearing
)

// Event is one finding transition worth telling a human about.
type Event struct {
	Kind    EventKind
	Module  string
	Finding core.Finding
}

// Digest is what channels actually send: one batched, ordered summary.
type Digest struct {
	Module   string
	Opened   []core.Finding // sorted most-severe first
	Resolved []core.Finding
	At       time.Time
}

// Empty reports whether the digest carries nothing worth sending.
func (d Digest) Empty() bool { return len(d.Opened) == 0 && len(d.Resolved) == 0 }

// Channel delivers a digest somewhere. Implementations must be safe for
// concurrent use and should return quickly; the dispatcher already retries.
type Channel interface {
	Name() string
	Send(ctx context.Context, d Digest) error
}

// Config tunes the dispatcher. Zero values become sane defaults.
type Config struct {
	// FlushInterval is how long events accumulate before one digest is sent.
	// Short enough to feel immediate, long enough to merge a burst.
	FlushInterval time.Duration
	// MaxBatch flushes early when this many events are pending.
	MaxBatch int
	// MinSeverity drops opened-events below this severity (resolved events
	// always pass — closure is cheap and users want it). Empty = send all.
	MinSeverity core.Severity
	// Retries per channel per digest; RetryDelay between attempts.
	Retries    int
	RetryDelay time.Duration
}

func (c Config) withDefaults() Config {
	if c.FlushInterval <= 0 {
		c.FlushInterval = 30 * time.Second
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = 100
	}
	if c.Retries <= 0 {
		c.Retries = 3
	}
	if c.RetryDelay <= 0 {
		c.RetryDelay = 5 * time.Second
	}
	return c
}

// Dispatcher batches events and fans digests out to channels.
type Dispatcher struct {
	cfg      Config
	channels []Channel

	mu      sync.Mutex
	pending map[string][]Event // module → events
	seen    map[string]bool    // dedup within the current batch window
	timer   *time.Timer
	closed  bool

	wg sync.WaitGroup

	// OnSendError observes delivery failures after retries are exhausted.
	// Optional; must be quick.
	OnSendError func(channel string, err error)
}

// NewDispatcher builds a dispatcher over the given channels.
func NewDispatcher(cfg Config, channels ...Channel) *Dispatcher {
	return &Dispatcher{
		cfg:      cfg.withDefaults(),
		channels: channels,
		pending:  make(map[string][]Event),
		seen:     make(map[string]bool),
	}
}

// Enqueue adds one event. Safe from any goroutine (the scheduler's OnResult
// callback calls this). Events below MinSeverity are dropped at the door;
// duplicate fingerprints within one window collapse to the first occurrence.
func (d *Dispatcher) Enqueue(e Event) {
	if e.Kind == KindOpened && !d.passesSeverity(e.Finding.Severity) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	key := string(e.Kind) + "|" + e.Module + "|" + e.Finding.Fingerprint
	if d.seen[key] {
		return
	}
	d.seen[key] = true
	d.pending[e.Module] = append(d.pending[e.Module], e)

	total := 0
	for _, evs := range d.pending {
		total += len(evs)
	}
	if total >= d.cfg.MaxBatch {
		d.flushLocked()
		return
	}
	if d.timer == nil {
		d.timer = time.AfterFunc(d.cfg.FlushInterval, d.Flush)
	}
}

// Flush sends everything pending now. Called by the window timer; callers may
// also invoke it directly (e.g. on shutdown).
func (d *Dispatcher) Flush() {
	d.mu.Lock()
	d.flushLocked()
	d.mu.Unlock()
}

// Close flushes remaining events and waits for in-flight sends.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	d.flushLocked()
	d.closed = true
	d.mu.Unlock()
	d.wg.Wait()
}

func (d *Dispatcher) passesSeverity(s core.Severity) bool {
	if d.cfg.MinSeverity == "" {
		return true
	}
	return severityRank(s) >= severityRank(d.cfg.MinSeverity)
}

// flushLocked builds digests from pending events and dispatches them
// asynchronously. Caller holds d.mu.
func (d *Dispatcher) flushLocked() {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if len(d.pending) == 0 {
		return
	}
	now := time.Now()
	digests := make([]Digest, 0, len(d.pending))
	for module, events := range d.pending {
		dg := Digest{Module: module, At: now}
		for _, e := range events {
			switch e.Kind {
			case KindOpened:
				dg.Opened = append(dg.Opened, e.Finding)
			case KindResolved:
				dg.Resolved = append(dg.Resolved, e.Finding)
			}
		}
		sortBySeverity(dg.Opened)
		digests = append(digests, dg)
	}
	d.pending = make(map[string][]Event)
	d.seen = make(map[string]bool)

	for _, dg := range digests {
		if dg.Empty() {
			continue
		}
		for _, ch := range d.channels {
			d.wg.Add(1)
			go func(ch Channel, dg Digest) {
				defer d.wg.Done()
				d.sendWithRetry(ch, dg)
			}(ch, dg)
		}
	}
}

func (d *Dispatcher) sendWithRetry(ch Channel, dg Digest) {
	var err error
	for attempt := 0; attempt < d.cfg.Retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = ch.Send(ctx, dg)
		cancel()
		if err == nil {
			return
		}
		if attempt < d.cfg.Retries-1 {
			time.Sleep(d.cfg.RetryDelay)
		}
	}
	if d.OnSendError != nil {
		d.OnSendError(ch.Name(), err)
	}
}

// --- helpers ----------------------------------------------------------------

func severityRank(s core.Severity) int {
	switch s {
	case core.SeverityCritical:
		return 4
	case core.SeverityHigh:
		return 3
	case core.SeverityMedium:
		return 2
	case core.SeverityLow:
		return 1
	default:
		return 0
	}
}

func sortBySeverity(fs []core.Finding) {
	// Insertion sort: batches are small and this avoids an import.
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && severityRank(fs[j].Severity) > severityRank(fs[j-1].Severity); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}
