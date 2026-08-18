package sched

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/store"
)

// fakeCollector is a scriptable collector for exercising the scheduler.
type fakeCollector struct {
	info core.ModuleInfo

	mu       sync.Mutex
	calls    int32
	inFlight int32
	maxSeen  int32
	fail     func(call int) error // optional scripted failure
	produce  func(t core.Target) []core.Finding
	block    time.Duration // simulated scan duration
}

func (f *fakeCollector) Describe() core.ModuleInfo { return f.info }

func (f *fakeCollector) ValidateTarget(raw string) (core.Target, error) {
	if strings.Contains(raw, " ") {
		return core.Target{}, errors.New("targets must not contain spaces")
	}
	return core.Target{Raw: raw, Canonical: raw}, nil
}

func (f *fakeCollector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	call := int(atomic.AddInt32(&f.calls, 1))
	cur := atomic.AddInt32(&f.inFlight, 1)
	defer atomic.AddInt32(&f.inFlight, -1)
	for {
		max := atomic.LoadInt32(&f.maxSeen)
		if cur <= max || atomic.CompareAndSwapInt32(&f.maxSeen, max, cur) {
			break
		}
	}
	if f.block > 0 {
		select {
		case <-time.After(f.block):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail != nil {
		if err := f.fail(call); err != nil {
			return nil, err
		}
	}
	if f.produce != nil {
		return f.produce(t), nil
	}
	return nil, nil
}

func (f *fakeCollector) Diff(prev, cur []core.Finding) []core.Change { return nil }

func newSched(fc *fakeCollector, cfg Config) (*Scheduler, *store.MemStore) {
	ms := store.NewMemStore()
	eng := store.NewEngine(ms)
	s := New(eng, cfg)
	if err := s.Register(fc); err != nil {
		panic(err)
	}
	return s, ms
}

func demoFinding(target string) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint("fake", target, "demo.check", ""),
		Target:      target, Check: "demo.check", Title: "demo",
		Severity: core.SeverityLow, Remediation: "do the thing",
	}
}

// A registered target must be scanned promptly after Start (first sweep is
// immediate — the "five minutes to first value" behaviour), findings must land
// in the store, and OnResult must fire with the newly-open finding.
func TestScheduler_FirstSweepIsImmediate(t *testing.T) {
	fc := &fakeCollector{
		info:    core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour},
		produce: func(t core.Target) []core.Finding { return []core.Finding{demoFinding(t.Canonical)} },
	}
	s, ms := newSched(fc, Config{})

	results := make(chan Result, 4)
	s.OnResult = func(r Result) { results <- r }

	if _, err := s.AddTarget("fake", "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	select {
	case r := <-results:
		if len(r.Reconcile.NewlyOpen) != 1 {
			t.Fatalf("want 1 newly-open from first sweep, got %d", len(r.Reconcile.NewlyOpen))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first sweep did not run promptly")
	}
	open, _ := ms.ListOpen("fake")
	if len(open) != 1 {
		t.Fatalf("finding not stored: %d open", len(open))
	}
}

// Worker-pool bound: with Workers=2 and many slow targets, no more than two
// Collect calls may ever run concurrently.
func TestScheduler_ConcurrencyBounded(t *testing.T) {
	fc := &fakeCollector{
		info:  core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour},
		block: 80 * time.Millisecond,
	}
	s, _ := newSched(fc, Config{Workers: 2})
	for _, h := range []string{"a", "b", "c", "d", "e", "f"} {
		s.AddTarget("fake", h)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	s.Stop()

	if got := atomic.LoadInt32(&fc.maxSeen); got > 2 {
		t.Fatalf("worker bound violated: %d concurrent collects (limit 2)", got)
	}
	if atomic.LoadInt32(&fc.calls) < 6 {
		t.Fatalf("all 6 targets should still be scanned, got %d calls", fc.calls)
	}
}

// A failing target must trigger OnError with growing backoff, and must NOT be
// retried before its backoff gate passes.
func TestScheduler_ErrorReportsAndBacksOff(t *testing.T) {
	boom := errors.New("connection refused")
	fc := &fakeCollector{
		info: core.ModuleInfo{ID: "fake", DefaultInterval: 40 * time.Millisecond},
		fail: func(int) error { return boom },
	}
	s, _ := newSched(fc, Config{RetryBase: 10 * time.Second}) // gate far beyond test duration

	errs := make(chan ScanError, 16)
	s.OnError = func(e ScanError) { errs <- e }

	s.AddTarget("fake", "dead-host")
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond) // several intervals pass
	s.Stop()

	close(errs)
	var got []ScanError
	for e := range errs {
		got = append(got, e)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 error (then backoff gate holds), got %d", len(got))
	}
	if !errors.Is(got[0].Err, boom) || got[0].Attempt != 1 || got[0].NextTry != 10*time.Second {
		t.Fatalf("unexpected error report: %+v", got[0])
	}
}

// After a failure, a recovered target must scan again once backoff passes and
// reset its failure count.
func TestScheduler_RecoveryAfterBackoff(t *testing.T) {
	boom := errors.New("flaky")
	fc := &fakeCollector{
		info: core.ModuleInfo{ID: "fake", DefaultInterval: 30 * time.Millisecond},
		fail: func(call int) error {
			if call == 1 {
				return boom
			}
			return nil
		},
		produce: func(t core.Target) []core.Finding { return []core.Finding{demoFinding(t.Canonical)} },
	}
	s, ms := newSched(fc, Config{RetryBase: 50 * time.Millisecond})

	s.AddTarget("fake", "flaky-host")
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	s.Stop()

	open, _ := ms.ListOpen("fake")
	if len(open) != 1 {
		t.Fatalf("recovered target should have produced its finding, got %d open", len(open))
	}
}

// ScanNow must sweep immediately regardless of interval, and block until done.
func TestScheduler_ScanNow(t *testing.T) {
	fc := &fakeCollector{
		info:    core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour},
		produce: func(t core.Target) []core.Finding { return []core.Finding{demoFinding(t.Canonical)} },
	}
	s, ms := newSched(fc, Config{})
	s.AddTarget("fake", "host-1")
	s.AddTarget("fake", "host-2")

	// Note: scheduler not started — ScanNow must work standalone too.
	if err := s.ScanNow(context.Background(), "fake"); err != nil {
		t.Fatal(err)
	}
	open, _ := ms.ListOpen("fake")
	if len(open) != 2 {
		t.Fatalf("ScanNow should have scanned both targets, got %d open", len(open))
	}
}

// The scan timeout must cancel a hung collector rather than wedging a worker.
func TestScheduler_ScanTimeoutCancelsHungCollect(t *testing.T) {
	fc := &fakeCollector{
		info:  core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour},
		block: 10 * time.Second, // "hangs" far beyond the timeout
	}
	s, _ := newSched(fc, Config{ScanTimeout: 60 * time.Millisecond})

	errs := make(chan ScanError, 1)
	s.OnError = func(e ScanError) { errs <- e }

	s.AddTarget("fake", "hung-host")
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-errs:
		if !errors.Is(e.Err, context.DeadlineExceeded) {
			t.Fatalf("want DeadlineExceeded, got %v", e.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hung collect was not cancelled by scan timeout")
	}
	s.Stop()
}

// Registering the same module twice must fail; adding targets to unknown
// modules must fail; invalid targets must surface the collector's message.
func TestScheduler_RegistrationAndValidation(t *testing.T) {
	fc := &fakeCollector{info: core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour}}
	s, _ := newSched(fc, Config{})

	if err := s.Register(fc); err == nil {
		t.Fatal("duplicate registration must fail")
	}
	if _, err := s.AddTarget("nope", "x"); err == nil {
		t.Fatal("unknown module must fail")
	}
	if _, err := s.AddTarget("fake", "has space"); err == nil {
		t.Fatal("collector validation error must propagate")
	}
}

// Stop cancels in-flight scans (fast shutdown) but must not return until every
// scan goroutine has actually exited — no leaks, no half-running Collects.
func TestScheduler_StopCancelsAndWaitsForInflight(t *testing.T) {
	fc := &fakeCollector{
		info:  core.ModuleInfo{ID: "fake", DefaultInterval: time.Hour},
		block: 10 * time.Second, // would run "forever" unless cancelled
	}
	s, _ := newSched(fc, Config{ScanTimeout: 30 * time.Second})
	s.AddTarget("fake", "host-1")
	s.Start(context.Background())

	// Wait until the scan is actually in flight.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&fc.inFlight) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("scan never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()

	select {
	case <-stopped:
		// Stop returned: the hung Collect must have been cancelled and exited.
		if got := atomic.LoadInt32(&fc.inFlight); got != 0 {
			t.Fatalf("Stop returned with %d Collect(s) still in flight", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly after cancelling in-flight scan")
	}
}
