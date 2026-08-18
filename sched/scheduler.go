// Package sched drives the scan loop: for every registered module and every
// registered target, it periodically runs Collect() under a timeout, feeds the
// results through the reconcile engine, and hands what changed to a callback
// (the notifier, the UI, a log). Collectors stay pure; this package owns all
// timing, concurrency, retries, and politeness. Written once, used by all six
// products.
package sched

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/attack-surface-monitor/store"
)

// Config tunes the scheduler. Zero values fall back to sane defaults, so the
// framework keeps its "smart defaults, no required knobs" promise.
type Config struct {
	// Workers bounds how many Collect() calls may run at once across ALL
	// modules. Protects both the host machine and the scanned targets.
	Workers int
	// ScanTimeout bounds one Collect() call.
	ScanTimeout time.Duration
	// JitterFraction (0..1) randomises each interval by ±fraction/2 so scans
	// spread out instead of firing in lockstep. 0.1 = ±5%.
	JitterFraction float64
	// RetryBase is the first retry delay after a failed scan; doubles per
	// consecutive failure up to RetryMax. A successful scan resets it.
	RetryBase time.Duration
	RetryMax  time.Duration
	// IntervalOverride, when >0, replaces every module's DefaultInterval
	// (the paid "custom scan interval" feature — enforcement is the caller's
	// job via license limits; the scheduler just obeys).
	IntervalOverride time.Duration
}

func (c Config) withDefaults() Config {
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.ScanTimeout <= 0 {
		c.ScanTimeout = 30 * time.Second
	}
	if c.JitterFraction <= 0 || c.JitterFraction > 1 {
		c.JitterFraction = 0.1
	}
	if c.RetryBase <= 0 {
		c.RetryBase = 30 * time.Second
	}
	if c.RetryMax <= 0 {
		c.RetryMax = 15 * time.Minute
	}
	return c
}

// Result is delivered to the OnResult callback after every successful scan.
type Result struct {
	Module    string
	Target    core.Target
	Reconcile store.ReconcileResult
	Duration  time.Duration
}

// ScanError is delivered to the OnError callback after every failed scan.
type ScanError struct {
	Module  string
	Target  core.Target
	Err     error
	Attempt int           // consecutive failures for this target, 1-based
	NextTry time.Duration // backoff chosen for the retry
}

// Scheduler runs registered collectors against their targets.
type Scheduler struct {
	cfg    Config
	engine *store.Engine

	// OnResult and OnError are optional observation points. They are called
	// from worker goroutines; implementations must be quick or hand off.
	OnResult func(Result)
	OnError  func(ScanError)

	mu      sync.Mutex
	modules map[string]registration
	ctx     context.Context // set by Start; used for add-time immediate scans
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	sem     chan struct{}
	started bool

	// rng is guarded by mu; used only for jitter, so weak randomness is fine.
	rng *rand.Rand
}

type registration struct {
	collector core.Collector
	info      core.ModuleInfo
	targets   map[string]core.Target // key: canonical
}

// New builds a Scheduler over a reconcile engine.
func New(engine *store.Engine, cfg Config) *Scheduler {
	cfg = cfg.withDefaults()
	return &Scheduler{
		cfg:     cfg,
		engine:  engine,
		modules: make(map[string]registration),
		sem:     make(chan struct{}, cfg.Workers),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Register adds a collector. Must be called before Start; registering the same
// module ID twice is an error (it would double-scan every target).
func (s *Scheduler) Register(c core.Collector) error {
	info := c.Describe()
	if info.ID == "" {
		return errors.New("collector ModuleInfo.ID must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.modules[info.ID]; dup {
		return errors.New("module already registered: " + info.ID)
	}
	s.modules[info.ID] = registration{
		collector: c,
		info:      info,
		targets:   make(map[string]core.Target),
	}
	return nil
}

// AddTarget validates raw input via the module's collector and schedules it.
// Safe to call before or after Start; a target added while running begins
// scanning on the next loop pass.
func (s *Scheduler) AddTarget(moduleID, raw string) (core.Target, error) {
	s.mu.Lock()
	reg, ok := s.modules[moduleID]
	s.mu.Unlock()
	if !ok {
		return core.Target{}, errors.New("unknown module: " + moduleID)
	}
	t, err := reg.collector.ValidateTarget(raw)
	if err != nil {
		return core.Target{}, err
	}
	s.mu.Lock()
	reg.targets[t.Canonical] = t
	ctx, started := s.ctx, s.started
	s.mu.Unlock()

	// First value now, not one interval from now: a freshly added target gets
	// an immediate scan on any tier ("five minutes to first value").
	if started && ctx != nil && ctx.Err() == nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.scanOne(ctx, reg, t)
		}()
	}
	return t, nil
}

// RemoveTarget stops scanning a target. Its stored findings remain (history);
// callers may prune separately.
func (s *Scheduler) RemoveTarget(moduleID, canonical string) {
	s.mu.Lock()
	if reg, ok := s.modules[moduleID]; ok {
		delete(reg.targets, canonical)
	}
	s.mu.Unlock()
}

// Start launches one loop goroutine per registered module. Idempotent-hostile
// by design: calling Start twice is an error, not a silent second fleet.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("scheduler already started")
	}
	s.started = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.ctx = ctx
	for id := range s.modules {
		s.wg.Add(1)
		go s.moduleLoop(ctx, id)
	}
	return nil
}

// Stop cancels all loops and waits for in-flight scans to finish.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// ScanNow runs one immediate scan of every target in a module (the paid-tier
// "scan now" button). It blocks until that sweep completes.
func (s *Scheduler) ScanNow(ctx context.Context, moduleID string) error {
	s.mu.Lock()
	reg, ok := s.modules[moduleID]
	if !ok {
		s.mu.Unlock()
		return errors.New("unknown module: " + moduleID)
	}
	targets := snapshotTargets(reg)
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t core.Target) {
			defer wg.Done()
			s.scanOne(ctx, reg, t)
		}(t)
	}
	wg.Wait()
	return ctx.Err()
}

// --- internals --------------------------------------------------------------

// moduleLoop wakes once per module interval and sweeps all its targets. Each
// target's scan runs on the shared worker pool; per-target failure backoff is
// tracked so one dead host slows only itself, never the sweep.
func (s *Scheduler) moduleLoop(ctx context.Context, moduleID string) {
	defer s.wg.Done()

	s.mu.Lock()
	reg := s.modules[moduleID]
	s.mu.Unlock()

	interval := reg.info.DefaultInterval
	if s.cfg.IntervalOverride > 0 {
		interval = s.cfg.IntervalOverride
	}
	if interval <= 0 {
		interval = time.Hour
	}

	failures := make(map[string]int)     // canonical → consecutive failures
	nextOK := make(map[string]time.Time) // canonical → earliest next attempt (backoff gate)
	var failMu sync.Mutex

	sweep := func() {
		s.mu.Lock()
		reg := s.modules[moduleID] // re-read: targets may have changed
		targets := snapshotTargets(reg)
		s.mu.Unlock()

		for _, t := range targets {
			failMu.Lock()
			gate := nextOK[t.Canonical]
			failMu.Unlock()
			if time.Now().Before(gate) {
				continue // still backing off this target
			}
			s.wg.Add(1)
			go func(t core.Target) {
				defer s.wg.Done()
				err := s.scanOne(ctx, reg, t)
				failMu.Lock()
				defer failMu.Unlock()
				if err != nil && !errors.Is(err, context.Canceled) {
					failures[t.Canonical]++
					backoff := s.backoffFor(failures[t.Canonical])
					nextOK[t.Canonical] = time.Now().Add(backoff)
					if s.OnError != nil {
						s.OnError(ScanError{
							Module: moduleID, Target: t, Err: err,
							Attempt: failures[t.Canonical], NextTry: backoff,
						})
					}
					return
				}
				failures[t.Canonical] = 0
				nextOK[t.Canonical] = time.Time{}
			}(t)
		}
	}

	// First sweep immediately: "five minutes to first value" starts now,
	// not one interval from now.
	sweep()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.jittered(interval)):
			sweep()
		}
	}
}

// scanOne acquires a worker slot, runs one Collect under timeout, reconciles,
// and reports. Returns the scan error (nil on success) for backoff tracking.
func (s *Scheduler) scanOne(ctx context.Context, reg registration, t core.Target) error {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.cfg.ScanTimeout)
	defer cancel()

	start := time.Now()
	findings, err := reg.collector.Collect(scanCtx, t)
	if err != nil {
		return err
	}

	res, err := s.engine.Reconcile(reg.info, t.Canonical, findings)
	if err != nil {
		return err
	}
	if s.OnResult != nil {
		s.OnResult(Result{
			Module: reg.info.ID, Target: t,
			Reconcile: res, Duration: time.Since(start),
		})
	}
	return nil
}

// backoffFor doubles from RetryBase per consecutive failure, capped at RetryMax.
func (s *Scheduler) backoffFor(consecutive int) time.Duration {
	d := s.cfg.RetryBase
	for i := 1; i < consecutive; i++ {
		d *= 2
		if d >= s.cfg.RetryMax {
			return s.cfg.RetryMax
		}
	}
	if d > s.cfg.RetryMax {
		d = s.cfg.RetryMax
	}
	return d
}

// jittered spreads an interval by ±JitterFraction/2 so fleets of targets and
// instances don't thunder in lockstep.
func (s *Scheduler) jittered(d time.Duration) time.Duration {
	s.mu.Lock()
	f := 1 + s.cfg.JitterFraction*(s.rng.Float64()-0.5)
	s.mu.Unlock()
	return time.Duration(float64(d) * f)
}

func snapshotTargets(reg registration) []core.Target {
	out := make([]core.Target, 0, len(reg.targets))
	for _, t := range reg.targets {
		out = append(out, t)
	}
	return out
}

// ListTargets returns the currently registered targets of a module, for the
// dashboard's target management view.
func (s *Scheduler) ListTargets(moduleID string) []core.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := s.modules[moduleID]
	if !ok {
		return nil
	}
	return snapshotTargets(reg)
}
