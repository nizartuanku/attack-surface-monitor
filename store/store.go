// Package store holds the persistence layer and the reconcile engine — the
// piece every Sentinel product depends on. The reconcile algorithm (upsert by
// fingerprint, auto-resolve absent findings, surface newly-open ones for
// notification) is defined here against the Store interface, so it can be
// tested with an in-memory store and run against SQLite in production.
package store

import (
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// Record is a Finding as persisted: the finding plus the core-managed
// bookkeeping the reconcile engine needs but the product never sees.
type Record struct {
	core.Finding
	// AbsentStreak counts consecutive scans in which this finding was NOT
	// returned by the collector. Reset to 0 whenever it reappears. When it
	// reaches the module's ResolveAfter threshold, the finding auto-resolves.
	AbsentStreak int
}

// Store is the minimal persistence surface the reconcile engine needs. A
// production implementation (SQLite) and a test implementation (in-memory)
// both satisfy it. Implementations must be safe for the engine's use within a
// single reconcile call; cross-goroutine safety is the engine's concern.
type Store interface {
	// ListByTarget returns all records for one module+target, in any order.
	ListByTarget(module, target string) ([]Record, error)

	// Upsert inserts or updates a record keyed by (Module, Fingerprint).
	Upsert(r Record) error

	// Get fetches one record by (module, fingerprint); ok is false if absent.
	Get(module, fingerprint string) (Record, bool, error)

	// ListOpen returns all records whose status is open, across every target
	// (used by the dashboard summary and, later, notification digests).
	ListOpen(module string) ([]Record, error)

	// ListAll returns every record for one module regardless of status — the
	// dashboard shows open, acknowledged, and recently-resolved together.
	ListAll(module string) ([]Record, error)
}

// Clock and IDGen are injected so reconcile is deterministic in tests.
type Clock func() time.Time
type IDGen func(t time.Time) (string, error)

// Engine runs reconcile against a Store. One Engine is shared by all modules.
type Engine struct {
	store Store
	now   Clock
	newID IDGen
}

// NewEngine wires an Engine with production defaults (wall clock, ULID ids).
func NewEngine(s Store) *Engine {
	return &Engine{store: s, now: time.Now, newID: NewULID}
}

// WithClock and WithIDGen override the defaults (used by tests).
func (e *Engine) WithClock(c Clock) *Engine { e.now = c; return e }
func (e *Engine) WithIDGen(g IDGen) *Engine { e.newID = g; return e }

// ReconcileResult reports what a single reconcile changed, so the caller
// (scheduler → notifier) can act without re-querying.
type ReconcileResult struct {
	NewlyOpen []core.Finding // inserted-open or reopened this scan; notify these
	Resolved  []core.Finding // auto-resolved this scan; send "resolved" signals
	Rejected  []RejectedFinding
}

// RejectedFinding records a collector output that failed validation.
type RejectedFinding struct {
	Finding core.Finding
	Err     error
}
