package store

// TargetStore persists the user's configured targets, so a restart restores
// them exactly. Kept as a separate small interface (not part of Store) because
// only the web layer and the boot sequence touch it — the reconcile engine
// never does.
type TargetStore interface {
	// SaveTarget records one target for a module. Idempotent on canonical.
	SaveTarget(module, raw, canonical string) error
	// DeleteTarget removes one target by canonical form.
	DeleteTarget(module, canonical string) error
	// ListSavedTargets returns raw inputs in insertion order. Raw (not
	// canonical) is returned because restoring replays the collector's
	// ValidateTarget on the original input — one validation path, always.
	ListSavedTargets(module string) ([]string, error)
}
