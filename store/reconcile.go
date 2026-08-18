package store

import (
	"encoding/json"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// Reconcile is the heart of Sentinel Core. Given the fresh findings a collector
// produced for one (module, target) in one scan, it:
//
//  1. validates each fresh finding and rejects malformed ones (loud, not silent),
//  2. upserts each valid finding by (module, fingerprint):
//     - new fingerprint      → insert as open (notify),
//     - previously resolved  → reopen (notify),
//     - open/acknowledged    → refresh mutable fields, keep status,
//     - suppressed           → refresh, stay silent,
//  3. for existing findings NOT seen this scan, increments an absent streak and
//     auto-resolves once it reaches the module's ResolveAfter threshold.
//
// It returns what changed so the scheduler can drive notifications without
// re-querying. Collectors never touch status, ids, or timestamps — this does.
func (e *Engine) Reconcile(mod core.ModuleInfo, target string, fresh []core.Finding) (ReconcileResult, error) {
	now := e.now()
	var res ReconcileResult

	existing, err := e.store.ListByTarget(mod.ID, target)
	if err != nil {
		return res, err
	}
	byFP := make(map[string]Record, len(existing))
	for _, r := range existing {
		byFP[r.Fingerprint] = r
	}

	seen := make(map[string]bool, len(fresh))

	for _, f := range fresh {
		if err := f.ValidateForIngest(); err != nil {
			res.Rejected = append(res.Rejected, RejectedFinding{Finding: f, Err: err})
			continue
		}
		capEvidence(&f)
		seen[f.Fingerprint] = true

		prev, ok := byFP[f.Fingerprint]
		if !ok {
			// Brand-new finding.
			id, err := e.newID(now)
			if err != nil {
				return res, err
			}
			rec := Record{Finding: f}
			rec.ID = id
			rec.Module = mod.ID
			rec.Status = core.StatusOpen
			rec.FirstSeen = now
			rec.LastSeen = now
			rec.AbsentStreak = 0
			if err := e.store.Upsert(rec); err != nil {
				return res, err
			}
			res.NewlyOpen = append(res.NewlyOpen, rec.Finding)
			continue
		}

		// Existing finding: refresh mutable descriptive fields, reset absence.
		reopened := prev.Status == core.StatusResolved
		merged := prev
		merged.Title = f.Title
		merged.Severity = f.Severity
		merged.Remediation = f.Remediation
		merged.Evidence = f.Evidence
		merged.LastSeen = now
		merged.AbsentStreak = 0
		if reopened {
			merged.Status = core.StatusOpen
			merged.ResolvedAt = nil
		}
		if err := e.store.Upsert(merged); err != nil {
			return res, err
		}
		if reopened {
			res.NewlyOpen = append(res.NewlyOpen, merged.Finding)
		}
	}

	// Auto-resolve findings the collector no longer reports.
	for _, r := range existing {
		if seen[r.Fingerprint] {
			continue
		}
		switch r.Status {
		case core.StatusResolved, core.StatusSuppressed:
			// Resolved stays resolved; suppressed is the user's call — leave both.
			continue
		}
		r.AbsentStreak++
		if r.AbsentStreak >= mod.ResolveAfterOrDefault() {
			r.Status = core.StatusResolved
			resolvedAt := now
			r.ResolvedAt = &resolvedAt
			res.Resolved = append(res.Resolved, r.Finding)
		}
		if err := e.store.Upsert(r); err != nil {
			return res, err
		}
	}

	return res, nil
}

// capEvidence enforces MaxEvidenceBytes by dropping the evidence and leaving a
// marker when the serialised blob is too large. Truncating structured data
// arbitrarily would corrupt it; a marker keeps the finding honest.
func capEvidence(f *core.Finding) {
	if f.Evidence == nil {
		return
	}
	b, err := json.Marshal(f.Evidence)
	if err != nil {
		f.Evidence = map[string]any{"_error": "evidence not serialisable; dropped"}
		return
	}
	if len(b) > core.MaxEvidenceBytes {
		f.Evidence = map[string]any{
			"_truncated":      true,
			"_original_bytes": len(b),
			"_note":           "evidence exceeded MaxEvidenceBytes and was dropped",
		}
	}
}
