// Package hfsbridge converts this product's findings into Hexward Finding
// Schema events (github.com/nizartuanku/hexward-core/hfs). It is the only
// place that knows both shapes, so the notify channels and the snapshot
// export can never disagree about a field.
package hfsbridge

import (
	"github.com/nizartuanku/attack-surface-monitor/core"
	"github.com/nizartuanku/hexward-core/hfs"
)

// Source maps a core finding onto the schema's input, field by field.
func Source(f core.Finding) hfs.Source {
	return hfs.Source{
		ID:          f.ID,
		Fingerprint: f.Fingerprint,
		Check:       f.Check,
		Title:       f.Title,
		Target:      f.Target,
		Severity:    string(f.Severity),
		Status:      string(f.Status),
		Remediation: f.Remediation,
		FirstSeen:   f.FirstSeen,
		LastSeen:    f.LastSeen,
		ResolvedAt:  f.ResolvedAt,
		GroupID:     f.GroupID,
		Evidence:    f.Evidence,
	}
}
