package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nizartuanku/attack-surface-monitor/core"
)

// SQLiteStore is the production Store. It is written against database/sql
// only, so the concrete driver is a one-line choice at build time:
//
//   - dev/sandbox:  github.com/mattn/go-sqlite3   (cgo)
//   - release:      modernc.org/sqlite            (pure Go → static binary)
//
// The reconcile engine never sees the difference; it talks to the Store
// interface. Schema management is embedded: NewSQLiteStore runs migrations
// automatically, honouring the "user never touches a config or a schema"
// philosophy.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) the database at path and migrates the
// schema. Pass ":memory:" for an ephemeral database (tests).
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}
	return s, nil
}

// migrate applies the schema idempotently. Versioned migrations can layer on
// later; v1 only needs CREATE IF NOT EXISTS.
func (s *SQLiteStore) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    fingerprint   TEXT NOT NULL,
    module        TEXT NOT NULL,
    target        TEXT NOT NULL,
    check_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    status        TEXT NOT NULL,
    remediation   TEXT NOT NULL,
    evidence      TEXT,
    group_id      TEXT,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    resolved_at   TIMESTAMP,
    absent_streak INTEGER NOT NULL DEFAULT 0,
    UNIQUE(module, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(module, target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS targets (
    module    TEXT NOT NULL,
    raw       TEXT NOT NULL,
    canonical TEXT NOT NULL,
    UNIQUE(module, canonical)
);
`
	_, err := s.db.Exec(schema)
	return err
}

const findingCols = `id, fingerprint, module, target, check_id, title, severity,
	status, remediation, evidence, group_id, first_seen, last_seen, resolved_at, absent_streak`

func (s *SQLiteStore) ListByTarget(module, target string) ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT `+findingCols+` FROM findings WHERE module = ? AND target = ?`,
		module, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

func (s *SQLiteStore) ListOpen(module string) ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT `+findingCols+` FROM findings WHERE module = ? AND status = ?`,
		module, string(core.StatusOpen))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

func (s *SQLiteStore) Get(module, fingerprint string) (Record, bool, error) {
	row := s.db.QueryRow(
		`SELECT `+findingCols+` FROM findings WHERE module = ? AND fingerprint = ?`,
		module, fingerprint)
	rec, err := scanRecord(row)
	if err == sql.ErrNoRows {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

func (s *SQLiteStore) Upsert(r Record) error {
	evidence, err := marshalEvidence(r.Evidence)
	if err != nil {
		return err
	}
	var resolvedAt any
	if r.ResolvedAt != nil {
		resolvedAt = r.ResolvedAt.UTC()
	}
	var groupID any
	if r.GroupID != nil {
		groupID = *r.GroupID
	}
	_, err = s.db.Exec(`
INSERT INTO findings (`+findingCols+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(module, fingerprint) DO UPDATE SET
    title         = excluded.title,
    severity      = excluded.severity,
    status        = excluded.status,
    remediation   = excluded.remediation,
    evidence      = excluded.evidence,
    group_id      = excluded.group_id,
    last_seen     = excluded.last_seen,
    resolved_at   = excluded.resolved_at,
    absent_streak = excluded.absent_streak`,
		r.ID, r.Fingerprint, r.Module, r.Target, r.Check, r.Title, string(r.Severity),
		string(r.Status), r.Remediation, evidence, groupID,
		r.FirstSeen.UTC(), r.LastSeen.UTC(), resolvedAt, r.AbsentStreak)
	return err
}

// --- row scanning -----------------------------------------------------------

// rowScanner covers both *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanRecord(row rowScanner) (Record, error) {
	var (
		r          Record
		severity   string
		status     string
		evidence   sql.NullString
		groupID    sql.NullString
		resolvedAt sql.NullTime
	)
	err := row.Scan(&r.ID, &r.Fingerprint, &r.Module, &r.Target, &r.Check, &r.Title,
		&severity, &status, &r.Remediation, &evidence, &groupID,
		&r.FirstSeen, &r.LastSeen, &resolvedAt, &r.AbsentStreak)
	if err != nil {
		return Record{}, err
	}
	r.Severity = core.Severity(severity)
	r.Status = core.FindingStatus(status)
	if evidence.Valid && evidence.String != "" {
		if err := json.Unmarshal([]byte(evidence.String), &r.Evidence); err != nil {
			// A corrupt evidence blob must not hide the finding itself.
			r.Evidence = map[string]any{"_error": "stored evidence unreadable"}
		}
	}
	if groupID.Valid {
		g := groupID.String
		r.GroupID = &g
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		r.ResolvedAt = &t
	}
	return r, nil
}

func scanRecords(rows *sql.Rows) ([]Record, error) {
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func marshalEvidence(ev map[string]any) (any, error) {
	if ev == nil {
		return nil, nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	return string(b), nil
}

// Vacuum reclaims space after large deletes; exposed for retention jobs later.
func (s *SQLiteStore) Vacuum() error {
	_, err := s.db.Exec(`VACUUM`)
	return err
}

// PruneResolvedBefore deletes resolved findings older than cutoff — the hook
// the core's tier-based retention (7d free / 1y Pro / unlimited Team) drives.
func (s *SQLiteStore) PruneResolvedBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM findings WHERE status = ? AND resolved_at IS NOT NULL AND resolved_at < ?`,
		string(core.StatusResolved), cutoff.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLiteStore) ListAll(module string) ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT `+findingCols+` FROM findings WHERE module = ? ORDER BY last_seen DESC`,
		module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// --- TargetStore (SQLite) ---------------------------------------------------

func (s *SQLiteStore) SaveTarget(module, raw, canonical string) error {
	_, err := s.db.Exec(`
INSERT INTO targets (module, raw, canonical) VALUES (?, ?, ?)
ON CONFLICT(module, canonical) DO NOTHING`, module, raw, canonical)
	return err
}

func (s *SQLiteStore) DeleteTarget(module, canonical string) error {
	_, err := s.db.Exec(`DELETE FROM targets WHERE module = ? AND canonical = ?`,
		module, canonical)
	return err
}

func (s *SQLiteStore) ListSavedTargets(module string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT raw FROM targets WHERE module = ? ORDER BY rowid`, module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
