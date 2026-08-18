package store

import (
	"database/sql"

	"github.com/nizartuanku/attack-surface-monitor/verify"
)

// SQLiteVerifyStore persists domain-ownership challenges (verify.Store) so
// verification survives restarts. It is a separate type from SQLiteStore
// because the findings store already has a Get(module, fingerprint) with a
// different signature; both can share the same *sql.DB.
type SQLiteVerifyStore struct {
	db *sql.DB
}

// NewSQLiteVerifyStore migrates the challenges table and returns the store.
func NewSQLiteVerifyStore(db *sql.DB) (*SQLiteVerifyStore, error) {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS verify_challenges (
    module      TEXT NOT NULL,
    domain      TEXT NOT NULL,
    token       TEXT NOT NULL,
    state       TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    UNIQUE(module, domain)
);`); err != nil {
		return nil, err
	}
	return &SQLiteVerifyStore{db: db}, nil
}

func (v *SQLiteVerifyStore) Put(module string, c verify.Challenge) error {
	var verifiedAt any
	if c.VerifiedAt != nil {
		verifiedAt = c.VerifiedAt.UTC()
	}
	_, err := v.db.Exec(`
INSERT INTO verify_challenges (module, domain, token, state, created_at, verified_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(module, domain) DO UPDATE SET
    token = excluded.token, state = excluded.state,
    created_at = excluded.created_at, verified_at = excluded.verified_at`,
		module, c.Domain, c.Token, string(c.State), c.CreatedAt.UTC(), verifiedAt)
	return err
}

func (v *SQLiteVerifyStore) Get(module, domain string) (verify.Challenge, bool, error) {
	row := v.db.QueryRow(
		`SELECT domain, token, state, created_at, verified_at FROM verify_challenges WHERE module = ? AND domain = ?`,
		module, domain)
	c, err := scanChallenge(row)
	if err == sql.ErrNoRows {
		return verify.Challenge{}, false, nil
	}
	if err != nil {
		return verify.Challenge{}, false, err
	}
	return c, true, nil
}

func (v *SQLiteVerifyStore) List(module string) ([]verify.Challenge, error) {
	rows, err := v.db.Query(
		`SELECT domain, token, state, created_at, verified_at FROM verify_challenges WHERE module = ? ORDER BY domain`,
		module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []verify.Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (v *SQLiteVerifyStore) Delete(module, domain string) error {
	_, err := v.db.Exec(`DELETE FROM verify_challenges WHERE module = ? AND domain = ?`, module, domain)
	return err
}

func scanChallenge(row rowScanner) (verify.Challenge, error) {
	var (
		c          verify.Challenge
		state      string
		verifiedAt sql.NullTime
	)
	if err := row.Scan(&c.Domain, &c.Token, &state, &c.CreatedAt, &verifiedAt); err != nil {
		return verify.Challenge{}, err
	}
	c.State = verify.State(state)
	if verifiedAt.Valid {
		t := verifiedAt.Time
		c.VerifiedAt = &t
	}
	return c, nil
}
