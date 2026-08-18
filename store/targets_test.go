package store

import (
	"database/sql"
	"testing"
)

func targetStores(t *testing.T) map[string]TargetStore {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sq, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]TargetStore{"mem": NewMemStore(), "sqlite": sq}
}

// Both implementations must behave identically: save, idempotent re-save,
// ordered listing of raw inputs, delete by canonical.
func TestTargetStore_Conformance(t *testing.T) {
	for name, ts := range targetStores(t) {
		t.Run(name, func(t *testing.T) {
			must := func(err error) {
				if err != nil {
					t.Fatal(err)
				}
			}
			must(ts.SaveTarget("certwatch", "example.com", "example.com:443"))
			must(ts.SaveTarget("certwatch", "other.com:8443", "other.com:8443"))
			// Idempotent on canonical: same target saved twice stays one row.
			must(ts.SaveTarget("certwatch", "example.com", "example.com:443"))
			// Another module's targets are invisible.
			must(ts.SaveTarget("attack-surface", "example.com", "example.com:443"))

			raws, err := ts.ListSavedTargets("certwatch")
			must(err)
			if len(raws) != 2 || raws[0] != "example.com" || raws[1] != "other.com:8443" {
				t.Fatalf("wrong listing: %v", raws)
			}

			must(ts.DeleteTarget("certwatch", "example.com:443"))
			raws, _ = ts.ListSavedTargets("certwatch")
			if len(raws) != 1 || raws[0] != "other.com:8443" {
				t.Fatalf("delete failed: %v", raws)
			}
			// The other module is untouched.
			other, _ := ts.ListSavedTargets("attack-surface")
			if len(other) != 1 {
				t.Fatalf("cross-module isolation broken: %v", other)
			}
		})
	}
}
