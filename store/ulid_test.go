package store

import (
	"testing"
	"time"
)

func TestNewULID_LengthAndSortability(t *testing.T) {
	t1 := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Millisecond)

	a, err := NewULID(t1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewULID(t2)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("ULIDs must be 26 chars, got %d and %d", len(a), len(b))
	}
	// A later timestamp must produce a lexicographically greater ULID, so the
	// store and UI order findings by creation time for free.
	if !(a < b) {
		t.Fatalf("later ULID must sort after earlier one: %s !< %s", a, b)
	}
}

func TestNewULID_Uniqueness(t *testing.T) {
	tm := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := NewULID(tm)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate ULID at same timestamp: %s", id)
		}
		seen[id] = true
	}
}
