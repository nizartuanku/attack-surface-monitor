package store

import "sync"

// MemStore is an in-memory Store. It backs unit tests (no database, fully
// deterministic) and is a useful reference for what the SQLite store must do.
type MemStore struct {
	mu      sync.RWMutex
	recs    map[string]Record // key: module + "\x00" + fingerprint
	targets map[string][]memTarget
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{recs: make(map[string]Record)}
}

func key(module, fingerprint string) string { return module + "\x00" + fingerprint }

func (m *MemStore) ListByTarget(module, target string) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Record
	for _, r := range m.recs {
		if r.Module == module && r.Target == target {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemStore) Upsert(r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[key(r.Module, r.Fingerprint)] = r
	return nil
}

func (m *MemStore) Get(module, fingerprint string) (Record, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.recs[key(module, fingerprint)]
	return r, ok, nil
}

func (m *MemStore) ListOpen(module string) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Record
	for _, r := range m.recs {
		if r.Module == module && r.Status == "open" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemStore) ListAll(module string) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Record
	for _, r := range m.recs {
		if r.Module == module {
			out = append(out, r)
		}
	}
	return out, nil
}

// --- TargetStore (in-memory) ------------------------------------------------

type memTarget struct{ raw, canonical string }

func (m *MemStore) SaveTarget(module, raw, canonical string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.targets == nil {
		m.targets = make(map[string][]memTarget)
	}
	for _, t := range m.targets[module] {
		if t.canonical == canonical {
			return nil // idempotent
		}
	}
	m.targets[module] = append(m.targets[module], memTarget{raw, canonical})
	return nil
}

func (m *MemStore) DeleteTarget(module, canonical string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.targets[module]
	out := list[:0]
	for _, t := range list {
		if t.canonical != canonical {
			out = append(out, t)
		}
	}
	m.targets[module] = out
	return nil
}

func (m *MemStore) ListSavedTargets(module string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var raws []string
	for _, t := range m.targets[module] {
		raws = append(raws, t.raw)
	}
	return raws, nil
}
