package verify

import "sync"

// MemStore is an in-memory challenge store for tests and ephemeral runs. The
// SQLite-backed store lives alongside the product binary's other persistence.
type MemStore struct {
	mu sync.RWMutex
	m  map[string]Challenge // key: module + "\x00" + domain
}

// NewMemStore returns an empty in-memory challenge store.
func NewMemStore() *MemStore { return &MemStore{m: make(map[string]Challenge)} }

func key(module, domain string) string { return module + "\x00" + domain }

func (s *MemStore) Put(module string, c Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key(module, c.Domain)] = c
	return nil
}

func (s *MemStore) Get(module, domain string) (Challenge, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[key(module, domain)]
	return c, ok, nil
}

func (s *MemStore) List(module string) ([]Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Challenge
	for k, c := range s.m {
		if len(k) > len(module) && k[:len(module)] == module && k[len(module)] == 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *MemStore) Delete(module, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key(module, domain))
	return nil
}
