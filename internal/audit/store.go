// Package audit provides an in-memory event store with concurrency-safe operations.
package audit

import (
	"sort"
	"sync"
	"time"
)

// Store is the interface that wraps event persistence operations.
type Store interface {
	Save(event SecurityEvent)
	ListAll() []SecurityEvent
	CountByIP(ip string) int
	TopIPs(n int) []string
}

// InMemoryStore is a thread-safe in-memory implementation of Store.
// Use a real database (PostgreSQL, ClickHouse) in production.
type InMemoryStore struct {
	mu     sync.RWMutex
	events []SecurityEvent
	ipHits map[string]int
}

// NewInMemoryStore initialises an empty store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		events: make([]SecurityEvent, 0, 512),
		ipHits: make(map[string]int),
	}
}

// Save appends an event and updates the IP counter atomically.
func (s *InMemoryStore) Save(event SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	s.events = append(s.events, event)
	s.ipHits[event.SourceIP]++
}

// ListAll returns a snapshot of all stored events (safe copy).
func (s *InMemoryStore) ListAll() []SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := make([]SecurityEvent, len(s.events))
	copy(snapshot, s.events)
	return snapshot
}

// CountByIP returns the number of events from a given source IP.
func (s *InMemoryStore) CountByIP(ip string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ipHits[ip]
}

// TopIPs returns the top n source IPs by event count (descending).
func (s *InMemoryStore) TopIPs(n int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type kv struct {
		ip    string
		count int
	}
	pairs := make([]kv, 0, len(s.ipHits))
	for ip, cnt := range s.ipHits {
		pairs = append(pairs, kv{ip, cnt})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})

	result := make([]string, 0, n)
	for i := 0; i < n && i < len(pairs); i++ {
		result = append(result, pairs[i].ip)
	}
	return result
}
