package record

import (
	"context"
	"github.com/garm-ai/garm/contracts/ledger"
	"sync"
)

// MemoryRecorder is for tests (spec §7 "memory (tests)").
type Memory struct {
	mu     sync.Mutex
	events []ledger.Event
}

func (m *Memory) Record(_ context.Context, ev ledger.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *Memory) Events() []ledger.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ledger.Event(nil), m.events...)
}
