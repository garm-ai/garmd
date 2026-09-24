package catalogue

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Source is where a catalogue comes from.
//
// An interface with one method because the interesting variation is not how
// bytes arrive but whether the thing they arrive from is trusted to change
// under a running process. A file is; a URL someone can repoint is a
// different conversation.
type Source interface {
	Read(ctx context.Context) ([]byte, error)
	String() string
}

// Store holds the catalogue a process is serving, and a bounded history of
// the ones it was serving before.
//
// The current catalogue is behind an atomic pointer so that reading it costs
// nothing and never blocks a request. Reload is the only writer.
type Store struct {
	current atomic.Pointer[Catalogue]

	mu      sync.Mutex
	retired []*Catalogue // superseded, newest first

	keepDepth int
	ttl       time.Duration
	now       func() time.Time
}

// Options configure retention.
//
// Retention is NOT what makes a swap safe. A request takes a *Catalogue at
// entry and holds it; the garbage collector keeps that generation alive until
// the last such request finishes, whatever this store does. Nothing in flight
// can be pulled out from under.
//
// What retention buys is deliberate: rolling back without re-reading a source,
// answering "what did digest X declare" while an incident is open, and pinning
// a long-lived session to the generation it started on.
//
// It is bounded because it is not free. A ten-thousand-tool catalogue retains
// roughly 93 MB of descriptors, so KeepDepth is a memory decision — and the
// default of one is the smallest number that still allows a rollback.
type Options struct {
	// KeepDepth is how many superseded generations to hold. Zero means the
	// default of 1; a negative value means none.
	KeepDepth int

	// TTL drops a superseded generation once it has been superseded for this
	// long, even if KeepDepth would have kept it. Zero means the default of
	// five minutes. Bounded by time as well as by count because a process
	// that reloads once and runs for a month should not hold the old one for
	// a month.
	TTL time.Duration

	// Now is injectable so retention can be tested without sleeping.
	Now func() time.Time
}

// NewStore builds an empty store. Nothing is served until a Reload succeeds.
func NewStore(o Options) *Store {
	s := &Store{keepDepth: o.KeepDepth, ttl: o.TTL, now: o.Now}
	if o.KeepDepth == 0 {
		s.keepDepth = 1
	}
	if s.keepDepth < 0 {
		s.keepDepth = 0
	}
	if s.ttl == 0 {
		s.ttl = 5 * time.Minute
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Current is the catalogue to serve a request with. Nil before the first
// successful Reload.
//
// Take it ONCE at the start of a request and use that same value throughout.
// Calling Current twice in one request is the one way to see two generations
// in a single call, which is the failure this design exists to prevent.
func (s *Store) Current() *Catalogue { return s.current.Load() }

// Reload reads a source, validates it, and swaps it in. It is the trigger:
// call it at boot, from a file watcher, from an admin endpoint, from a test.
//
// **A bad catalogue never becomes current.** Everything that can fail —
// reading, parsing, the schema window, resolution, finding any tools at all —
// fails before the swap, and the process keeps serving what it was serving.
// That is the same fail-closed rule as boot, minus the process dying.
//
// Reloading an identical digest is a no-op rather than a swap, so a watcher
// that fires on a touched file does not churn a generation for nothing.
func (s *Store) Reload(ctx context.Context, src Source) (*Catalogue, error) {
	body, err := src.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading catalogue from %s: %w", src, err)
	}
	next, err := Load(body, s.now)
	if err != nil {
		return nil, err
	}

	prev := s.current.Load()
	if prev != nil && prev.Digest == next.Digest {
		return prev, nil
	}

	s.current.Store(next)

	s.mu.Lock()
	defer s.mu.Unlock()
	if prev != nil && s.keepDepth > 0 {
		s.retired = append([]*Catalogue{prev}, s.retired...)
	}
	s.sweepLocked()
	return next, nil
}

// Generations lists what this store holds: the current catalogue first, then
// any superseded ones still retained. For an operator answering "what is this
// process serving, and what was it serving".
func (s *Store) Generations() []*Catalogue {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	out := make([]*Catalogue, 0, len(s.retired)+1)
	if c := s.current.Load(); c != nil {
		out = append(out, c)
	}
	return append(out, s.retired...)
}

// Sweep drops retained generations that have aged out. Reload does this
// already; a caller only needs it if reloads are rare and holding a
// superseded catalogue for the gap is not wanted.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

// sweepLocked applies both bounds: count, then age.
//
// Count first because it is the cheaper check and the one an operator sets
// deliberately; age second because it catches the process that reloaded once
// and then ran for a month.
func (s *Store) sweepLocked() {
	if len(s.retired) > s.keepDepth {
		s.retired = s.retired[:s.keepDepth]
	}
	cut := s.now().Add(-s.ttl)
	keep := s.retired[:0]
	for _, c := range s.retired {
		if c.LoadedAt.After(cut) {
			keep = append(keep, c)
		}
	}
	// Release the tail so a dropped generation is actually collectable.
	for i := len(keep); i < len(s.retired); i++ {
		s.retired[i] = nil
	}
	s.retired = keep
}
