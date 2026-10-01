package authn

import (
	"context"
	"sync/atomic"

	"github.com/garm-ai/contracts/policy"
)

// Compartments supplies the taxonomy a token's compartment names resolve
// against, for the generation currently being served.
//
// An interface rather than the registry itself because the taxonomy is a
// property of the CATALOGUE — an enterprise declares its own and ships it in
// the artifact — and the catalogue reloads under a running process. A verifier
// holding a value could only ever decide with the one it was built from.
//
// The invariant that makes all of this delicate: a compartment SET is a
// bitset, and policy.Registry assigns bits by sorted index over the whole
// generation's declarations. A single added declaration renumbers every name
// after it. So a Principal's compartments are meaningful ONLY against the
// registry that folded them — read under a different generation they are not
// a narrower answer or a wider one, they are a different answer, and the
// caller silently holds compartments nobody granted. Every consumer of a
// folded bitset has to be on the same generation as the fold, which is why
// WithRegistry exists and why the surface pins one per request.
type Compartments interface {
	// Registry is the taxonomy to use right now. It is read once per
	// verification, so a swap never splits a single token's fold across two
	// generations.
	Registry() *policy.Registry
}

type registryKey struct{}

// WithRegistry pins the taxonomy for one request.
//
// The caller is the surface, which reads the catalogue generation and its
// chain exactly once and then hands that same generation's registry to the
// fold. It outranks anything on the Config because the generation that will
// INTERPRET the bitset — the chain, comparing it against each tool's declared
// compartments — is the plane's, and the two must not be allowed to be on
// different clocks.
//
// A nil registry is ignored rather than pinned, for the same reason Set
// ignores one: there is no state in which "no taxonomy" is the right answer,
// and a nil here could only come from a caller that has nothing to pin.
func WithRegistry(ctx context.Context, reg *policy.Registry) context.Context {
	if reg == nil {
		return ctx
	}
	return context.WithValue(ctx, registryKey{}, reg)
}

// registryFrom returns the taxonomy pinned for this request, if any.
func registryFrom(ctx context.Context) *policy.Registry {
	reg, _ := ctx.Value(registryKey{}).(*policy.Registry)
	return reg
}

// Swappable is a compartment taxonomy a catalogue reload can replace.
//
// This closes a gap that failed silently and in the safe direction, which is
// the worst combination: the registry was built once at boot, so a reload that
// ADDED a compartment did not reach the verifier, and every token asserting the
// new name had it dropped. Callers lost authority they had been granted, with
// no error anywhere, until someone restarted the process.
//
// An atomic pointer rather than a mutex because the read is on every request
// and the write is on a reload: a lock here would put every verification behind
// the same word, for a value that changes twice a day.
//
// internal/reload drives Set, on a generation that became current and never on
// one that was refused. It is the FALLBACK taxonomy: a request served through
// the surface folds against the registry of the plane serving it, pinned with
// WithRegistry, which is what keeps a fold and the chain that judges it on the
// same generation even across a swap.
type Swappable struct {
	p atomic.Pointer[policy.Registry]
}

func NewSwappable(reg *policy.Registry) *Swappable {
	s := &Swappable{}
	s.Set(reg)
	return s
}

// Set publishes a new taxonomy.
//
// A nil is ignored rather than stored. There is no state in which "no
// taxonomy" is the right answer — a verifier that read it as "no restrictions"
// would be exactly backwards, and one that read it as "nothing is declared"
// would drop every compartment in every token — so the failure to build a new
// registry has to leave the working one in place, and the caller has to log it.
func (s *Swappable) Set(reg *policy.Registry) {
	if reg != nil {
		s.p.Store(reg)
	}
}

func (s *Swappable) Registry() *policy.Registry { return s.p.Load() }
