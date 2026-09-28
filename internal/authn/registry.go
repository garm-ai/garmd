package authn

import (
	"sync/atomic"

	"github.com/garm-ai/garm/policy"
)

// Compartments supplies the taxonomy a token's compartment names resolve
// against, for the generation currently being served.
//
// An interface rather than the registry itself because the taxonomy is a
// property of the CATALOGUE — an enterprise declares its own and ships it in
// the artifact — and the catalogue reloads under a running process. A verifier
// holding a value could only ever decide with the one it was built from.
type Compartments interface {
	// Registry is the taxonomy to use right now. It is read once per
	// verification, so a swap never splits a single token's fold across two
	// generations.
	Registry() *policy.Registry
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
// Nothing drives Set yet. The reload path that will call it is a later task;
// this holds one generation and serves it until then.
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
