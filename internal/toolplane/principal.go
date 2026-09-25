// Package toolplane serves proto-defined tools behind one policy chain.
package toolplane

import (
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
)

// VerbSet is a bitset over Verb. Bit 0 (UNSPECIFIED) is never set, so an
// unspecified verb can never satisfy a membership test.
type VerbSet uint8

func NewVerbSet(vs ...toolv1.Verb) VerbSet {
	var out VerbSet
	for _, v := range vs {
		if v == toolv1.Verb_VERB_UNSPECIFIED {
			continue
		}
		out |= 1 << uint(v)
	}
	return out
}

func (s VerbSet) Has(v toolv1.Verb) bool {
	if v == toolv1.Verb_VERB_UNSPECIFIED {
		return false
	}
	return s&(1<<uint(v)) != 0
}

// Intersect narrows a verb set, for folding a delegation chain (Plan B).
func (s VerbSet) Intersect(o VerbSet) VerbSet { return s & o }

// Principal is an authenticated caller. Plan A supplies it from Config;
// Plan B derives it from a verified JWT.
type Principal struct {
	Subject string // whose authority
	Actor   string // who exercises it; empty when direct

	// Kind is WHAT the subject is — user, agent or service.
	//
	// Attribution, never authorization. Nothing in the chain reads it: the
	// ten steps decide on clearance, compartments, verbs and tool sets, and
	// a fifth vocabulary that could deny a call would mean two places to
	// look when one is refused. It exists because "which of these ledger
	// rows were agents" is a question people ask constantly and cannot
	// currently answer, and because the tool on the far side of the
	// resolver is entitled to know whether a human is waiting on it.
	//
	// It describes the SUBJECT, not the actor: on a delegated call this is
	// the kind of whoever's authority is being exercised, and Actor names
	// who is exercising it. Per-hop kinds would need Chain to carry more
	// than strings, which is a wire change the tool-service-shell spec will
	// force in its own time.
	Kind         toolv1.PrincipalKind
	Chain        []string // full delegation chain, for the ledger
	Tenant       string
	Clearance    toolv1.Clearance
	Compartments policy.CompartmentSet
	Verbs        VerbSet
	TokenID      string

	// ToolSets scopes this session. NIL means unscoped — the full catalogue
	// this principal is entitled to — and a non-nil slice means only tools
	// declaring membership of one of these sets.
	//
	// The nil/empty distinction is load-bearing: absent must mean EVERYTHING,
	// because a token that says nothing about scope is not a token that
	// scoped itself to nothing. An empty non-nil slice does mean nothing,
	// which is what two disjoint scopes intersect to and is the right answer
	// there.
	//
	// Sets NARROW and never widen: scoping is applied on top of the
	// clearance, compartment and verb checks rather than beside them, so a
	// caller cannot reach a tool by asking for a set.
	ToolSets []string
}

// Shape returns only the parts policy depends on.
//
// Identity is deliberately excluded: two callers with the same clearance and
// compartments resolve to the same plan, which is what gives the cache a hit
// rate near one.
func (p Principal) Shape() policy.Shape {
	return policy.Shape{Clearance: p.Clearance, Compartments: p.Compartments}
}
