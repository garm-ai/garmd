package toolplane

import (
	"fmt"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
)

// ShapeRequest asks for a view as a LESSER principal.
//
// An absent dimension means "do not narrow this one", matching how a real
// principal reads an absent claim — otherwise asking about clearance alone
// would silently strip every compartment and verb, and the answer would be
// about a principal nobody described.
//
// HasClearance exists because CLEARANCE_UNSPECIFIED is a real value that
// means "the token did not say", and a zero Clearance field cannot be
// distinguished from an unset one.
type ShapeRequest struct {
	Clearance    toolv1.Clearance
	HasClearance bool
	Compartments []string
	Verbs        []toolv1.Verb
	ToolSets     []string
}

// Narrow returns the principal a caller is asking to be answered as.
//
// It can only ever go DOWN, and every widening is refused. That single rule
// is what makes this safe to expose with no flag, no dev mode and no loopback
// check: projecting downward reveals nothing a caller could not already learn
// from their own catalogue, while projecting upward would answer questions
// about tools they cannot see — which is exactly what step 2 answers NotFound
// to protect.
//
// The result is a PREVIEW, not a credential. Subject and TokenID are
// unchanged, so anything ledgered stays attributable to the caller who asked;
// and nothing in this package will invoke with it, because invocation takes
// the principal the surface authenticated, never one derived here.
func (c *Core) Narrow(p *Principal, want ShapeRequest) (*Principal, error) {
	if p == nil {
		return nil, fmt.Errorf("toolplane: no principal to narrow")
	}

	out := *p // copy: the caller's principal must not be mutated

	if want.HasClearance && want.Clearance != toolv1.Clearance_CLEARANCE_UNSPECIFIED {
		if !policy.Allows(p.Clearance, want.Clearance) {
			return nil, fmt.Errorf(
				"toolplane: cannot preview clearance %v: you hold %v, and a preview "+
					"may only narrow", want.Clearance, p.Clearance)
		}
		out.Clearance = want.Clearance
	}

	if len(want.Compartments) > 0 {
		c.mu.RLock()
		bits, err := c.reg.Set(want.Compartments)
		c.mu.RUnlock()
		if err != nil {
			return nil, fmt.Errorf("toolplane: %w", err)
		}
		if !p.Compartments.Covers(bits) {
			return nil, fmt.Errorf(
				"toolplane: cannot preview compartments you do not hold; a preview " +
					"may only narrow")
		}
		out.Compartments = bits
	}

	if len(want.Verbs) > 0 {
		verbs := NewVerbSet(want.Verbs...)
		for _, v := range want.Verbs {
			if !p.Verbs.Has(v) {
				return nil, fmt.Errorf(
					"toolplane: cannot preview verb %v, which you do not hold; a "+
						"preview may only narrow", v)
			}
		}
		out.Verbs = verbs
	}

	if len(want.ToolSets) > 0 {
		// Scoping narrows by construction: a scope the caller is not
		// entitled to matches no tool they can see, so there is nothing to
		// refuse. Intersecting with an existing scope keeps that true when
		// the caller is already scoped.
		if p.ToolSets == nil {
			out.ToolSets = append([]string(nil), want.ToolSets...)
		} else {
			keep := make([]string, 0, len(want.ToolSets))
			for _, w := range want.ToolSets {
				for _, h := range p.ToolSets {
					if w == h {
						keep = append(keep, w)
						break
					}
				}
			}
			out.ToolSets = keep
		}
	}

	return &out, nil
}
