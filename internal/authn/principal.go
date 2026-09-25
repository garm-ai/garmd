package authn

import (
	"fmt"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/toolplane"
	"github.com/garm-ai/garm/policy"
)

// maxDelegationDepth is the documented ceiling on a delegation chain.
//
// A chain is a blast radius: every hop is another party that can act as the
// subject. Four levels covers the real shapes — a user, an agent, an
// orchestrator, a service — and a fifth is far likelier to be a
// confused-deputy loop than a workflow anyone designed. Note this is a
// POLICY limit, distinct from ParseClaims' structural bound, which exists
// only to stop a hostile token exhausting the stack before we get here.
const maxDelegationDepth = 4

// Fold reduces a delegation chain to the single authority it actually
// carries, and returns the compartment names it had to drop so the ledger
// can record them.
//
// The rule is intersection at every level: minimum clearance, AND of
// compartments, AND of verbs. That is what makes delegation safe to reason
// about — adding a hop can only ever narrow authority, whatever the added
// hop claims for itself, so a compromised agent cannot escalate by minting
// itself a generous token.
func Fold(c *Claims, reg *policy.Registry) (*toolplane.Principal, []string, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("no claims")
	}
	if d := c.Depth(); d > maxDelegationDepth {
		return nil, nil, fmt.Errorf("delegation chain is %d deep; the limit is %d "+
			"— a chain this long is more likely a confused-deputy loop than a workflow",
			d, maxDelegationDepth)
	}

	var (
		clearance    toolv1.Clearance
		compartments policy.CompartmentSet
		verbs        toolplane.VerbSet
		chain        []string
		dropped      []string
		toolSets     []string
		first        = true
	)

	for cur := c; cur != nil; cur = cur.Act {
		chain = append(chain, cur.Subject)

		lvlClearance := toolv1.Clearance(toolv1.Clearance_value[cur.Garm.Clearance])
		// SetLenient, not Set: an unknown compartment is an IdP typo or a
		// name this build does not declare. It must cost THAT caller access
		// to THAT compartment, not fail the token and take the caller out
		// entirely — a deploy skew between IdP and build would otherwise be
		// an outage.
		lvlCompartments, lvlDropped := reg.SetLenient(cur.Garm.Compartments)
		dropped = append(dropped, lvlDropped...)
		lvlVerbs := verbSetFromNames(cur.Garm.Verbs)

		// Before the first-level shortcut, and unconditionally: an identity
		// that names no sets imposes no constraint, so intersecting is
		// correct at every level including the first.
		toolSets = intersectSets(toolSets, cur.Garm.ToolSets)

		if first {
			clearance, compartments, verbs = lvlClearance, lvlCompartments, lvlVerbs
			first = false
			continue
		}
		if int32(lvlClearance) < int32(clearance) {
			clearance = lvlClearance
		}
		compartments &= lvlCompartments
		verbs = verbs.Intersect(lvlVerbs)
	}

	p := &toolplane.Principal{
		Subject:      c.Subject,
		Chain:        chain,
		Tenant:       c.Tenant,
		Clearance:    clearance,
		Compartments: compartments,
		Verbs:        verbs,
		TokenID:      c.ID,
		// The SUBJECT's kind, taken from the outermost claims — whose
		// authority this is, not who is exercising it. Unlike clearance and
		// compartments it is not folded across the chain: intersecting
		// "user" with "agent" has no meaning, and the actor is already
		// recorded separately below.
		Kind: kindFromName(c.Garm.Kind),
		// Intersected across the chain like every other authority, with one
		// difference that matters: an identity that names no sets imposes no
		// constraint rather than contributing an empty one. A user who did
		// not scope themselves must not silently scope an agent to nothing.
		ToolSets: toolSets,
	}
	// Actor is the INNERMOST actor — the party actually making the call.
	// Empty for a direct token, which is how the ledger tells a human
	// calling directly from an agent calling on their behalf.
	if len(chain) > 1 {
		p.Actor = chain[len(chain)-1]
	}
	return p, dropped, nil
}

// intersectSets narrows a tool-set scope by one identity's claim.
//
// nil on either side means "no constraint from this side", which is why this
// cannot be a plain set intersection: a user who scoped nothing must not
// silently scope an agent to nothing, and an agent that scoped nothing must
// not widen a user who did.
//
// Two scopes that share nothing produce an EMPTY non-nil slice, and that is
// the right answer — a session scoped to sets it is not entitled to reaches
// no tools at all, rather than falling back to everything.
func intersectSets(have, add []string) []string {
	if len(add) == 0 {
		return have
	}
	if have == nil {
		out := make([]string, len(add))
		copy(out, add)
		return out
	}
	keep := make([]string, 0, len(have))
	for _, h := range have {
		for _, a := range add {
			if h == a {
				keep = append(keep, h)
				break
			}
		}
	}
	return keep
}

// kindFromName maps a normalised PrincipalKind name onto the enum. An empty
// or unrecognised name is UNSPECIFIED, which is a valid state: kind is
// attribution and a token that did not say is still a good token.
func kindFromName(name string) toolv1.PrincipalKind {
	if name == "" {
		return toolv1.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED
	}
	if v, ok := toolv1.PrincipalKind_value[name]; ok {
		return toolv1.PrincipalKind(v)
	}
	return toolv1.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED
}

// verbSetFromNames maps claim verb names onto the enum, tolerating the bare
// and VERB_-prefixed spellings for the same reason clearance does. An
// unrecognised verb is ignored rather than rejected: it can only ever narrow
// the intersection, so a claim naming a verb this build has never heard of
// is harmless.
func verbSetFromNames(names []string) toolplane.VerbSet {
	vs := make([]toolv1.Verb, 0, len(names))
	for _, n := range names {
		key := n
		if _, ok := toolv1.Verb_value[key]; !ok {
			key = "VERB_" + n
		}
		if v, ok := toolv1.Verb_value[key]; ok {
			vs = append(vs, toolv1.Verb(v))
		}
	}
	return toolplane.NewVerbSet(vs...)
}
