package toolplane

import (
	"sort"
	"strings"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
)

// CatalogFilter narrows a listing. Every field is optional and they are
// CONJUNCTIVE: two filters are an intersection, never a union.
//
// Filters, never scores. Relevance ranking would put an index or an embedding
// in the discovery path, and it collides with the parent spec's rejection of
// tool selection as garm's job — garm says what a caller MAY call, and the
// model decides what it SHOULD call. A ranked list quietly does the second.
type CatalogFilter struct {
	// NamePrefix matches the tool's name, not its FQN: a model that half
	// remembers a name is looking for "lookup_", not for a proto package.
	NamePrefix string

	// Verb, when set (non-zero), keeps only tools of that verb.
	Verb toolv1.Verb

	// Service is the proto service name, e.g. "AccountsService".
	Service string

	// Set keeps only tools declaring membership of this tool set.
	Set string

	// MaxApprovalMode, when set, keeps only tools whose approval mode is at
	// most this — so a caller that cannot satisfy approvals can ask for the
	// tools it is able to complete unaided.
	MaxApprovalMode toolv1.Approval_Mode
}

// Catalog returns the tools this principal may see, filtered and sorted.
//
// Visibility is decided by Visible — the SAME predicate step 2 denies with.
// That is the point, and it is structural rather than a convention: the
// catalogue cannot list a tool the chain would deny, because there is only
// one rule and both call it. Two hand-written lists that agree today would
// stop agreeing the first time one changed, and neither side would look
// wrong.
//
// Sorted by FQN, so two listings can be diffed. An unsorted catalogue appears
// to change on every call.
func (c *Core) Catalog(p *Principal, f CatalogFilter) []ToolDef {
	if p == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]ToolDef, 0, len(c.tools))
	for _, t := range c.tools {
		if !c.visibleLocked(p, t) || !f.matches(t) {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQN < out[j].FQN })
	return out
}

// ToolByFQN returns one tool, if this principal may see it.
//
// The second return is false both for a tool that does not exist and for one
// this caller may not see, and the caller must not distinguish them: detail
// that answered differently would be a way to enumerate exactly the tools the
// listing withholds.
func (c *Core) ToolByFQN(p *Principal, fqn string) (ToolDef, bool) {
	if p == nil || fqn == "" {
		return ToolDef{}, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, t := range c.tools {
		if t.FQN == fqn {
			if !c.visibleLocked(p, t) {
				return ToolDef{}, false
			}
			return t, true
		}
	}
	return ToolDef{}, false
}

// matches applies the filter. A zero field means "no opinion", so an empty
// filter keeps everything the principal may see.
func (f CatalogFilter) matches(t ToolDef) bool {
	if f.NamePrefix != "" && !strings.HasPrefix(t.Name, f.NamePrefix) {
		return false
	}
	if f.Verb != toolv1.Verb_VERB_UNSPECIFIED && t.Verb != f.Verb {
		return false
	}
	if f.Service != "" && t.Service() != f.Service {
		return false
	}
	if f.Set != "" && !containsString(t.Sets, f.Set) {
		return false
	}
	if f.MaxApprovalMode != toolv1.Approval_MODE_UNSPECIFIED &&
		t.ApprovalMode > f.MaxApprovalMode {
		return false
	}
	return true
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
