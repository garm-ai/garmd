// Package conformance checks that a token minter and this verifier agree.
//
// It exists because garmd may not import a minter and a minter may not
// import the verifier — see devkit/README.md. The agreement is therefore
// asserted against a declarative suite owned by neither, obtained over HTTP
// at run time, which adds no dependency edge in either direction.
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/grant"
)

// Suite is one minter's conformance table.
type Suite struct {
	// Issuer and Audience are what the minter is configured to emit; the
	// verifier under test is built to trust exactly these.
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`

	// Compartments is the vocabulary this build declares. A name outside it
	// is dropped by SetLenient rather than refused, which is what `dropped`
	// on a case asserts.
	Compartments []string `json:"compartments"`

	Cases []Case `json:"cases"`
}

// Case is one persona and what verifying its token must produce.
type Case struct {
	Name string `json:"name"`

	// Mint is the query the minter is asked, verbatim. Keeping it opaque is
	// what lets one suite format serve minters with different request
	// shapes. It is required and must be non-empty: a minter asked for
	// nothing answers with whatever it defaults to.
	Mint map[string]string `json:"mint"`

	// Expect is the Principal the fold must produce. Exactly one of Expect,
	// MintError, Grant and GrantError is set.
	Expect *Expect `json:"expect"`

	// MintError asserts the minter REFUSES. An entitlement the minter
	// enforces is part of the contract too: garm folds a chain it is given
	// and cannot know whether the delegation was permitted.
	MintError bool `json:"mintError"`

	// Grant asks the minter's APPROVAL endpoint for a grant and checks that
	// this daemon's own verifier accepts it. A grant case drives a
	// different endpoint from Mint and carries no mint params.
	//
	// Exactly one of Expect, MintError, Grant and GrantError is set.
	Grant *Grant `json:"grant"`

	// GrantError asks the minter's APPROVAL endpoint for a grant and asserts
	// that it REFUSES — the counterpart of MintError for POST /approve. A
	// customer approving, a delegated identity approving, a malformed
	// material path, a calling service that never authenticated: each is a
	// refusal the STS owes a caller, and each is unchecked by a suite that
	// can only say "approve this".
	//
	// Exactly one of Expect, MintError, Grant and GrantError is set.
	GrantError *GrantError `json:"grantError"`
}

// Expect is a folded Principal, in claim spellings rather than enum values
// so the suite stays readable and language-neutral.
type Expect struct {
	Subject      string   `json:"subject"`
	Actor        string   `json:"actor"`
	Kind         string   `json:"kind"`
	Clearance    string   `json:"clearance"`
	Compartments []string `json:"compartments"`
	Verbs        []string `json:"verbs"`

	// ToolSets asserts scope, and its zero value is deliberately not a slice:
	// nil/absent, `[]`, and a populated list are three different assertions,
	// mirroring the same load-bearing distinction on toolplane.Principal.
	//
	//   - absent, or JSON null: the principal must be UNSCOPED (nil).
	//   - `[]`:                 the principal must be scoped to NOTHING
	//                           (non-nil, empty) — what two disjoint scopes
	//                           intersect to.
	//   - `["a","b"]`:          the principal's scope must equal this set,
	//                           order-insensitively.
	ToolSets *[]string `json:"toolSets"`

	Dropped []string `json:"dropped"`

	// Execution is the `exec.sub` the fold carried through, empty when the
	// token had no exec claim. Asserted UNCONDITIONALLY, like subject and
	// actor: a case that omits it is asserting the token carried no exec at
	// all, which is exactly what every exchange-1 case needs to say and
	// what would otherwise go unchecked.
	Execution string `json:"execution"`

	// Tenant is the `tenant` claim the fold carried through. Asserted
	// UNCONDITIONALLY and required at load: it is what confines a caller to
	// their own organisation's data, and on the governed door it arrives as
	// a form field the runner supplies rather than inside a verified subject
	// token — which is exactly the kind of value a drift check must pin.
	Tenant string `json:"tenant"`

	// Chain is every hop the fold walked, IN ORDER: Chain[0] is the subject
	// and the last entry is the actor (for a direct token the chain is the
	// subject alone). Asserted unconditionally and required at load, and
	// compared as an ordered list rather than a set — a chain is the record
	// of who acted for whom, and reversing it is a different fact.
	Chain []string `json:"chain"`
}

// ApprovalRequest is one call to the approval endpoint: the approver as
// the upstream IdP is asked to mint them, and the request body itself. It
// is what a GrantMinter is handed, and both Grant and GrantError produce
// one — a grant case asks for it to succeed, a grantError case for it to
// be refused.
type ApprovalRequest struct {
	Approver             string
	ApproverTenant       string
	ApproverClearance    string
	ApproverCompartments []string

	// ApproverActor, when set, asks the upstream IdP to mint the approver's
	// token WITH an `act` chain naming this actor — a delegated identity,
	// which the STS refuses as an approver. Only a refusal case sets it.
	ApproverActor string

	Tool     string
	Subject  string
	Material map[string]string

	// OmitClientAssertion sends the request with no client_assertion at
	// all: the calling service never authenticates. Only a refusal case
	// sets it.
	OmitClientAssertion bool
}

// Grant is one approval case: what to ask the approval endpoint for, and
// what this daemon's verifier must then accept.
//
// The first block describes the APPROVER as the upstream IdP is asked to
// mint them; the second is the approval request itself; the third is what a
// tool would declare, so checkShape has something to judge the recorded
// authority against; the fourth is what the grant must then say.
type Grant struct {
	Approver             string   `json:"approver"`
	ApproverTenant       string   `json:"approverTenant"`
	ApproverClearance    string   `json:"approverClearance"`
	ApproverCompartments []string `json:"approverCompartments"`

	Tool     string            `json:"tool"`
	Subject  string            `json:"subject"`
	Material map[string]string `json:"material"`

	ToolApproverMinClearance string   `json:"toolApproverMinClearance"`
	ToolApproverCompartments []string `json:"toolApproverCompartments"`
	ToolMaxGrantAgeSeconds   int      `json:"toolMaxGrantAgeSeconds"`

	// ExpectApprover is the identity the grant must record. It is the one
	// value the issuer DERIVES rather than copies — from the verified
	// token's sub and the issuer's configured kind — so it is the one worth
	// asserting separately from what the verifier already checks.
	ExpectApprover string `json:"expectApprover"`
}

// Request is the approval call a grant case makes. Never delegated and
// never unauthenticated: those knobs exist only on GrantError, and a grant
// case's JSON cannot even name them.
func (g Grant) Request() ApprovalRequest {
	return ApprovalRequest{
		Approver:             g.Approver,
		ApproverTenant:       g.ApproverTenant,
		ApproverClearance:    g.ApproverClearance,
		ApproverCompartments: g.ApproverCompartments,
		Tool:                 g.Tool,
		Subject:              g.Subject,
		Material:             g.Material,
	}
}

// GrantError is one approval REFUSAL case: what to ask the approval
// endpoint for, such that it must say no.
//
// It carries the approver and the request as Grant does, plus the two
// knobs that make a request refusable — a delegated approver and an
// omitted client_assertion — and NO tool declaration or expected approver,
// because there is no grant to judge. A material path here is deliberately
// NOT validated at load: a malformed one is the point of the case that
// carries it.
//
// The refusal it is satisfied by is exactly one: the STS's own opaque
// `400 {"error":"access_denied"}`. See runGrantErrorCase.
type GrantError struct {
	Approver             string   `json:"approver"`
	ApproverTenant       string   `json:"approverTenant"`
	ApproverClearance    string   `json:"approverClearance"`
	ApproverCompartments []string `json:"approverCompartments"`
	ApproverActor        string   `json:"approverActor"`

	Tool     string            `json:"tool"`
	Subject  string            `json:"subject"`
	Material map[string]string `json:"material"`

	OmitClientAssertion bool `json:"omitClientAssertion"`
}

// Request is the approval call a refusal case makes, exactly as declared.
func (g GrantError) Request() ApprovalRequest {
	return ApprovalRequest{
		Approver:             g.Approver,
		ApproverTenant:       g.ApproverTenant,
		ApproverClearance:    g.ApproverClearance,
		ApproverCompartments: g.ApproverCompartments,
		ApproverActor:        g.ApproverActor,
		Tool:                 g.Tool,
		Subject:              g.Subject,
		Material:             g.Material,
		OmitClientAssertion:  g.OmitClientAssertion,
	}
}

// LoadSuite reads and validates a suite file.
//
// Validation is strict because a malformed suite fails OPEN: a case that
// asserts nothing passes, and a suite of such cases reports success while
// checking nothing. That is the same failure shape as a test file whose
// tests all skip.
func LoadSuite(path string) (*Suite, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("conformance: %w", err)
	}
	var s Suite
	dec := json.NewDecoder(bytes.NewReader(b))
	// A misspelled key is a case that silently asserts nothing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("conformance: %s: %w", path, err)
	}
	if s.Issuer == "" {
		return nil, fmt.Errorf("conformance: %s: issuer is required", path)
	}
	if s.Audience == "" {
		return nil, fmt.Errorf("conformance: %s: audience is required", path)
	}
	if len(s.Cases) == 0 {
		return nil, fmt.Errorf("conformance: %s: no cases; an empty suite passes trivially", path)
	}
	for i, c := range s.Cases {
		if c.Name == "" {
			return nil, fmt.Errorf("conformance: %s: case %d has no name", path, i)
		}
		asserted := 0
		if c.Expect != nil {
			asserted++
		}
		if c.MintError {
			asserted++
		}
		if c.Grant != nil {
			asserted++
		}
		if c.GrantError != nil {
			asserted++
		}
		if asserted != 1 {
			return nil, fmt.Errorf("conformance: %s: case %q asserts %d things; it must set "+
				"exactly one of expect, mintError, grant and grantError", path, c.Name, asserted)
		}
		// A grant or grantError case drives the APPROVAL endpoint, not the
		// token one, so the "asks the minter for nothing" rule below does
		// not apply to it — its own required fields are checked instead.
		if c.Grant != nil {
			if err := validateGrant(path, c.Name, c.Grant); err != nil {
				return nil, err
			}
			continue
		}
		if c.GrantError != nil {
			if err := validateGrantError(path, c.Name, c.GrantError); err != nil {
				return nil, err
			}
			continue
		}
		if len(c.Mint) == 0 {
			return nil, fmt.Errorf("conformance: %s: case %q asks the minter for nothing; "+
				"a minter handed no parameters mints whatever it defaults to, "+
				"so the case would pass or fail on something other than its subject",
				path, c.Name)
		}
		if c.Expect == nil {
			continue
		}
		if c.Expect.Clearance == "" {
			return nil, fmt.Errorf("conformance: %s: case %q expects no clearance; "+
				"a fold always produces one", path, c.Name)
		}
		// Same reasoning as clearance: a fold always produces a subject, so
		// a case that names none is not asserting "any subject" — it is
		// asserting nothing, and compare would pass it whoever the token
		// turned out to be.
		if c.Expect.Subject == "" {
			return nil, fmt.Errorf("conformance: %s: case %q expects no subject; "+
				"a fold always produces one, and a case that omits it would pass "+
				"for any identity", path, c.Name)
		}
		for _, name := range c.Expect.Compartments {
			if !slices.Contains(s.Compartments, name) {
				return nil, fmt.Errorf("conformance: %s: case %q expects compartment %q, "+
					"which the suite does not declare — the verifier would drop it",
					path, c.Name, name)
			}
		}
		for _, name := range c.Expect.Dropped {
			if slices.Contains(s.Compartments, name) {
				return nil, fmt.Errorf("conformance: %s: case %q expects %q to be dropped, "+
					"but the suite declares it", path, c.Name, name)
			}
		}
		if err := validateTenantAndChain(path, c.Name, c.Expect); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// validateTenantAndChain refuses an expectation that would pass for any
// tenant or any chain. Both are asserted unconditionally by compare, so an
// omitted one is not "don't care" — it is a case asserting the fold carried
// no tenant and walked no hops, which no verified token produces, and the
// case would then fail on every run for a reason it never states. The chain
// is also checked against the subject and actor the same case names, since
// the fold derives both from it: a case that disagrees with itself is wrong
// before a token is ever minted.
func validateTenantAndChain(path, name string, e *Expect) error {
	if e.Tenant == "" {
		return fmt.Errorf("conformance: %s: case %q expects no tenant; a fold always "+
			"carries one, and the tenant is what confines a caller to their own "+
			"organisation's data — it must be asserted", path, name)
	}
	if len(e.Chain) == 0 {
		return fmt.Errorf("conformance: %s: case %q expects no chain; a fold always walks "+
			"at least the subject, so the chain must be asserted, in order", path, name)
	}
	if e.Chain[0] != e.Subject {
		return fmt.Errorf("conformance: %s: case %q: chain[0] is %q but subject is %q; "+
			"the chain starts with the subject", path, name, e.Chain[0], e.Subject)
	}
	last := e.Chain[len(e.Chain)-1]
	if len(e.Chain) == 1 && e.Actor != "" {
		return fmt.Errorf("conformance: %s: case %q: chain names only the subject but "+
			"actor is %q; a delegated token's chain ends with the actor", path, name, e.Actor)
	}
	if len(e.Chain) > 1 && last != e.Actor {
		return fmt.Errorf("conformance: %s: case %q: chain ends with %q but actor is %q; "+
			"the last hop of the chain is the actor", path, name, last, e.Actor)
	}
	return nil
}

// validateGrantError refuses a refusal case that could be refused for a
// reason it never names. A refusal case is satisfied by ANY opaque denial,
// which is inherent to asserting "no" — mintError has the same shape — so
// what the loader can do is insist the request is well-formed on every
// axis the case does not claim to be testing: the tool, the subject and
// the approver are present, and the approver's clearance is a real one, so
// that "no usable authority" is never the refusal a misspelling earns.
func validateGrantError(path, name string, g *GrantError) error {
	for _, f := range []struct{ field, value string }{
		{"tool", g.Tool},
		{"subject", g.Subject},
		{"approver", g.Approver},
	} {
		if f.value == "" {
			return fmt.Errorf("conformance: %s: grantError case %q has no %s", path, name, f.field)
		}
	}
	if _, err := ClearanceValue(g.ApproverClearance); err != nil {
		return fmt.Errorf("conformance: %s: grantError case %q: approverClearance: %w "+
			"— an approver minted with no real clearance is refused for asserting no "+
			"authority, which would satisfy this case for the wrong reason",
			path, name, err)
	}
	return nil
}

// validateGrant refuses a grant case that would assert nothing. Same
// reasoning as everywhere else in this loader: a malformed suite fails
// OPEN, and an approval case missing its tool would be satisfied by a grant
// approving anything at all.
func validateGrant(path, name string, g *Grant) error {
	for _, f := range []struct{ field, value string }{
		{"tool", g.Tool},
		{"subject", g.Subject},
		{"approver", g.Approver},
		{"expectApprover", g.ExpectApprover},
	} {
		if f.value == "" {
			return fmt.Errorf("conformance: %s: grant case %q has no %s", path, name, f.field)
		}
	}
	// Both clearances, at LOAD, because this is the one typo in a grant case
	// that fails OPEN. grants.Verifier skips the approver-seniority check
	// entirely when the tool's ApproverMinClearance is UNSPECIFIED, and an
	// unknown name is UNSPECIFIED — so "RESTRICTD" would mint a grant, verify
	// it without ever judging the approver, and report ok. UNSPECIFIED spelled
	// out is refused for the same reason and not as a shape rule: a case may
	// legitimately want a tool that requires no particular seniority, but it
	// cannot want that here, where the whole point is to pin what the issuer
	// recorded against what a tool demanded.
	for _, f := range []struct{ field, value string }{
		{"approverClearance", g.ApproverClearance},
		{"toolApproverMinClearance", g.ToolApproverMinClearance},
	} {
		if _, err := ClearanceValue(f.value); err != nil {
			return fmt.Errorf("conformance: %s: grant case %q: %s: %w", path, name, f.field, err)
		}
	}
	// Same fail-open shape: checkShape skips the age check when MaxGrantAge is
	// zero, so a case declaring no ceiling asserts that an approval of ANY age
	// is accepted — which is not what a grant case is for.
	if g.ToolMaxGrantAgeSeconds <= 0 {
		return fmt.Errorf("conformance: %s: grant case %q: toolMaxGrantAgeSeconds is %d; "+
			"it must be positive, because a tool declaring no ceiling has no age this "+
			"verifier checks and the case would accept an approval of any age",
			path, name, g.ToolMaxGrantAgeSeconds)
	}
	// Checked here rather than left to the issuer: a path the issuer would
	// refuse turns the case into an accidental mintError, which is not what
	// it says it is asserting.
	for p := range g.Material {
		if err := grant.ValidPath(p); err != nil {
			return fmt.Errorf("conformance: %s: grant case %q: material path: %w", path, name, err)
		}
	}
	return nil
}

// ClearanceValue reads the bare spelling a suite writes ("RESTRICTED") and the
// CLEARANCE_ spelling the enum uses, and REFUSES anything else — including
// UNSPECIFIED, which is the zero value rather than a clearance anybody holds.
//
// It returns an error rather than a zero value because the zero value is the
// dangerous answer here: every check in grants.Verifier that reads a clearance
// treats UNSPECIFIED as "no requirement", so a silent fallback turns a typo
// into a case that passes while checking less than it says.
func ClearanceValue(name string) (toolv1.Clearance, error) {
	spelled := strings.ToUpper(strings.TrimSpace(name))
	if spelled != "" && !strings.HasPrefix(spelled, "CLEARANCE_") {
		spelled = "CLEARANCE_" + spelled
	}
	v, ok := toolv1.Clearance_value[spelled]
	if !ok || toolv1.Clearance(v) == toolv1.Clearance_CLEARANCE_UNSPECIFIED {
		return toolv1.Clearance_CLEARANCE_UNSPECIFIED, fmt.Errorf(
			"%q is not a clearance; want one of PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED "+
				"(bare or CLEARANCE_-prefixed)", name)
	}
	return toolv1.Clearance(v), nil
}
