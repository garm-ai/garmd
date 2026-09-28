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

	"github.com/garm-ai/garm/contracts/grant"
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
	// MintError and Grant is set.
	Expect *Expect `json:"expect"`

	// MintError asserts the minter REFUSES. An entitlement the minter
	// enforces is part of the contract too: garm folds a chain it is given
	// and cannot know whether the delegation was permitted.
	MintError bool `json:"mintError"`

	// Grant asks the minter's APPROVAL endpoint for a grant and checks that
	// this daemon's own verifier accepts it. A grant case drives a
	// different endpoint from Mint and carries no mint params.
	//
	// Exactly one of Expect, MintError and Grant is set.
	Grant *Grant `json:"grant"`
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
		if asserted != 1 {
			return nil, fmt.Errorf("conformance: %s: case %q asserts %d things; it must set "+
				"exactly one of expect, mintError and grant", path, c.Name, asserted)
		}
		// A grant case drives the APPROVAL endpoint, not the token one, so
		// the "asks the minter for nothing" rule below does not apply to it
		// — its own required fields are checked instead.
		if c.Grant != nil {
			if err := validateGrant(path, c.Name, c.Grant); err != nil {
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
	}
	return &s, nil
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
