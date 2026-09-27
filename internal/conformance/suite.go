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
	// shapes.
	Mint map[string]string `json:"mint"`

	// Expect is the Principal the fold must produce. Exactly one of Expect
	// and MintError is set.
	Expect *Expect `json:"expect"`

	// MintError asserts the minter REFUSES. An entitlement the minter
	// enforces is part of the contract too: garm folds a chain it is given
	// and cannot know whether the delegation was permitted.
	MintError bool `json:"mintError"`
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
		if (c.Expect == nil) == !c.MintError {
			return nil, fmt.Errorf("conformance: %s: case %q must set exactly one of expect and mintError",
				path, c.Name)
		}
		if c.Expect == nil {
			continue
		}
		if c.Expect.Clearance == "" {
			return nil, fmt.Errorf("conformance: %s: case %q expects no clearance; "+
				"a fold always produces one", path, c.Name)
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
