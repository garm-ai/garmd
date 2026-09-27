package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// Minter is a thing that hands out tokens. It is an interface so the runner
// is testable in process; the only production implementation is HTTPMinter,
// because an import would defeat the boundary.
//
// A Minter that REFUSES must say so with a *RefusalError. Any other error
// means the minter did not answer, which is a different fact entirely — see
// RefusalError.
type Minter interface {
	Token(ctx context.Context, params map[string]string) (string, error)
}

// RefusalError is a minter that answered and said no.
//
// It is a distinct type because `mintError` on a case asserts that the minter
// REFUSED — an entitlement it enforces — and "could not be reached" is not
// "said no". Without the distinction, a suite of nothing but `mintError`
// cases pointed at a dead port reports ok while checking nothing, which is
// the exact failure this package exists to prevent.
type RefusalError struct {
	Status int
	Body   string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("minter returned %d: %s", e.Status, e.Body)
}

// HTTPMinter asks a minter over loopback. A non-200 is an error, never an
// empty token: a minter that has stopped answering must fail the run.
type HTTPMinter struct {
	BaseURL string
	Client  *http.Client
}

func (m HTTPMinter) Token(ctx context.Context, params map[string]string) (string, error) {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u := strings.TrimSuffix(m.BaseURL, "/") + "/token?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	c := m.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("minter unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// A refusal: the minter was reached and declined. Transport
		// failures above stay ordinary wrapped errors, so the two can
		// never be confused by a case asserting mintError.
		return "", &RefusalError{
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(b)),
		}
	}
	return strings.TrimSpace(string(b)), nil
}

// Result is one case's verdict. Err nil means the fold matched.
type Result struct {
	Case string
	Err  error
}

// Run executes every case and returns a verdict for each.
//
// A case failure is data rather than an abort, so one run reports every
// disagreement instead of the first: a minter whose claim shape has drifted
// usually breaks several cases, and seeing all of them is the difference
// between one fix and several round trips.
func Run(ctx context.Context, s *Suite, m Minter, jwksURL string) ([]Result, error) {
	decls := make([]*toolv1.Decl, 0, len(s.Compartments))
	for _, n := range s.Compartments {
		decls = append(decls, &toolv1.Decl{Name: n})
	}
	reg, err := policy.NewRegistry(decls)
	if err != nil {
		return nil, fmt.Errorf("conformance: building the compartment registry: %w", err)
	}
	v := authn.NewVerifier(authn.Config{
		KeySet:       authn.NewKeySet(authn.KeySetConfig{URL: jwksURL}),
		Issuers:      []string{s.Issuer},
		Audience:     s.Audience,
		Compartments: reg,
	})

	out := make([]Result, 0, len(s.Cases))
	for _, c := range s.Cases {
		out = append(out, Result{Case: c.Name, Err: runCase(ctx, c, m, v, reg)})
	}
	return out, nil
}

func runCase(ctx context.Context, c Case, m Minter, v *authn.Verifier, reg *policy.Registry) error {
	tok, mintErr := m.Token(ctx, c.Mint)
	if c.MintError {
		if mintErr == nil {
			return fmt.Errorf("the minter granted this, but the suite says it must refuse")
		}
		// Only a refusal satisfies the assertion. A dead port, a DNS
		// failure or a timeout all produce a non-nil error too, and
		// accepting those would turn "delegation is refused" into
		// "something went wrong", which any broken setup satisfies.
		var refusal *RefusalError
		if !errors.As(mintErr, &refusal) {
			return fmt.Errorf("the suite says the minter must refuse this, but the minter "+
				"could not be reached at all — that asserts nothing: %w", mintErr)
		}
		return nil
	}
	if mintErr != nil {
		return fmt.Errorf("minting: %w", mintErr)
	}

	p, dropped, err := v.Verify(ctx, tok)
	if err != nil {
		return fmt.Errorf("verifying: %w", err)
	}
	return compare(c.Expect, p, dropped, reg)
}

// compare reports every field that disagrees, not just the first: a claim
// shape that has drifted usually moves more than one.
func compare(e *Expect, p *toolplane.Principal, dropped []string, reg *policy.Registry) error {
	var bad []string
	// Unconditional, like every other field here: LoadSuite requires
	// `subject`, so an omitted one is a malformed suite rather than a
	// silent "assert nothing".
	if p.Subject != e.Subject {
		bad = append(bad, fmt.Sprintf("subject: got %q want %q", p.Subject, e.Subject))
	}
	if p.Actor != e.Actor {
		bad = append(bad, fmt.Sprintf("actor: got %q want %q", p.Actor, e.Actor))
	}
	// Kind is the one field left optional, and deliberately: it is
	// attribution rather than authority, so a suite that does not name it is
	// making a legitimate choice, not losing an assertion it meant to make.
	// Every other field above and below is asserted whether the case names
	// it or not.
	if e.Kind != "" && p.Kind.String() != e.Kind {
		bad = append(bad, fmt.Sprintf("kind: got %s want %s", p.Kind, e.Kind))
	}
	if p.Clearance.String() != e.Clearance {
		bad = append(bad, fmt.Sprintf("clearance: got %s want %s", p.Clearance, e.Clearance))
	}
	if d := diffSets(reg.Names(p.Compartments), e.Compartments); d != "" {
		bad = append(bad, "compartments: "+d)
	}
	if d := diffSets(verbNames(p.Verbs), e.Verbs); d != "" {
		bad = append(bad, "verbs: "+d)
	}
	if d := diffToolSets(p.ToolSets, e.ToolSets); d != "" {
		bad = append(bad, "toolSets: "+d)
	}
	if d := diffSets(dropped, e.Dropped); d != "" {
		bad = append(bad, "dropped: "+d)
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(bad, "; "))
}

// diffSets compares order-insensitively and treats nil and empty as equal —
// a claim that omitted a list and one that sent an empty list mean the same
// thing to the fold.
func diffSets(got, want []string) string {
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	if slices.Equal(g, w) {
		return ""
	}
	return fmt.Sprintf("got %v want %v", g, w)
}

// diffToolSets compares scope, where nil and non-nil-empty are NOT the same
// thing: nil means unscoped (the full catalogue) and a non-nil empty slice
// means scoped to nothing, per toolplane.Principal's own doc comment. A
// suite must be able to assert either, so this does not route through
// diffSets, which treats them as equal.
func diffToolSets(got []string, want *[]string) string {
	switch {
	case want == nil:
		if got != nil {
			return fmt.Sprintf("got %v want unscoped (nil)", got)
		}
		return ""
	case len(*want) == 0:
		if got == nil {
			return "got unscoped (nil) want scoped to nothing (non-nil, empty)"
		}
		if len(got) != 0 {
			return fmt.Sprintf("got %v want scoped to nothing (non-nil, empty)", got)
		}
		return ""
	default:
		if got == nil {
			return fmt.Sprintf("got unscoped (nil) want %v", *want)
		}
		return diffSets(got, *want)
	}
}

// verbNames spells out every verb the set holds.
//
// It reads the generated enum rather than a hand-written list: a fourth verb
// added upstream would otherwise be invisible here, and a minter granting it
// against a verifier folding it would agree silently — the harness reporting
// ok about a field it cannot see. VERB_UNSPECIFIED is skipped because it is
// the zero value, not a grant, and the result is sorted so a map's iteration
// order cannot make a passing case flap.
func verbNames(vs toolplane.VerbSet) []string {
	var out []string
	for code, name := range toolv1.Verb_name {
		if toolv1.Verb(code) == toolv1.Verb_VERB_UNSPECIFIED {
			continue
		}
		if vs.Has(toolv1.Verb(code)) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
