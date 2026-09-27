package conformance

import (
	"context"
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
type Minter interface {
	Token(ctx context.Context, params map[string]string) (string, error)
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
		return "", fmt.Errorf("minter returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(b)))
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
	if e.Subject != "" && p.Subject != e.Subject {
		bad = append(bad, fmt.Sprintf("subject: got %q want %q", p.Subject, e.Subject))
	}
	if p.Actor != e.Actor {
		bad = append(bad, fmt.Sprintf("actor: got %q want %q", p.Actor, e.Actor))
	}
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
	if d := diffSets(p.ToolSets, e.ToolSets); d != "" {
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

func verbNames(vs toolplane.VerbSet) []string {
	var out []string
	for _, v := range []toolv1.Verb{
		toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE, toolv1.Verb_VERB_DESTRUCTIVE,
	} {
		if vs.Has(v) {
			out = append(out, v.String())
		}
	}
	return out
}
