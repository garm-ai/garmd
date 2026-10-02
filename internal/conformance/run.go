package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/grant"
	"github.com/garm-ai/contracts/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/replay"
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

// GrantMinter is a minter that also issues APPROVAL grants. Optional,
// because a minter may implement the token endpoint and not the approval
// one — devkit does — and a suite carrying a grant case against such a
// minter must fail loudly rather than skip.
//
// Approve must report a refusal as a *RefusalError, exactly as Token does:
// a grantError case asserts that the approval endpoint SAID NO, and an
// endpoint that could not be reached said nothing.
type GrantMinter interface {
	Approve(ctx context.Context, req ApprovalRequest) (string, error)
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
		out = append(out, Result{Case: c.Name, Err: runCase(ctx, c, m, v, reg, s, jwksURL)})
	}
	return out, nil
}

func runCase(
	ctx context.Context, c Case, m Minter, v *authn.Verifier, reg *policy.Registry,
	s *Suite, jwksURL string,
) error {
	if c.Grant != nil {
		return runGrantCase(ctx, c, m, s, jwksURL)
	}
	if c.GrantError != nil {
		return runGrantErrorCase(ctx, c, m)
	}
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

// chainSubjects is the subjects of a delegation chain, in order. The
// conformance suite's own Expect.Chain is a shared vector format — []string,
// subjects only — predating ChainEntry's kind; comparing against it is a
// projection, not a loss of what this package itself verifies, since Kind is
// already asserted separately below.
func chainSubjects(chain []toolplane.ChainEntry) []string {
	out := make([]string, len(chain))
	for i, e := range chain {
		out[i] = e.Subject
	}
	return out
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
	// Unconditional, like subject and actor. A case that names no execution
	// is asserting the token carried NO exec claim, which is what pins
	// "exec on the governed-door rows and nowhere else" — an optional check
	// here would let a runner-obtained token pass an exchange-1 case
	// silently.
	if p.Execution != e.Execution {
		bad = append(bad, fmt.Sprintf("execution: got %q want %q", p.Execution, e.Execution))
	}
	// Unconditional, and LoadSuite requires both, for the reason given on
	// Expect: the tenant confines, and the chain is the record of who acted
	// for whom. The chain is compared IN ORDER — not through diffSets — since
	// a reversed chain names a different delegation.
	if p.Tenant != e.Tenant {
		bad = append(bad, fmt.Sprintf("tenant: got %q want %q", p.Tenant, e.Tenant))
	}
	if !slices.Equal(chainSubjects(p.Chain), e.Chain) {
		bad = append(bad, fmt.Sprintf("chain: got %v want %v", p.Chain, e.Chain))
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

// memSpent is a per-run replay cache. It is the harness's own, not the
// daemon's: a conformance run checks that a grant VERIFIES, and single-use
// is garmd's own test's subject (internal/grants), not a property a minter
// can be conformant or non-conformant about.
type memSpent struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (c *memSpent) Spend(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[id] {
		return replay.ErrAlreadySpent
	}
	c.seen[id] = true
	return nil
}

// Retention reports a window longer than any grant a suite can declare, so
// CheckRetention never refuses this cache. It holds entries for the life of
// the process, which for one conformance run is the whole window.
func (c *memSpent) Retention() time.Duration { return 24 * time.Hour }

var _ replay.Cache = (*memSpent)(nil)

// runGrantCase obtains an approval grant from the minter and checks that
// THIS daemon's own verifier accepts it — the same code path a real call
// would take at step 5, with one exception: the tool declares no material
// fields, because re-extraction needs a real request message and a suite
// file carries none. The digest is asserted directly instead, which is the
// half that belongs to the issuer. Re-extraction from a real request is
// internal/grants's own test's subject.
func runGrantCase(ctx context.Context, c Case, m Minter, s *Suite, jwksURL string) error {
	gm, ok := m.(GrantMinter)
	if !ok {
		return fmt.Errorf("this case asks for an approval grant and the configured " +
			"minter shape cannot issue one; a grant case against a token-only minter " +
			"must fail rather than be skipped")
	}
	g := *c.Grant

	raw, err := gm.Approve(ctx, g.Request())
	if err != nil {
		return fmt.Errorf("minting the grant: %w", err)
	}

	// LoadSuite has already refused an unknown or UNSPECIFIED spelling, so
	// this cannot fail for a suite that was loaded. It is checked anyway
	// rather than discarded: a caller building a Suite in memory bypasses
	// the loader, and the failure mode is the silent one — UNSPECIFIED makes
	// grants.Verifier skip the approver-seniority check altogether.
	minClearance, err := ClearanceValue(g.ToolApproverMinClearance)
	if err != nil {
		return fmt.Errorf("toolApproverMinClearance: %w", err)
	}
	def := toolplane.ToolDef{
		FQN:                  g.Tool,
		ApprovalMode:         toolv1.Approval_MODE_GRANT,
		ApproverMinClearance: minClearance,
		ApproverCompartments: g.ToolApproverCompartments,
		MaxGrantAge:          time.Duration(g.ToolMaxGrantAgeSeconds) * time.Second,
	}
	v := &grants.Verifier{
		Keys:     authn.NewKeySet(authn.KeySetConfig{URL: jwksURL}),
		Issuers:  []string{s.Issuer},
		Audience: s.Audience,
		Spent:    &memSpent{},
	}
	p := &toolplane.Principal{Subject: g.Subject}
	if err := v.Verify(grants.WithGrant(ctx, raw), p, def, nil); err != nil {
		return fmt.Errorf("this daemon's own grant verifier refused the grant: %w", err)
	}

	// Signature, issuer, audience, jti, tool, subject, expiry, age and the
	// approver's authority are all checked above. What remains is what only
	// this harness can see: that the digest is over the values the ISSUER
	// WAS GIVEN, and that the approver recorded is the one derived from the
	// verified token rather than a field the caller supplied.
	claims, err := grantBody(raw)
	if err != nil {
		return err
	}
	if want := grant.Digest(g.Material); claims.Material != want {
		return fmt.Errorf("garm_grant.material = %q, want %q — the digest must be over the "+
			"values presented and nothing else, or a grant authorises a call the approver never saw",
			claims.Material, want)
	}
	if claims.Approver != g.ExpectApprover {
		return fmt.Errorf("garm_grant.approver = %q, want %q", claims.Approver, g.ExpectApprover)
	}
	return nil
}

// runGrantErrorCase asks the approval endpoint for a grant the suite says
// it must refuse, and is satisfied by exactly one answer: the STS's own
// opaque `400 {"error":"access_denied"}`.
//
// Exactly one, and not "any non-200", for two reasons that pull the same
// way. A refusal case pointed at a service that is crashing (500), or at
// the wrong route (404, 405), would otherwise report ok while checking
// nothing — the mintError lesson again. And the STS's contract is that
// EVERY refusal is that one opaque body, with the reason on the log and
// never in the response, so that the endpoint is not an enumeration oracle
// for which tools exist and who may approve them; a body that names the
// reason is a drift this case is well placed to catch.
func runGrantErrorCase(ctx context.Context, c Case, m Minter) error {
	gm, ok := m.(GrantMinter)
	if !ok {
		return fmt.Errorf("this case asks the approval endpoint to refuse and the configured " +
			"minter shape cannot reach one; a grantError case against a token-only minter " +
			"must fail rather than be skipped")
	}
	_, err := gm.Approve(ctx, c.GrantError.Request())
	if err == nil {
		return fmt.Errorf("the approval endpoint minted a grant, but the suite says it must refuse")
	}
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		return fmt.Errorf("the suite says the approval endpoint must refuse this, but it "+
			"could not be reached at all — that asserts nothing: %w", err)
	}
	if refusal.Status != http.StatusBadRequest {
		return fmt.Errorf("the approval endpoint answered %d, but every refusal it owes a "+
			"caller is the one opaque 400; this is not the refusal the case asserts (body: %s)",
			refusal.Status, refusal.Body)
	}
	if !isOpaqueDenial(refusal.Body) {
		return fmt.Errorf("the approval endpoint answered 400 with %q, but a refusal is exactly "+
			"{\"error\":\"access_denied\"} — a body saying more is an enumeration oracle, and one "+
			"saying something else is not this endpoint's refusal", refusal.Body)
	}
	return nil
}

// isOpaqueDenial reports whether body is the STS's one refusal shape and
// nothing more: a JSON object whose only member is error=access_denied.
// Decoded rather than compared as a string so whitespace cannot fail it,
// and required to be the ONLY member so a body that also names the reason
// cannot pass it.
func isOpaqueDenial(body string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	return len(m) == 1 && m["error"] == "access_denied"
}

// grantClaimBody is the half of garm_grant this harness reads directly. The
// verifier has already checked the signature by the time this runs, so the
// unverified payload is safe to decode here.
type grantClaimBody struct {
	Material string `json:"material"`
	Approver string `json:"approver"`
}

func grantBody(raw string) (*grantClaimBody, error) {
	sig, err := jose.ParseSigned(raw, authn.PermittedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("the grant is not a well-formed token: %w", err)
	}
	var body struct {
		Grant grantClaimBody `json:"garm_grant"`
	}
	// Unverified is correct here and only here: Verify above already
	// checked this exact token's signature against the served JWKS.
	if err := json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &body); err != nil {
		return nil, fmt.Errorf("the grant's body is not JSON: %w", err)
	}
	return &body.Grant, nil
}
