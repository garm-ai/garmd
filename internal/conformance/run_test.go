package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/garm-ai/contracts/grant"
	"github.com/garm-ai/garmd/internal/conformance"
	jose "github.com/go-jose/go-jose/v4"
)

// fakeMinter is an in-process stand-in. It cannot be devkit: garmd may not
// import a minter, which is the constraint this whole package works around.
type fakeMinter struct {
	key    *ecdsa.PrivateKey
	bodies map[string]map[string]any // mint["user"] -> token body
	refuse map[string]bool
}

func (f *fakeMinter) Token(_ context.Context, params map[string]string) (string, error) {
	k := params["user"]
	if f.refuse[k] {
		// A refusal is a *RefusalError, as the Minter contract requires:
		// the minter answered and said no. HTTPMinter does the same for a
		// non-200, and everything else stays an ordinary error.
		return "", &conformance.RefusalError{
			Status: http.StatusForbidden,
			Body:   fmt.Sprintf("minter refused %q", k),
		}
	}
	body, ok := f.bodies[k]
	if !ok {
		return "", fmt.Errorf("no persona %q", k)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(body)
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// jwksFor serves the public half of key.
func jwksFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: key.Public(), KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func body(now time.Time, sub, clearance string, comps, verbs []any, act map[string]any) map[string]any {
	b := map[string]any{
		"iss": "https://minter.test", "sub": sub, "aud": []any{"garm"},
		"jti": "t-" + sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"tenant": "bank",
		"garm": map[string]any{
			"clearance": clearance, "compartments": comps,
			"verbs": verbs, "kind": "USER",
		},
	}
	if act != nil {
		b["act"] = act
	}
	return b
}

func TestRunPassesWhenTheFoldMatches(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_RESTRICTED",
			[]any{"financial", "pii-contact"}, []any{"READ", "WRITE"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial", "pii-contact", "support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Kind: "PRINCIPAL_KIND_USER",
				Clearance:    "CLEARANCE_RESTRICTED",
				Compartments: []string{"pii-contact", "financial"}, // order must not matter
				Verbs:        []string{"VERB_READ", "VERB_WRITE"},
				Tenant:       "bank", Chain: []string{"user:alice"},
			},
		}},
	}

	res, err := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("expected a pass, got %+v", res)
	}
}

func TestRunReportsAMismatchedFold(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_INTERNAL",
			[]any{"support"}, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial", "pii-contact", "support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_RESTRICTED",
				Compartments: []string{"support"}, Verbs: []string{"VERB_READ"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a minter emitting INTERNAL passed a case expecting RESTRICTED")
	}
	if !strings.Contains(res[0].Err.Error(), "clearance") {
		t.Fatalf("the error must name the field that disagreed: %v", res[0].Err)
	}
}

// Review Focus 3. An unreachable minter must FAIL the case, never skip it.
func TestRunFailsWhenTheMinterIsUnreachable(t *testing.T) {
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{}} // knows nobody
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{Clearance: "CLEARANCE_PUBLIC"},
		}},
	}

	res, err := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if err != nil {
		t.Fatalf("an unreachable minter is a case failure, not a run failure: %v", err)
	}
	if len(res) != 1 || res[0].Err == nil {
		t.Fatal("an unreachable minter produced no failure; the run would report ok")
	}
}

func TestRunHonoursMintError(t *testing.T) {
	key := newECKey(t)
	m := &fakeMinter{key: key, refuse: map[string]bool{"alice": true}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a refusal the suite expected was reported as a failure: %v", res[0].Err)
	}
}

func TestRunFailsWhenAnExpectedRefusalSucceeds(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_PUBLIC", nil, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "should be refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("the minter granted a delegation the suite says it must refuse")
	}
}

// Review Focus 4. The drop list is part of the contract.
func TestRunAssertsDroppedCompartments(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_INTERNAL",
			[]any{"support", "finance"}, []any{"READ"}, nil), // `finance` is a typo
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "typo is dropped", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_INTERNAL",
				Compartments: []string{"support"}, Verbs: []string{"VERB_READ"},
				Dropped: []string{"finance"},
				Tenant:  "bank", Chain: []string{"user:alice"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a correctly-dropped compartment was reported as a failure: %v", res[0].Err)
	}
}

// Fix round 1, Finding 1. ToolSets has three states — absent/null (unscoped),
// `[]` (scoped to nothing) and a populated list — and nil vs. non-nil-empty
// is load-bearing per toolplane.Principal's own doc comment. These three
// tests exercise all three, including the one the pre-fix diffSets could not
// catch: a suite that demands "scoped to nothing" must fail against a
// principal that came back unscoped, even though both look empty once
// sorted.

func TestRunAssertsUnscopedToolSets(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		// No `tool_sets` claim at all: the fold must leave ToolSets nil.
		"alice": body(now, "user:alice", "CLEARANCE_PUBLIC", nil, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "unscoped", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_PUBLIC",
				Verbs:  []string{"VERB_READ"},
				Tenant: "bank", Chain: []string{"user:alice"},
				// ToolSets left nil: absent/null means "assert unscoped".
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("an unscoped principal failed an unscoped expectation: %v", res[0].Err)
	}
}

func TestRunAssertsToolSetsScopedToNothing(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	// Two hops whose tool_sets share nothing: Fold's intersectSets produces a
	// non-nil, empty slice for this, which is the "scoped to nothing" state.
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": {
			"iss": "https://minter.test", "sub": "user:alice", "aud": []any{"garm"},
			"jti": "t-alice", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"tenant": "bank",
			"garm": map[string]any{
				"clearance": "CLEARANCE_RESTRICTED", "compartments": []any{"support"},
				"verbs": []any{"READ"}, "kind": "USER", "tool_sets": []any{"alpha"},
			},
			"act": map[string]any{
				"sub": "agent:bot",
				"garm": map[string]any{
					"clearance": "CLEARANCE_RESTRICTED", "compartments": []any{"support"},
					"verbs": []any{"READ"}, "kind": "AGENT", "tool_sets": []any{"beta"},
				},
			},
		},
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "disjoint scopes fold to nothing", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Actor: "agent:bot",
				Clearance:    "CLEARANCE_RESTRICTED",
				Compartments: []string{"support"}, Verbs: []string{"VERB_READ"},
				ToolSets: &[]string{}, // non-nil, empty: "scoped to nothing"
				Tenant:   "bank", Chain: []string{"user:alice", "agent:bot"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a principal correctly scoped to nothing failed that expectation: %v", res[0].Err)
	}
}

// This is the case the pre-fix diffSets could not express: an unscoped
// principal (nil) is NOT the same thing as one scoped to nothing (non-nil,
// empty), and a suite that expects the latter must catch the former.
func TestRunCatchesUnscopedWhenScopedToNothingWasExpected(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		// No tool_sets claim: the fold leaves ToolSets nil (unscoped).
		"alice": body(now, "user:alice", "CLEARANCE_PUBLIC", nil, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "unscoped is not scoped-to-nothing", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_PUBLIC",
				Verbs:    []string{"VERB_READ"},
				ToolSets: &[]string{}, // demands "scoped to nothing"
				Tenant:   "bank", Chain: []string{"user:alice"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("an unscoped principal passed a case that demanded scoped-to-nothing")
	}
	if !strings.Contains(res[0].Err.Error(), "toolSets") {
		t.Fatalf("the error must name toolSets as the field that disagreed: %v", res[0].Err)
	}
}

// Fix round 1, Finding 2. The `verifying:` error path had no coverage: every
// prior test fed the verifier a token that verified fine and only disagreed
// in the fold. A token signed by a key the JWKS does not serve must fail
// verification itself, distinctly attributed from a mint error.
func TestRunAttributesAVerificationFailureDistinctlyFromAMintError(t *testing.T) {
	now := time.Now()
	servedKey := newECKey(t)  // what the JWKS endpoint serves
	signingKey := newECKey(t) // what actually signs the token — a different key
	m := &fakeMinter{key: signingKey, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_PUBLIC", nil, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "wrong signing key", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{Subject: "user:alice", Clearance: "CLEARANCE_PUBLIC"},
		}},
	}

	res, err := conformance.Run(context.Background(), s, m, jwksFor(t, servedKey))
	if err != nil {
		t.Fatalf("a verification failure is a case failure, not a run failure: %v", err)
	}
	if res[0].Err == nil {
		t.Fatal("a token signed by a key absent from the JWKS was verified anyway")
	}
	if !strings.Contains(res[0].Err.Error(), "verifying:") {
		t.Fatalf("the error must be attributed to verification, not minting: %v", res[0].Err)
	}
	if strings.Contains(res[0].Err.Error(), "minting:") {
		t.Fatalf("a verification failure must not be mislabelled as a mint error: %v", res[0].Err)
	}
}

// unreachableMinter is a minter that never answers, spelled the way
// HTTPMinter spells a transport failure: an ordinary wrapped error, NOT a
// *RefusalError.
type unreachableMinter struct{}

func (unreachableMinter) Token(context.Context, map[string]string) (string, error) {
	return "", fmt.Errorf("minter unreachable: %w",
		fmt.Errorf("dial tcp 127.0.0.1:7450: connect: connection refused"))
}

// Fix round 2, Finding 1. This is the test the finding is about.
//
// Before the fix, `mintError` accepted ANY non-nil error, so a suite of
// nothing but refusal cases pointed at a dead port reported ok — and a
// typo'd persona name passed too, because the minter answered 404 and the
// case only ever asked for "an error". The suite would then read as
// asserting "delegation is refused" while actually asserting "this persona
// does not exist".
func TestRunFailsAMintErrorCaseWhenTheMinterIsUnreachable(t *testing.T) {
	key := newECKey(t)
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}

	res, err := conformance.Run(context.Background(), s, unreachableMinter{}, jwksFor(t, key))
	if err != nil {
		t.Fatalf("an unreachable minter is a case failure, not a run failure: %v", err)
	}
	if res[0].Err == nil {
		t.Fatal("a suite of mintError cases pointed at a dead minter reported ok; " +
			"'could not be reached' is not 'refused'")
	}
	if !strings.Contains(res[0].Err.Error(), "could not be reached") {
		t.Fatalf("the failure must say the minter was unreachable, not imply a refusal: %v",
			res[0].Err)
	}
}

// The mirror: a real refusal, spelled the way HTTPMinter spells one, still
// satisfies a mintError case. Without this the fix above could be "reject
// everything" and still look green.
func TestRunAcceptsAMintErrorCaseOnlyForARefusal(t *testing.T) {
	key := newECKey(t)
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}
	m := &fakeMinter{key: key, refuse: map[string]bool{"alice": true}}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a refusal the suite expected was reported as a failure: %v", res[0].Err)
	}
}

// Fix round 2, minor 10. HTTPMinter is the only production Minter and
// Finding 1 changed its error contract, so the contract is pinned here:
// a 200 is the trimmed token, a non-200 is a *RefusalError carrying the
// status, and a dead port is NOT a refusal.

func TestHTTPMinterReturnsTheTrimmedTokenOn200(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		// Trailing newline on purpose: a minter that echoes a token with
		// `echo` produces one, and it must not reach the verifier.
		fmt.Fprintln(w, "header.payload.signature")
	}))
	t.Cleanup(srv.Close)

	tok, err := conformance.HTTPMinter{BaseURL: srv.URL + "/"}.Token(
		context.Background(), map[string]string{"user": "alice", "as": "triage-bot"})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "header.payload.signature" {
		t.Fatalf("token not trimmed: %q", tok)
	}
	if gotQuery.Get("user") != "alice" || gotQuery.Get("as") != "triage-bot" {
		t.Fatalf("mint params were not passed through verbatim: %v", gotQuery)
	}
}

func TestHTTPMinterReturnsARefusalErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "may_act_for names only bob", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	_, err := conformance.HTTPMinter{BaseURL: srv.URL}.Token(
		context.Background(), map[string]string{"user": "alice", "as": "triage-bot"})
	if err == nil {
		t.Fatal("a 403 produced no error")
	}
	var refusal *conformance.RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("a non-200 must be a *RefusalError, got %T: %v", err, err)
	}
	if refusal.Status != http.StatusForbidden {
		t.Fatalf("refusal must carry the status, got %d", refusal.Status)
	}
	if !strings.Contains(refusal.Body, "may_act_for names only bob") {
		t.Fatalf("refusal must carry the minter's reason, got %q", refusal.Body)
	}
}

func TestHTTPMinterDoesNotReportAConnectionFailureAsARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing is listening on that port any more

	_, err := conformance.HTTPMinter{BaseURL: base}.Token(
		context.Background(), map[string]string{"user": "alice"})
	if err == nil {
		t.Fatal("a dead port produced no error")
	}
	var refusal *conformance.RefusalError
	if errors.As(err, &refusal) {
		t.Fatalf("a minter that could not be reached was reported as a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("the error must say the minter was unreachable, got: %v", err)
	}
}

// exec is provenance, and the one claim exchange 2 adds that exchange 1 must
// never carry. compare asserts it UNCONDITIONALLY: a case naming no execution
// is asserting the token had no exec claim at all, so a runner-obtained token
// cannot pass an exchange-1 case silently.
func TestRunAssertsTheExecutionClaim(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	withExec := body(now, "employee:jdoe", "CLEARANCE_INTERNAL", nil, []any{"READ"}, nil)
	withExec["exec"] = map[string]any{"sub": "runner:conformance-client", "iss": "https://minter.test"}
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"jdoe": withExec,
	}}
	base := func(e *conformance.Expect) *conformance.Suite {
		return &conformance.Suite{
			Issuer: "https://minter.test", Audience: "garm",
			Compartments: []string{"support"},
			Cases: []conformance.Case{{
				Name: "jdoe via a runner", Mint: map[string]string{"user": "jdoe"}, Expect: e,
			}},
		}
	}

	res, err := conformance.Run(context.Background(), base(&conformance.Expect{
		Subject: "employee:jdoe", Clearance: "CLEARANCE_INTERNAL",
		Verbs: []string{"VERB_READ"}, Execution: "runner:conformance-client",
		Tenant: "bank", Chain: []string{"employee:jdoe"},
	}), m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil {
		t.Fatalf("a case naming the right execution failed: %v", res[0].Err)
	}

	res, _ = conformance.Run(context.Background(), base(&conformance.Expect{
		Subject: "employee:jdoe", Clearance: "CLEARANCE_INTERNAL",
		Verbs:  []string{"VERB_READ"},
		Tenant: "bank", Chain: []string{"employee:jdoe"},
	}), m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a token carrying exec passed a case that names no execution; " +
			"exec would then go unchecked on every exchange-1 case")
	}
	if !strings.Contains(res[0].Err.Error(), "execution") {
		t.Fatalf("the error must name execution as what disagreed: %v", res[0].Err)
	}
}

// fakeGrantMinter is a minter that also issues approvals. In process, because
// garmd may not import the service that mints them.
type fakeGrantMinter struct {
	fakeMinter
	// approver and material override what the grant records, so a test can
	// mint a grant that disagrees with what was asked for.
	approver string
	material map[string]string
	// refuseWith, when set, is the approval endpoint's answer: it was
	// reached and said no, spelled however the test wants — the STS's
	// opaque denial, or something a grantError case must NOT accept.
	refuseWith *conformance.RefusalError
	// unreachable is a dead port: an ordinary error, never a refusal.
	unreachable bool
	// last is the request the endpoint was handed, verbatim.
	last conformance.ApprovalRequest
}

func (f *fakeGrantMinter) Approve(_ context.Context, g conformance.ApprovalRequest) (string, error) {
	f.last = g
	if f.unreachable {
		return "", fmt.Errorf("approval endpoint unreachable: %w",
			fmt.Errorf("dial tcp 127.0.0.1:8081: connect: connection refused"))
	}
	if f.refuseWith != nil {
		return "", f.refuseWith
	}
	approver := f.approver
	if approver == "" {
		approver = "employee:" + g.Approver
	}
	material := g.Material
	if f.material != nil {
		material = f.material
	}
	now := time.Now()
	claims := map[string]any{
		"iss": "https://minter.test", "aud": "garm",
		"jti": fmt.Sprintf("g-%d", now.UnixNano()),
		"iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
		"garm_grant": map[string]any{
			"tool": g.Tool, "subject": g.Subject,
			"material":              grant.Digest(material),
			"approver":              approver,
			"approver_clearance":    g.ApproverClearance,
			"approver_compartments": g.ApproverCompartments,
		},
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func grantSuite() *conformance.Suite {
	return &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial"},
		Cases: []conformance.Case{{
			Name: "an approval this daemon accepts",
			Grant: &conformance.Grant{
				Approver: "jdoe", ApproverClearance: "RESTRICTED",
				ApproverCompartments:     []string{"financial"},
				Tool:                     "payments.v1.initiate_payment",
				Subject:                  "employee:jdoe",
				Material:                 map[string]string{"amount_minor_units": "25000"},
				ToolApproverMinClearance: "RESTRICTED",
				ToolApproverCompartments: []string{"financial"},
				ToolMaxGrantAgeSeconds:   900,
				ExpectApprover:           "employee:jdoe",
			},
		}},
	}
}

func TestRunGrantCasePassesWhenThisDaemonsVerifierAccepts(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}}
	res, err := conformance.Run(context.Background(), grantSuite(), m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil {
		t.Fatalf("a grant this daemon's own verifier accepts was reported as a failure: %v", res[0].Err)
	}
}

// The half only this harness can see: the digest must be over the values the
// issuer was GIVEN. An issuer digesting something else authorises a call the
// approver never saw, and every check inside grants.Verifier passes anyway —
// there is no request message here to re-extract from.
func TestRunGrantCaseFailsOnADigestOverOtherValues(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{
		fakeMinter: fakeMinter{key: key},
		material:   map[string]string{"amount_minor_units": "1"},
	}
	res, _ := conformance.Run(context.Background(), grantSuite(), m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a grant digesting values nobody presented passed")
	}
	if !strings.Contains(res[0].Err.Error(), "material") {
		t.Fatalf("the error must name the material digest: %v", res[0].Err)
	}
}

// The approver is the one value the issuer DERIVES rather than copies — from
// the verified token's sub and the issuer's configured kind — so it is worth
// asserting separately from what the verifier already checks.
func TestRunGrantCaseFailsOnAnApproverItDidNotDerive(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, approver: "employee:somebody-else"}
	res, _ := conformance.Run(context.Background(), grantSuite(), m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a grant recording an approver the issuer never verified passed")
	}
	if !strings.Contains(res[0].Err.Error(), "approver") {
		t.Fatalf("the error must name the approver: %v", res[0].Err)
	}
}

// A grant case against a minter that cannot issue one must FAIL, never skip:
// a skipped case is a suite reporting ok about something it did not check.
func TestRunGrantCaseFailsAgainstATokenOnlyMinter(t *testing.T) {
	key := newECKey(t)
	res, _ := conformance.Run(context.Background(), grantSuite(), &fakeMinter{key: key}, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a grant case against a token-only minter was reported as a pass")
	}
}

// An approval endpoint that refuses fails the case too. A grant case asserts
// that an approval CAN be obtained and verified, so there is no refusal it is
// satisfied by.
func TestRunGrantCaseFailsWhenTheApprovalEndpointRefuses(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, refuseWith: opaqueDenial()}
	res, _ := conformance.Run(context.Background(), grantSuite(), m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a refused approval was reported as a pass")
	}
}

// F12b. Tenant and chain are part of the fold and compare asserts both
// UNCONDITIONALLY, like subject and execution: the tenant is what confines
// a caller to their own organisation's data, and the chain is every hop the
// fold walked, in order — Chain[0] is the subject, the last hop the actor.
func TestRunAssertsTenantAndChain(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	delegated := body(now, "employee:jdoe", "CLEARANCE_INTERNAL", []any{"support"}, []any{"READ"},
		map[string]any{"sub": "agent:order-assistant", "garm": map[string]any{
			"clearance": "CLEARANCE_INTERNAL", "compartments": []any{"support"},
			"verbs": []any{"READ"}, "kind": "AGENT"}})
	delegated["tenant"] = "acme"
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{"jdoe": delegated}}
	suite := func(e *conformance.Expect) *conformance.Suite {
		return &conformance.Suite{
			Issuer: "https://minter.test", Audience: "garm",
			Compartments: []string{"support"},
			Cases: []conformance.Case{{
				Name: "jdoe via order-assistant", Mint: map[string]string{"user": "jdoe"}, Expect: e,
			}},
		}
	}
	right := func() *conformance.Expect {
		return &conformance.Expect{
			Subject: "employee:jdoe", Actor: "agent:order-assistant",
			Clearance: "CLEARANCE_INTERNAL", Compartments: []string{"support"},
			Verbs:  []string{"VERB_READ"},
			Tenant: "acme", Chain: []string{"employee:jdoe", "agent:order-assistant"},
		}
	}

	res, err := conformance.Run(context.Background(), suite(right()), m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil {
		t.Fatalf("a case naming the right tenant and chain failed: %v", res[0].Err)
	}

	for name, tc := range map[string]struct {
		mutate func(*conformance.Expect)
		names  string
	}{
		"wrong tenant":       {func(e *conformance.Expect) { e.Tenant = "globex" }, "tenant"},
		"no tenant":          {func(e *conformance.Expect) { e.Tenant = "" }, "tenant"},
		"a hop missing":      {func(e *conformance.Expect) { e.Chain = []string{"employee:jdoe"} }, "chain"},
		"hops out of order":  {func(e *conformance.Expect) { e.Chain = []string{"agent:order-assistant", "employee:jdoe"} }, "chain"},
		"a hop never walked": {func(e *conformance.Expect) { e.Chain = append(e.Chain, "service:bff") }, "chain"},
	} {
		t.Run(name, func(t *testing.T) {
			e := right()
			tc.mutate(e)
			res, _ := conformance.Run(context.Background(), suite(e), m, jwksFor(t, key))
			if res[0].Err == nil {
				t.Fatalf("a case with %s passed", name)
			}
			if !strings.Contains(res[0].Err.Error(), tc.names) {
				t.Fatalf("the error must name %s as what disagreed: %v", tc.names, res[0].Err)
			}
		})
	}
}

// F12a. A grantError case asserts the approval endpoint REFUSED — and
// refused the way the STS's contract says every refusal looks: the one
// opaque `400 {"error":"access_denied"}`. Anything else is not a refusal
// this case is satisfied by: a 500 is a crashed service, a 405 is the wrong
// method, a body naming the reason is an enumeration oracle, and none of
// those is the property the case pins.

func grantErrorSuite() *conformance.Suite {
	return &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial"},
		Cases: []conformance.Case{{
			Name: "an approval the STS must refuse",
			GrantError: &conformance.GrantError{
				Approver: "jdoe", ApproverClearance: "RESTRICTED",
				ApproverCompartments: []string{"financial"},
				ApproverActor:        "agent:order-assistant",
				Tool:                 "payments.v1.initiate_payment",
				Subject:              "employee:jdoe",
				Material:             map[string]string{"amount_minor_units": "25000"},
			},
		}},
	}
}

func opaqueDenial() *conformance.RefusalError {
	return &conformance.RefusalError{Status: http.StatusBadRequest, Body: `{"error":"access_denied"}`}
}

func TestRunGrantErrorCasePassesOnTheOpaqueRefusal(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, refuseWith: opaqueDenial()}
	res, err := conformance.Run(context.Background(), grantErrorSuite(), m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil {
		t.Fatalf("a refusal the suite expected was reported as a failure: %v", res[0].Err)
	}
}

func TestRunGrantErrorCaseFailsWhenTheApprovalEndpointMints(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}} // mints happily
	res, _ := conformance.Run(context.Background(), grantErrorSuite(), m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("the approval endpoint minted a grant the suite says it must refuse, and the case passed")
	}
	if !strings.Contains(res[0].Err.Error(), "must refuse") {
		t.Fatalf("the error must say the suite expected a refusal: %v", res[0].Err)
	}
}

func TestRunGrantErrorCaseFailsOnAnyAnswerButTheOpaqueDenial(t *testing.T) {
	key := newECKey(t)
	for name, refusal := range map[string]*conformance.RefusalError{
		"a 500":                     {Status: http.StatusInternalServerError, Body: "boom"},
		"a 403 with the right body": {Status: http.StatusForbidden, Body: `{"error":"access_denied"}`},
		"a 400 naming the reason":   {Status: http.StatusBadRequest, Body: `{"error":"approver is not an employee"}`},
		"a 400 with a bare body":    {Status: http.StatusBadRequest, Body: "access_denied"},
		"a 405":                     {Status: http.StatusMethodNotAllowed, Body: "method not allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, refuseWith: refusal}
			res, _ := conformance.Run(context.Background(), grantErrorSuite(), m, jwksFor(t, key))
			if res[0].Err == nil {
				t.Fatalf("%s satisfied a grantError case; only the opaque 400 access_denied may", name)
			}
		})
	}
}

// The same rule mintError has: "could not be reached" is not "refused".
func TestRunGrantErrorCaseFailsWhenTheApprovalEndpointIsUnreachable(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, unreachable: true}
	res, err := conformance.Run(context.Background(), grantErrorSuite(), m, jwksFor(t, key))
	if err != nil {
		t.Fatalf("an unreachable endpoint is a case failure, not a run failure: %v", err)
	}
	if res[0].Err == nil {
		t.Fatal("a grantError case against a dead approval endpoint reported ok")
	}
	if !strings.Contains(res[0].Err.Error(), "could not be reached") {
		t.Fatalf("the failure must say the endpoint was unreachable, not imply a refusal: %v", res[0].Err)
	}
}

func TestRunGrantErrorCaseFailsAgainstATokenOnlyMinter(t *testing.T) {
	key := newECKey(t)
	res, _ := conformance.Run(context.Background(), grantErrorSuite(), &fakeMinter{key: key}, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a grantError case against a token-only minter was reported as a pass")
	}
}

// What the case declares must reach the minter verbatim: the delegated
// approver, the omitted assertion and the malformed path are each the
// whole point of their case, and a harness that quietly repaired any of
// them would send a request the STS accepts.
func TestRunGrantErrorCaseHandsTheMinterTheRequestAsDeclared(t *testing.T) {
	key := newECKey(t)
	m := &fakeGrantMinter{fakeMinter: fakeMinter{key: key}, refuseWith: opaqueDenial()}
	s := grantErrorSuite()
	s.Cases[0].GrantError.OmitClientAssertion = true
	s.Cases[0].GrantError.Material = map[string]string{"amount=minor": "1"}
	if _, err := conformance.Run(context.Background(), s, m, jwksFor(t, key)); err != nil {
		t.Fatal(err)
	}
	got := m.last
	if got.ApproverActor != "agent:order-assistant" {
		t.Errorf("approverActor = %q, want agent:order-assistant", got.ApproverActor)
	}
	if !got.OmitClientAssertion {
		t.Error("omitClientAssertion did not reach the minter")
	}
	if got.Material["amount=minor"] != "1" {
		t.Errorf("material = %v; the malformed path must be sent as declared", got.Material)
	}
	if got.Approver != "jdoe" || got.ApproverClearance != "RESTRICTED" || got.Tool != "payments.v1.initiate_payment" {
		t.Errorf("request = %+v", got)
	}
}
