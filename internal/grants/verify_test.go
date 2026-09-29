package grants_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/grant"
	contractgrants "github.com/garm-ai/contracts/grants"
	"github.com/garm-ai/contracts/policy/testdata"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/replay"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// Step 5, and almost everything here is a refusal.
//
// A grant is the only credential in the system that authorises an irreversible
// act, so the interesting tests are the ones where a token is valid, signed by
// the right issuer, and still must not be spent: for the wrong tool, by the
// wrong caller, too old, already used, or approved by somebody who was
// delegating rather than deciding.

const (
	issuer   = "https://sts.test"
	audience = "garm://garmd"
	approver = "employee:jdoe"
)

var now = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

type fixture struct {
	v   *grants.Verifier
	key *ecdsa.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: "g1", Algorithm: string(jose.ES256), Use: "sig",
	}}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)

	return &fixture{
		v: &grants.Verifier{
			Keys:     authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
			Issuers:  []string{issuer},
			Audience: audience,
			Spent:    spentCache(t),
			Skew:     30 * time.Second,
			Now:      func() time.Time { return now },
		},
		key: key,
	}
}

func spentCache(t *testing.T) replay.Cache {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats did not start")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	c, err := replay.NewJetStream(context.Background(), nc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The tool under approval: a destructive one binding two material fields.
func payTool() toolplane.ToolDef {
	pd := (*testdata.Profile)(nil).ProtoReflect().Descriptor()
	return toolplane.ToolDef{
		FullMethod:           "/t.v1.S/Pay",
		FQN:                  "t.v1.pay",
		Name:                 "pay",
		Verb:                 toolv1.Verb_VERB_DESTRUCTIVE,
		MinClearance:         toolv1.Clearance_CLEARANCE_RESTRICTED,
		ApprovalMode:         toolv1.Approval_MODE_GRANT,
		ApproverMinClearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		MaxGrantAge:          15 * time.Minute,
		MaterialFields:       []string{"id", "email"},
		Input:                pd,
		Output:               pd,
	}
}

func caller() *toolplane.Principal {
	return &toolplane.Principal{Subject: "customer:C-1"}
}

// theRequest is what is actually being sent.
func theRequest() *testdata.Profile {
	e := "ada@example.com"
	return &testdata.Profile{Id: "p1", Email: &e}
}

// claims builds a grant body, which tests then bend one field at a time.
func (f *fixture) claims(mut func(body, g map[string]any)) string {
	values := map[string]string{"id": "p1", "email": "ada@example.com"}
	g := map[string]any{
		"tool":                  "t.v1.pay",
		"subject":               "customer:C-1",
		"material":              grant.Digest(values),
		"approver":              approver,
		"approver_clearance":    "RESTRICTED",
		"approver_compartments": []any{},
	}
	body := map[string]any{
		"iss": issuer, "aud": audience, "jti": "g-" + time.Now().Format("150405.000000000"),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"garm_grant": g,
	}
	if mut != nil {
		mut(body, g)
	}
	return f.sign(body)
}

func (f *fixture) sign(body map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "g1"))
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(body)
	obj, err := signer.Sign(b)
	if err != nil {
		panic(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return s
}

func (f *fixture) verify(t *testing.T, token string) error {
	t.Helper()
	ctx := context.Background()
	if token != "" {
		ctx = grants.WithGrant(ctx, token)
	}
	return f.v.Verify(ctx, caller(), payTool(), theRequest())
}

func TestAValidGrantIsAccepted(t *testing.T) {
	f := newFixture(t)
	if err := f.verify(t, f.claims(nil)); err != nil {
		t.Fatalf("a valid grant was refused: %v", err)
	}
}

// The only refusal with a next move. A caller told "denied" has nowhere to go;
// one told "grant required" can obtain an approval and come back.
func TestNoGrantIsDistinctFromABadOne(t *testing.T) {
	f := newFixture(t)
	if err := f.verify(t, ""); err == nil {
		t.Fatal("a grant-gated tool ran with no grant")
	} else if !strings.Contains(err.Error(), "required") {
		t.Errorf("a missing grant did not say so: %v", err)
	}

	bad := f.claims(func(_, g map[string]any) { g["tool"] = "t.v1.something_else" })
	err := f.verify(t, bad)
	if err == nil {
		t.Fatal("a grant for another tool was accepted")
	}
	if strings.Contains(err.Error(), "required") {
		t.Error("a wrong grant reported as a missing one; a caller would fetch " +
			"another and fail the same way forever")
	}
}

// The structural rule: a delegated identity cannot approve.
//
// Without it, an agent holding a delegation token could approve the
// destructive action it is itself about to take. This is not a policy anybody
// configures — it is a shape the token may not have.
func TestADelegatedIdentityCannotApprove(t *testing.T) {
	f := newFixture(t)
	tok := f.claims(func(body, _ map[string]any) {
		body["act"] = map[string]any{"sub": "agent:order-assistant"}
	})
	err := f.verify(t, tok)
	if err == nil {
		t.Fatal("a grant carrying a delegation chain was accepted; an agent can " +
			"approve its own irreversible call")
	}
	if !strings.Contains(err.Error(), "delegation") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A delegation token is not a grant. Without the garm_grant claim there is no
// tool, no subject and no material digest — so accepting one would make every
// ordinary token an approval for everything.
func TestADelegationTokenIsNotSpendableAsAGrant(t *testing.T) {
	f := newFixture(t)
	tok := f.sign(map[string]any{
		"iss": issuer, "aud": audience, "jti": "d-1",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"garm": map[string]any{"clearance": "RESTRICTED"},
	})
	if err := f.verify(t, tok); err == nil {
		t.Fatal("a delegation token was spent as an approval")
	}
}

func TestEachBindingIsChecked(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(body, g map[string]any)
		want string
	}{
		{"another tool", func(_, g map[string]any) { g["tool"] = "t.v1.other" }, "approves"},
		{"another caller", func(_, g map[string]any) { g["subject"] = "customer:C-2" }, "not by this caller"},
		{"another deployment", func(b, _ map[string]any) { b["aud"] = "garm://elsewhere" }, "minted for"},
		{"an untrusted issuer", func(b, _ map[string]any) { b["iss"] = "https://evil" }, "not trusted"},
		{"no jti", func(b, _ map[string]any) { delete(b, "jti") }, "single-use"},
		{"an approver below the bar", func(_, g map[string]any) {
			g["approver_clearance"] = "INTERNAL"
		}, "requires at least"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			err := f.verify(t, f.claims(tc.mut))
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not mention %q: %v", tc.want, err)
			}
		})
	}
}

// The tool's max_grant_age is a CEILING the issuer cannot raise. An issuer
// minting a day-long approval for a tool that asked for fifteen minutes gets
// fifteen minutes.
func TestTheToolsMaximumAgeBeatsTheIssuersExpiry(t *testing.T) {
	f := newFixture(t)
	tok := f.claims(func(b, _ map[string]any) {
		b["iat"] = now.Add(-2 * time.Hour).Unix() // older than the tool allows
		b["exp"] = now.Add(22 * time.Hour).Unix() // but the issuer says it lives
	})
	err := f.verify(t, tok)
	if err == nil {
		t.Fatal("a two-hour-old approval was accepted by a tool declaring fifteen " +
			"minutes; the issuer's expiry overrode the tool's declaration")
	}
	if !strings.Contains(err.Error(), "old") {
		t.Errorf("refusal does not name the age: %v", err)
	}
}

// The binding that makes an approval mean something.
func TestARequestThatDiffersFromWhatWasApprovedIsRefused(t *testing.T) {
	f := newFixture(t)
	tok := f.claims(func(_, g map[string]any) {
		g["material"] = grant.Digest(map[string]string{
			"id": "p1", "email": "someone.else@example.com",
		})
	})
	err := f.verify(t, tok)
	if err == nil {
		t.Fatal("a request was sent that did not match the approval")
	}
	// The difference is not named. The caller sent the request and knows its
	// values; naming it would only help somebody probing what an approval
	// covered.
	if strings.Contains(err.Error(), "example.com") {
		t.Errorf("the refusal quotes a value back: %v", err)
	}
}

// A grant for a tool that binds material fields must carry a digest. Without
// this, omitting the claim would downgrade a bound approval to a tool-wide
// one — the weaker thing, obtained by leaving a field out.
func TestAGrantWithNoDigestIsRefusedWhenTheToolBindsFields(t *testing.T) {
	f := newFixture(t)
	tok := f.claims(func(_, g map[string]any) { delete(g, "material") })
	if err := f.verify(t, tok); err == nil {
		t.Fatal("a grant with no material digest was accepted for a tool that " +
			"binds its fields")
	}
}

// One approval, one call.
func TestAGrantCannotBeSpentTwice(t *testing.T) {
	f := newFixture(t)
	tok := f.claims(nil)
	if err := f.verify(t, tok); err != nil {
		t.Fatalf("first use: %v", err)
	}
	err := f.verify(t, tok)
	if err == nil {
		t.Fatal("the same approval authorised a second call")
	}
	if !strings.Contains(err.Error(), "already been used") {
		t.Errorf("refusal does not say it was reused: %v", err)
	}
}

// Nothing is consumed until the grant is known good.
//
// Spending first would let an attacker burn somebody else's pending approval
// by replaying it at the wrong tool — a denial of service against a payment
// somebody is waiting to make.
func TestARefusedGrantIsNotSpent(t *testing.T) {
	f := newFixture(t)
	values := map[string]string{"id": "p1", "email": "ada@example.com"}

	// Same jti, presented first at the wrong tool.
	body := map[string]any{
		"iss": issuer, "aud": audience, "jti": "shared-jti",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"garm_grant": map[string]any{
			"tool": "t.v1.wrong", "subject": "customer:C-1",
			"material": grant.Digest(values), "approver": approver,
			"approver_clearance": "RESTRICTED",
		},
	}
	if err := f.verify(t, f.sign(body)); err == nil {
		t.Fatal("a grant for the wrong tool was accepted")
	}

	// The real one, same jti, now correct.
	body["garm_grant"].(map[string]any)["tool"] = "t.v1.pay"
	if err := f.verify(t, f.sign(body)); err != nil {
		t.Fatalf("a legitimate approval was already spent by a refused one: %v — an "+
			"attacker can cancel a pending payment by replaying its grant at the "+
			"wrong tool", err)
	}
}

// A half-configured verifier must refuse, not pass. AddTools only mounted the
// tool because something claimed this seam existed.
func TestAnUnconfiguredVerifierRefuses(t *testing.T) {
	v := &grants.Verifier{}
	err := v.Verify(context.Background(), caller(), payTool(), theRequest())
	if err == nil {
		t.Fatal("a verifier with no keys, no issuers and no replay cache let a " +
			"grant-gated call through")
	}
}

// A tool that does not ask for a grant is not gated by one.
func TestAToolWithoutAGrantModeIsNotChecked(t *testing.T) {
	f := newFixture(t)
	td := payTool()
	td.ApprovalMode = toolv1.Approval_MODE_NONE
	if err := f.v.Verify(context.Background(), caller(), td, theRequest()); err != nil {
		t.Errorf("a tool declaring no approval was checked for one: %v", err)
	}
}

// A grant carrying a `task` claim verifies (cards-and-tasks design §7).
//
// The STS binds a grant to the task it was given on, so two tasks with the
// same material — the same payment asked twice — cannot share one. garmd's
// verifier does NOT read the claim to decide with: the thing that knows which
// task is being decided is the tasks tool, comparing the claim against the row
// it stored, and a check here would have nothing to compare against but
// itself.
//
// What this pins is the half that CAN go wrong from here: a claim garmd does
// not read must not fail a grant. A verifier that refused what it did not
// recognise would make every claim the STS adds a breaking change, and the
// symptom would be every approval in the estate failing at once on the day
// the STS shipped.
func TestAGrantCarryingATaskClaimVerifies(t *testing.T) {
	f := newFixture(t)
	// `task` is the contract's name. `task_id` is here as a claim this
	// verifier does not recognise AT ALL — it used to be read as a second
	// spelling, and is not any more — so the row proves the same point as an
	// invented claim would: what garmd does not read cannot fail a grant.
	for name, claim := range map[string]string{"task": "task", "an unread claim": "task_id"} {
		t.Run(name, func(t *testing.T) {
			token := f.claims(func(_, g map[string]any) { g[claim] = "tsk_01HZY" })
			if err := f.verify(t, token); err != nil {
				t.Fatalf("a grant bound to a task was refused: %v", err)
			}
		})
	}
}

// And the binding reaches whoever asked for it, refused or not.
//
// Before the checks, deliberately: "an approval naming task X was presented
// and rejected" and "no approval naming a task was ever presented" are
// different facts, and only the first is worth waking up for.
func TestTheTaskBindingIsReportedWhetherTheGrantIsGoodOrNot(t *testing.T) {
	for name, tc := range map[string]struct {
		mut      func(body, g map[string]any)
		wantPass bool
	}{
		"a good grant": {func(_, g map[string]any) { g["task"] = "tsk_ok" }, true},
		"a grant for another tool": {func(_, g map[string]any) {
			g["task"] = "tsk_ok"
			g["tool"] = "t.v1.something_else"
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			var got toolplane.GrantBinding
			ctx := toolplane.WithGrantBindingForTest(context.Background(), &got)
			ctx = grants.WithGrant(ctx, f.claims(tc.mut))

			err := f.v.Verify(ctx, caller(), payTool(), theRequest())
			if tc.wantPass != (err == nil) {
				t.Fatalf("Verify err = %v, wantPass = %v", err, tc.wantPass)
			}
			if got.TaskID != "tsk_ok" {
				t.Errorf("the binding reported %q, want tsk_ok", got.TaskID)
			}
		})
	}
}

// A grant with no task claim reports no binding, so the ledger tag is absent
// rather than empty. A column that is always filled distinguishes nothing.
func TestAGrantWithNoTaskReportsNoBinding(t *testing.T) {
	f := newFixture(t)
	var got toolplane.GrantBinding
	ctx := toolplane.WithGrantBindingForTest(context.Background(), &got)
	ctx = grants.WithGrant(ctx, f.claims(nil))

	if err := f.v.Verify(ctx, caller(), payTool(), theRequest()); err != nil {
		t.Fatalf("a valid grant was refused: %v", err)
	}
	if got.TaskID != "" {
		t.Errorf("a grant naming no task reported %q", got.TaskID)
	}
}

// ---------------------------------------------------------------------------
// What consolidating the reader onto contracts/grants must not have changed.
// ---------------------------------------------------------------------------

// The digest over the values a human approved is pinned to a literal.
//
// This is the one value in the platform that must never change by accident.
// It is computed on one side by an STS showing a person some values, and on
// this side by re-extracting them from the request about to be sent — so a
// change to the canonical text of a scalar, or to grant.Digest's encoding,
// invalidates every approval outstanding in the plane at the moment it ships.
// Nothing about that failure is loud: the grants simply stop matching.
//
// The literal below is the digest of the request the rest of this file uses,
// read through the material fields the tool declares. If this test fails, the
// change under it is a breaking change to a credential, not a refactor.
func TestTheMaterialDigestIsPinnedToALiteral(t *testing.T) {
	const want = "sha256:6a6dfa720e0b2334e26035636ede4cc1b5c62232594d2aaac68ff8d61265680d"

	values, err := contractgrants.Materialise(theRequest().ProtoReflect(), payTool().MaterialFields)
	if err != nil {
		t.Fatalf("Materialise: %v", err)
	}
	if got := grant.Digest(values); got != want {
		t.Errorf("the material digest is %s, want %s\n"+
			"values = %v\n"+
			"If this is deliberate, every approval outstanding when it ships stops "+
			"matching, so it is a break in a credential rather than a refactor.",
			got, want, values)
	}
}

// garmd checks the claims it checked before, and still ignores the task.
//
// The task claim binds an approval to the decision it was given on, and the
// service that knows which task is being decided is the one that opened it —
// contracts/grants has CheckTask for exactly that, and this verifier must
// never call it. A check here would have nothing to compare against but
// itself, and would turn a claim garmd only RECORDS into one that can refuse
// a call.
//
// The table is the whole set: bend one claim at a time and assert whether the
// verdict moves. A consolidation that quietly widened or narrowed which
// claims are read fails here rather than in production.
func TestTheClaimsGarmdChecksAreUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mut     func(body, g map[string]any)
		refused bool
	}{
		// Read and checked.
		{"iss", func(b, _ map[string]any) { b["iss"] = "https://evil" }, true},
		{"aud", func(b, _ map[string]any) { b["aud"] = "garm://elsewhere" }, true},
		{"jti", func(b, _ map[string]any) { delete(b, "jti") }, true},
		{"iat", func(b, _ map[string]any) { b["iat"] = now.Add(-2 * time.Hour).Unix() }, true},
		{"exp", func(b, _ map[string]any) { b["exp"] = now.Add(-time.Hour).Unix() }, true},
		{"act", func(b, _ map[string]any) {
			b["act"] = map[string]any{"sub": "agent:x"}
		}, true},
		{"tool", func(_, g map[string]any) { g["tool"] = "t.v1.other" }, true},
		{"subject", func(_, g map[string]any) { g["subject"] = "customer:C-2" }, true},
		{"material", func(_, g map[string]any) { g["material"] = "sha256:0000" }, true},
		{"approver_clearance", func(_, g map[string]any) {
			g["approver_clearance"] = "INTERNAL"
		}, true},

		// Read and NOT checked. The task reaches the ledger row as
		// attribution and decides nothing.
		{"task, naming another task", func(_, g map[string]any) {
			g["task"] = "tsk_somebody_elses"
		}, false},
		{"task, absent", func(_, g map[string]any) { delete(g, "task") }, false},

		// Not read at all. `task_id` was accepted as a second spelling of
		// `task` because both had appeared in the design record; no minter
		// produces it, the contract declares one name, and a reader tolerant
		// of two is how two readers of one credential drift apart without
		// anything noticing. Setting it must now do nothing whatsoever —
		// including not populating the binding, which the next test pins.
		{"task_id", func(_, g map[string]any) { g["task_id"] = "tsk_ignored" }, false},

		// Claims the approver's own token carries that a grant does not
		// speak for. Present in the body and read by nothing here.
		{"approver", func(_, g map[string]any) { g["approver"] = "employee:someone" }, false},
		{"an unknown claim", func(_, g map[string]any) { g["invented"] = "x" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			err := f.verify(t, f.claims(tc.mut))
			switch {
			case tc.refused && err == nil:
				t.Errorf("bending %q was accepted; garmd used to check that claim", tc.name)
			case !tc.refused && err != nil:
				t.Errorf("bending %q was refused (%v); garmd did not use to check "+
					"that claim, and a consolidation must not have started", tc.name, err)
			}
		})
	}
}

// `task_id` is not a second spelling of `task`, anywhere.
//
// The tolerant reader is gone, and the proof that it is gone is that a grant
// carrying only `task_id` reports NO binding — not merely that it verifies.
// A reader that still accepted the alias would pass the table above, because
// the task decides nothing; it would show up here.
func TestTaskIdIsNotReadAsTheTaskClaim(t *testing.T) {
	f := newFixture(t)
	var got toolplane.GrantBinding
	ctx := toolplane.WithGrantBindingForTest(context.Background(), &got)
	ctx = grants.WithGrant(ctx, f.claims(func(_, g map[string]any) {
		delete(g, "task")
		g["task_id"] = "tsk_ignored"
	}))
	if err := f.v.Verify(ctx, caller(), payTool(), theRequest()); err != nil {
		t.Fatalf("the grant was refused: %v", err)
	}
	if got.TaskID != "" {
		t.Errorf("the binding reported %q; task_id was read as the task claim", got.TaskID)
	}
}

// One signature-algorithm allowlist, not two.
//
// garmd's token verifier exports the list and the grant verifier shares it,
// for the reason its own comment gives. The contract module publishes the
// same list for the processes that cannot import garmd. Two lists is two
// things to widen and the second is the one nobody remembers to look at, so
// this fails the day they stop agreeing.
func TestTheAlgorithmAllowlistsAgree(t *testing.T) {
	if !reflect.DeepEqual(authn.PermittedAlgorithms, contractgrants.PermittedAlgorithms) {
		t.Errorf("the allowlists have drifted:\n  garmd:     %v\n  contracts: %v",
			authn.PermittedAlgorithms, contractgrants.PermittedAlgorithms)
	}
}
