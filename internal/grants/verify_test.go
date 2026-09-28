package grants_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/grant"
	"github.com/garm-ai/garm/policy/testdata"
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
