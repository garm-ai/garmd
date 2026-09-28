package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// Nil is the configured answer, and it must be a nil INTERFACE.
//
// A typed-nil *grants.Verifier assigned into toolplane.GrantVerifier is
// non-nil, and the mount refusal reads that field to decide whether a
// MODE_GRANT tool may be served — so the typed nil would mount an
// approval-gated tool against a verifier that panics on the first call. Same
// trap, same shape, as the audit Sink in records_test.go.
func TestWithNoGrantIssuerThereIsNoVerifierAtAll(t *testing.T) {
	v, err := grantVerifier(context.Background(), nil, gatedCatalogue(t), serveOpts{})
	if err != nil {
		t.Fatalf("grantVerifier: %v", err)
	}
	if v != nil {
		t.Error("a grant verifier was built with no --grant-issuer; an approval-gated " +
			"tool would now mount against a verifier trusting nobody")
	}
}

// The flag being SET is what turns step 5 on, and what it turns on has to be
// reachable: a verifier with no key set, no issuer or no replay cache refuses
// every call, which is safe and useless.
func TestTheGrantIssuerFlagBuildsAUsableVerifier(t *testing.T) {
	nc := jetstreamConn(t)
	v, err := grantVerifier(context.Background(), nc, gatedCatalogue(t), serveOpts{
		jwksURLs:    []string{"https://idp.test/jwks.json"},
		audience:    "garm",
		grantIssuer: "https://sts.test",
	})
	if err != nil {
		t.Fatalf("grantVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("--grant-issuer was set and no verifier was built")
	}
}

// --grant-jwks and --grant-audience default to --jwks and --audience, because
// an STS that issues both tokens and approvals is the ordinary deployment and
// making an operator type the same two values twice is how they end up
// disagreeing.
func TestTheGrantJWKSAndAudienceDefaultToTheTokenOnes(t *testing.T) {
	o := serveOpts{jwksURLs: []string{"https://idp.test/jwks.json"}, audience: "garm",
		grantIssuer: "https://sts.test"}
	if got := grantJWKS(o); got != o.jwksURLs[0] {
		t.Errorf("grant JWKS = %q, want the token JWKS %q", got, o.jwksURLs[0])
	}
	if got := grantAudience(o); got != o.audience {
		t.Errorf("grant audience = %q, want the token audience %q", got, o.audience)
	}

	o.grantJWKS = "https://sts.test/jwks.json"
	o.grantAudience = "garm://garmd"
	if got := grantJWKS(o); got != o.grantJWKS {
		t.Errorf("grant JWKS = %q, want the explicit %q", got, o.grantJWKS)
	}
	if got := grantAudience(o); got != o.grantAudience {
		t.Errorf("grant audience = %q, want the explicit %q", got, o.grantAudience)
	}
}

// The replay cache must outlast the longest approval the CATALOGUE declares,
// which is computable from the artifact rather than guessed. A cache that
// forgets first makes a grant replayable in the gap, and nothing about that is
// visible at the moment it is configured.
func TestTheLongestGrantAgeComesFromTheCatalogue(t *testing.T) {
	cat := gatedCatalogue(t)
	cat.Defs = append(cat.Defs, tool.Def{
		FQN:          "t.v1.slow",
		ApprovalMode: toolv1.Approval_MODE_GRANT,
		MaxGrantAge:  2 * time.Hour,
	}, tool.Def{
		// Not gated, so its value must not count: an ungated tool spends no
		// grants and a stray annotation on one should not size the cache.
		FQN:         "t.v1.ungated",
		MaxGrantAge: 99 * time.Hour,
	})
	if got := longestGrantAge(cat); got != 2*time.Hour {
		t.Errorf("longestGrantAge = %s, want 2h", got)
	}
	if got := longestGrantAge(&catalogue.Catalogue{}); got != 0 {
		t.Errorf("longestGrantAge of a catalogue with no gated tool = %s, want 0", got)
	}
}

// The banner is what an operator reads at startup, and it said something
// false: that a tool declaring an unimplemented step is "mounted as though it
// had not". It is not — the catalogue refuses to mount and the process does
// not start. An operator who believed the old line would deploy an
// approval-gated catalogue expecting degraded service and get a crash loop.
func TestTheBannerStatesTheActualMountPolicy(t *testing.T) {
	off := chainBanner(false, "")
	if strings.Contains(off, "as though it had not") {
		t.Error("the banner still says an unimplemented step is mounted anyway")
	}
	for _, want := range []string{"WILL NOT MOUNT", "grants are NOT verified"} {
		if !strings.Contains(off, want) {
			t.Errorf("the banner omits %q: %s", want, off)
		}
	}
	on := chainBanner(true, "https://sts.test")
	if !strings.Contains(on, "https://sts.test") {
		t.Errorf("the banner does not name the grant issuer: %s", on)
	}
	if strings.Contains(on, "grants are NOT verified") {
		t.Errorf("the banner says grants are unverified while a verifier is configured: %s", on)
	}
}

// gatedCatalogue is one approval-gated tool, which is all these need: the
// descriptors are never resolved here because nothing mounts it.
func gatedCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()
	return &catalogue.Catalogue{
		Digest: "sha256:test",
		Defs: []tool.Def{{
			FQN:          "t.v1.pay",
			ApprovalMode: toolv1.Approval_MODE_GRANT,
			MaxGrantAge:  15 * time.Minute,
		}},
	}
}

func jetstreamConn(t *testing.T) *nats.Conn {
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
		t.Fatal("the embedded NATS server never became ready")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// (Fix round 1, item 1) A MODE_GRANT tool with no ceiling must not be served.
//
// Without a max_grant_age the tool's approval is bounded only by the token's
// own exp, which the issuer chooses and the tool cannot cap — so there is no
// number to size the replay cache from, and a grant valid for a day against a
// cache that forgets in an hour is replayable for twenty-three of them. The
// refusal has to name the tool, because "some tool is missing a ceiling" sends
// an operator to read a whole catalogue.
func TestAGatedToolWithNoCeilingRefusesToStart(t *testing.T) {
	cat := gatedCatalogue(t)
	cat.Defs = append(cat.Defs, tool.Def{
		FQN:          "t.v1.wire_transfer",
		ApprovalMode: toolv1.Approval_MODE_GRANT,
	})

	_, err := grantVerifier(context.Background(), nil, cat, serveOpts{
		jwksURLs: []string{"https://idp.test/jwks.json"}, audience: "garm",
		grantIssuer: "https://sts.test",
	})
	if err == nil {
		t.Fatal("a MODE_GRANT tool with no max_grant_age was accepted; its approval " +
			"is bounded only by the issuer's exp and the replay cache cannot be sized")
	}
	if !strings.Contains(err.Error(), "t.v1.wire_transfer") {
		t.Errorf("the refusal does not name the tool: %v", err)
	}
	if !strings.Contains(err.Error(), "max_grant_age") {
		t.Errorf("the refusal does not name what is missing: %v", err)
	}
}

// The bucket is sized by the LONGEST ceiling the catalogue declares, not by
// the first one or by a constant. A cache sized by the shortest would forget a
// longer tool's approval while it was still spendable.
func TestTheBucketIsSizedByTheLongestCeiling(t *testing.T) {
	cat := gatedCatalogue(t) // 15m
	cat.Defs = append(cat.Defs, tool.Def{
		FQN:          "t.v1.slow",
		ApprovalMode: toolv1.Approval_MODE_GRANT,
		MaxGrantAge:  2 * time.Hour,
	})

	v, err := grantVerifier(context.Background(), jetstreamConn(t), cat, serveOpts{
		jwksURLs: []string{"https://idp.test/jwks.json"}, audience: "garm",
		grantIssuer: "https://sts.test",
	})
	if err != nil {
		t.Fatalf("grantVerifier: %v", err)
	}
	ver, ok := v.(*grants.Verifier)
	if !ok {
		t.Fatalf("grantVerifier built a %T", v)
	}
	// Ceiling plus the clock tolerance: the verifier accepts an approval up
	// to Skew past its ceiling, so a cache sized to the ceiling alone forgets
	// a promptly spent grant one skew before the grant stops verifying.
	want := 2*time.Hour + authn.DefaultSkew
	if got := ver.Spent.Retention(); got != want {
		t.Errorf("the replay cache keeps entries for %s, want %s; the catalogue's "+
			"longest approval is 2h and the verifier tolerates %s of skew past it, "+
			"so a shorter cache is replayable in the gap", got, want, authn.DefaultSkew)
	}
}

// (Fix round 1, item 2) The clock tolerance is the token path's.
//
// Two tolerances in one process that differ is how a caller ends up with a
// token that verifies and an approval that does not, with nothing in either
// message to say the clocks are what disagreed. Exercised through the
// DAEMON-built verifier, because a test that sets Skew itself proves nothing
// about what garmd serve constructs.
func TestTheDaemonBuiltVerifierUsesTheTokenPathsClockSkew(t *testing.T) {
	idp := newGrantIDP(t)
	v, err := grantVerifier(context.Background(), jetstreamConn(t), gatedCatalogue(t),
		serveOpts{
			jwksURLs: []string{idp.url}, audience: cmdGrantAudience,
			grantIssuer: cmdGrantIssuer,
		})
	if err != nil {
		t.Fatalf("grantVerifier: %v", err)
	}

	def := gatedCatalogue(t).Defs[0]
	p := &toolplane.Principal{Subject: "user:test"}

	// Expired half a minute ago. Inside the tolerance, so it is accepted —
	// the same answer the token path gives a token half a minute stale.
	ctx := grants.WithGrant(context.Background(),
		idp.mintGrant(t, "user:test", -30*time.Second))
	if err := v.Verify(ctx, p, def, nil); err != nil {
		t.Errorf("a grant that expired 30s ago was refused, so the clock tolerance "+
			"is shorter than the token path's %s: %v", authn.DefaultSkew, err)
	}

	// Two minutes stale is outside it, and must be refused — a tolerance that
	// accepted this would be an expiry nobody set.
	ctx = grants.WithGrant(context.Background(),
		idp.mintGrant(t, "user:test", -2*time.Minute))
	if err := v.Verify(ctx, p, def, nil); err == nil {
		t.Error("a grant that expired two minutes ago was accepted; the tolerance " +
			"is longer than the token path's")
	}
}

// (Fix round 1, item 5) --grant-jwks and --grant-audience without
// --grant-issuer are silently inert: step 5 stays off, and the operator who
// typed two of the three flags believes it is on. Say so at startup.
func TestGrantFlagsAreAllOrNone(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    serveOpts
		want string
	}{
		{"jwks without issuer",
			serveOpts{jwksURLs: []string{"https://idp.test/jwks.json"}, audience: "garm",
				grantJWKS: "https://sts.test/jwks.json"},
			"--grant-jwks"},
		{"audience without issuer",
			serveOpts{jwksURLs: []string{"https://idp.test/jwks.json"}, audience: "garm",
				grantAudience: "garm://garmd"},
			"--grant-audience"},
		{"issuer with no key set anywhere",
			serveOpts{audience: "garm", grantIssuer: "https://sts.test"},
			"--grant-jwks"},
		{"issuer with no audience anywhere",
			serveOpts{jwksURLs: []string{"https://idp.test/jwks.json"},
				grantIssuer: "https://sts.test"},
			"--grant-audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := grantVerifier(context.Background(), nil, gatedCatalogue(t), tc.o)
			if err == nil {
				t.Fatalf("a half-given grant configuration was accepted: %+v", tc.o)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name %s: %v", tc.want, err)
			}
		})
	}
}

const (
	cmdGrantIssuer   = "https://sts.test"
	cmdGrantAudience = "garm://garmd"
)

// grantIDP mints approvals the daemon-built verifier will accept, over a real
// JWKS endpoint — the key fetch is part of what is under test.
type grantIDP struct {
	url string
	key *ecdsa.PrivateKey
	n   atomic.Int64
}

func newGrantIDP(t *testing.T) *grantIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: "g1", Algorithm: string(jose.ES256), Use: "sig",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return &grantIDP{url: srv.URL, key: key}
}

// mintGrant signs an approval expiring at now+expiresIn, which the tests pass
// NEGATIVE to mint one that is already stale.
func (i *grantIDP) mintGrant(t *testing.T, subject string, expiresIn time.Duration) string {
	t.Helper()
	now := time.Now()
	body, err := json.Marshal(map[string]any{
		"iss": cmdGrantIssuer,
		"aud": cmdGrantAudience,
		"jti": fmt.Sprintf("g-%d", i.n.Add(1)),
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(expiresIn).Unix(),
		"garm_grant": map[string]any{
			"tool":     "t.v1.pay",
			"subject":  subject,
			"approver": "employee:amir",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "g1"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
