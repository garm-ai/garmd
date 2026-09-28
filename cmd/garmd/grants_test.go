package main

import (
	"context"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
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
		jwksURL:     "https://idp.test/jwks.json",
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
	o := serveOpts{jwksURL: "https://idp.test/jwks.json", audience: "garm",
		grantIssuer: "https://sts.test"}
	if got := grantJWKS(o); got != o.jwksURL {
		t.Errorf("grant JWKS = %q, want the token JWKS %q", got, o.jwksURL)
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
