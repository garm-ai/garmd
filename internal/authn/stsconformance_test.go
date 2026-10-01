package authn_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/authn"
)

// The shape garm-ai/sts mints, verified by the verifier that has to read it.
//
// Neither repository may import the other. sts holds a private key and mints
// tokens; this package decides what a token MEANS, and a module that can
// assert any identity must not be in the dependency graph of one that decides
// what an identity may do. So this pins the shape by construction instead:
// the claim structures below are copied from sts's own tests, and a change on
// either side that they do not both agree to fails here.
//
// That is weaker than running the real service and stronger than nothing. The
// gap it leaves — sts changing the shape and updating only its own tests — is
// the cross-repository conformance job named in KNOWN-GAPS.
//
// Three things about the shape are load-bearing and easy to get wrong:
// clearance and verbs arrive BARE ("CONFIDENTIAL", "READ") where devkit mints
// them prefixed; `aud` names garmd rather than the agent; and the agent sits
// at `act`, never at `sub`.

const (
	stsIssuer   = "https://sts.internal.example.com"
	stsAudience = "garm://garmd"
)

// stsHarness trusts what sts actually issues.
//
// The issuer and audience are not incidental: garmd has to be configured with
// exactly these, and its own defaults (`garm`) do not match sts's
// (`garm://garmd`). A deployment that leaves the default gets every token
// refused for audience mismatch, which is correct and mystifying.
func stsHarness(t *testing.T, now time.Time) (*authn.Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	v := authn.NewVerifier(authn.Config{
		KeySet:       authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
		Issuers:      []string{stsIssuer},
		Audience:     stsAudience,
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})
	return v, key
}

// customerThroughAgent is exchange 1: a customer's authority, an agent
// exercising it.
func customerThroughAgent(now time.Time) map[string]any {
	return map[string]any{
		"iss":    stsIssuer,
		"aud":    stsAudience,
		"sub":    "customer:C-8123",
		"tenant": "acme",
		"iat":    now.Unix(),
		"exp":    now.Add(10 * time.Minute).Unix(),
		"jti":    "sts-1",
		"garm": map[string]any{
			"clearance":    "CONFIDENTIAL",
			"compartments": []any{"pii-contact"},
			"verbs":        []any{"READ"},
			"kind":         "USER",
		},
		"act": map[string]any{
			"sub": "agent:order-assistant",
			"garm": map[string]any{
				"clearance": "INTERNAL",
				"verbs":     []any{"READ"},
				"kind":      "AGENT",
			},
		},
	}
}

func TestAnSTSDelegationTokenFoldsToTheCustomersAuthorityNarrowedByTheAgent(t *testing.T) {
	now := time.Now()
	v, key := stsHarness(t, now)
	tok := sign(t, key, "k1", customerThroughAgent(now))

	p, dropped, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("a token in sts's shape did not verify: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("compartments dropped: %v — this build does not declare what sts "+
			"minted, so the caller silently has less authority than its token says", dropped)
	}

	// The customer's authority is the subject's, not the agent's.
	if p.Subject != "customer:C-8123" {
		t.Errorf("Subject = %q, want the customer — staff and agents exercise "+
			"authority, they do not replace it", p.Subject)
	}
	if p.Actor != "agent:order-assistant" {
		t.Errorf("Actor = %q, want the agent", p.Actor)
	}
	// Kind describes the SUBJECT. An agent exercising a customer's authority
	// is still a call made on behalf of a user, which is what a ledger row
	// needs to say.
	if p.Kind != toolv1.PrincipalKind_PRINCIPAL_KIND_USER {
		t.Errorf("Kind = %v, want USER", p.Kind)
	}
	// Folding intersects. The customer is CONFIDENTIAL and the agent is
	// INTERNAL, so the call is INTERNAL — sts mints the agent's own claim
	// unnarrowed and leaves this to us, deliberately.
	if p.Clearance != toolv1.Clearance_CLEARANCE_INTERNAL {
		t.Errorf("Clearance = %v, want INTERNAL: an INTERNAL agent exercising a "+
			"CONFIDENTIAL customer's authority must not reach CONFIDENTIAL", p.Clearance)
	}
	if p.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme", p.Tenant)
	}
}

// The bare spellings, which are the ones sts actually mints.
//
// devkit mints CLEARANCE_RESTRICTED and VERB_READ; sts mints RESTRICTED and
// READ. Both are valid and this verifier normalises them — but only because
// something does, and nothing else tests that the bare forms survive.
func TestTheBareSpellingsSTSMintsAreAccepted(t *testing.T) {
	now := time.Now()
	v, key := stsHarness(t, now)

	body := customerThroughAgent(now)
	body["garm"].(map[string]any)["clearance"] = "RESTRICTED"
	body["garm"].(map[string]any)["verbs"] = []any{"READ", "WRITE"}
	delete(body, "act") // no agent: the subject's own authority, undiluted

	p, _, err := v.Verify(context.Background(), sign(t, key, "k1", body))
	if err != nil {
		t.Fatalf("bare spellings were refused: %v", err)
	}
	if p.Clearance != toolv1.Clearance_CLEARANCE_RESTRICTED {
		t.Errorf("Clearance = %v, want RESTRICTED from the bare spelling", p.Clearance)
	}
	if !p.Verbs.Has(toolv1.Verb_VERB_WRITE) {
		t.Error("VERB_WRITE absent from the bare spelling \"WRITE\"")
	}
}

// Exchange 1's other path: an employee acting for a customer they handle, with
// an agent exercising it. sub=customer, act=agent, act.act=employee.
//
// Three levels, and the ceiling is the minimum of all three. If this ever
// folded to anything but the lowest, an employee could reach further through
// an agent than either of them could alone — which is the confused deputy the
// chain limit exists to bound.
func TestAThreeLevelChainFoldsToTheLowestAuthority(t *testing.T) {
	now := time.Now()
	v, key := stsHarness(t, now)

	body := customerThroughAgent(now)
	act := body["act"].(map[string]any)
	act["act"] = map[string]any{
		"sub": "employee:jdoe",
		"garm": map[string]any{
			"clearance": "PUBLIC", // the weakest link, deliberately
			"verbs":     []any{"READ"},
			"kind":      "USER",
		},
	}

	p, _, err := v.Verify(context.Background(), sign(t, key, "k1", body))
	if err != nil {
		t.Fatalf("a three-level chain did not verify: %v", err)
	}
	if p.Clearance != toolv1.Clearance_CLEARANCE_PUBLIC {
		t.Errorf("Clearance = %v, want PUBLIC — the chain is a customer at "+
			"CONFIDENTIAL, an agent at INTERNAL and an employee at PUBLIC, and the "+
			"call may only be as strong as its weakest link", p.Clearance)
	}
	if len(p.Chain) < 3 {
		t.Errorf("chain = %v, want all three identities; the ledger has to show "+
			"every one of them", p.Chain)
	}
}
