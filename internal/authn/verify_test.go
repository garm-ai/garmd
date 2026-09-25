package authn_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/authn"
	jose "github.com/go-jose/go-jose/v4"
)

// sign mints a token from body, signed by key under kid.
func sign(t *testing.T, key *ecdsa.PrivateKey, kid string, body map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the token body: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialising: %v", err)
	}
	return s
}

func goodBody(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://idp.example.com",
		"sub": "user-1",
		"aud": "garm",
		"jti": "tok-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"garm": map[string]any{
			"clearance":    "CLEARANCE_CONFIDENTIAL",
			"compartments": []any{"financial"},
			"verbs":        []any{"VERB_READ"},
		},
	}
}

// harness wires a KeySet against a live JWKS server and returns a verifier
// configured to trust it, plus the signing key.
func harness(t *testing.T, now time.Time) (*authn.Verifier, *ecdsa.PrivateKey, *jwksServer) {
	t.Helper()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	v := authn.NewVerifier(authn.Config{
		KeySet:       authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
		Issuers:      []string{"https://idp.example.com"},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})
	return v, key, srv
}

func TestVerifyAcceptsAValidTokenAndFoldsIt(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)

	p, dropped, err := v.Verify(context.Background(), sign(t, key, "k1", goodBody(now)))
	if err != nil {
		t.Fatalf("Verify rejected a valid token: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped compartments %v from a token declaring only known ones", dropped)
	}
	if p.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", p.Subject)
	}
	if p.Clearance != toolv1.Clearance_CLEARANCE_CONFIDENTIAL {
		t.Errorf("Clearance = %v, want CONFIDENTIAL", p.Clearance)
	}
	if p.TokenID != "tok-1" {
		t.Errorf("TokenID = %q, want tok-1", p.TokenID)
	}
}

// alg=none is the original JWT vulnerability. It must be impossible, not
// merely unusual.
func TestVerifyRejectsAlgNone(t *testing.T) {
	now := time.Now()
	v, _, _ := harness(t, now)

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	unsigned := enc(map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"}) +
		"." + enc(goodBody(now)) + "."

	if _, _, err := v.Verify(context.Background(), unsigned); err == nil {
		t.Fatal("an alg=none token was accepted")
	}
}

func TestVerifyRejectsAKeyNotInTheKeySet(t *testing.T) {
	now := time.Now()
	v, _, _ := harness(t, now)
	attacker, _ := newKey(t, "k1") // same kid, different key

	if _, _, err := v.Verify(context.Background(), sign(t, attacker, "k1", goodBody(now))); err == nil {
		t.Fatal("a token signed with a key the IdP never published was accepted")
	}
}

func TestVerifyRejectsExpiredAndNotYetValidOutsideSkew(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)

	expired := goodBody(now)
	expired["exp"] = now.Add(-time.Minute).Unix()
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", expired)); err == nil {
		t.Error("an expired token was accepted")
	}

	future := goodBody(now)
	future["nbf"] = now.Add(time.Minute).Unix()
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", future)); err == nil {
		t.Error("a not-yet-valid token was accepted")
	}
}

// Skew exists because clocks disagree; without it a token minted one second
// in the future by a slightly-fast IdP is rejected for no good reason.
func TestVerifyAcceptsWithinSkew(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now) // skew 30s

	justExpired := goodBody(now)
	justExpired["exp"] = now.Add(-10 * time.Second).Unix()
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", justExpired)); err != nil {
		t.Errorf("a token expired 10s ago was rejected with 30s of skew: %v", err)
	}

	justFuture := goodBody(now)
	justFuture["nbf"] = now.Add(10 * time.Second).Unix()
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", justFuture)); err != nil {
		t.Errorf("a token valid in 10s was rejected with 30s of skew: %v", err)
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)
	body := goodBody(now)
	body["aud"] = "some-other-service"

	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", body)); err == nil {
		t.Fatal("a token minted for another audience was accepted — it is a valid " +
			"token, which is exactly why the audience check is what stops it")
	}
}

func TestVerifyRejectsAnIssuerNotInTheAllowlist(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)
	body := goodBody(now)
	body["iss"] = "https://attacker.example.com"

	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", body)); err == nil {
		t.Fatal("a token from an unlisted issuer was accepted")
	}
}

// The attack the whole delegation model rests on not working: take a real
// token, add or widen an `act` chain, re-sign with a key you control. The
// chain is inside the signed payload, so this must fail on the signature —
// and the test signs with a key that is NOT published, which is the only way
// an attacker can alter the chain.
func TestVerifyRejectsAForgedActChain(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)
	attacker, _ := newKey(t, "k1")

	forged := goodBody(now)
	forged["act"] = map[string]any{
		"sub": "orchestrator-1",
		"garm": map[string]any{
			"clearance":    "CLEARANCE_RESTRICTED",
			"compartments": []any{"financial", "pii-contact"},
			"verbs":        []any{"VERB_READ", "VERB_DESTRUCTIVE"},
		},
	}

	if _, _, err := v.Verify(context.Background(), sign(t, attacker, "k1", forged)); err == nil {
		t.Fatal("an act chain re-signed with an unpublished key was accepted; " +
			"delegation would be forgeable by anyone who can mint a keypair")
	}

	// And the same chain, legitimately signed, must still narrow rather than
	// widen — proving the rejection above was the signature, not the fold
	// silently discarding the chain.
	p, _, err := v.Verify(context.Background(), sign(t, key, "k1", forged))
	if err != nil {
		t.Fatalf("a legitimately signed act chain was rejected: %v", err)
	}
	if p.Clearance != toolv1.Clearance_CLEARANCE_CONFIDENTIAL {
		t.Errorf("folding took the actor's RESTRICTED instead of the minimum; got %v", p.Clearance)
	}
	if !strings.Contains(strings.Join(p.Chain, ","), "orchestrator-1") {
		t.Errorf("Chain = %v, want it to record the actor", p.Chain)
	}
}
