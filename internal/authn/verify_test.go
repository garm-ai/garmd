package authn_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
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

func TestVerifyAudienceForms(t *testing.T) {
	now := time.Now()

	for _, tc := range []struct {
		name   string
		aud    any
		accept bool
	}{
		{"bare string, matching", "garm", true},
		{"single-element array", []any{"garm"}, true},
		{"array, match first", []any{"garm", "other"}, true},
		{"array, match NOT first", []any{"other", "garm"}, true},
		{"array, no match", []any{"other", "another"}, false},
		{"empty array", []any{}, false},
		{"bare string, not matching", "other", false},
		{"absent", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, key, _ := harness(t, now)
			body := goodBody(now)
			if tc.aud == nil {
				delete(body, "aud")
			} else {
				body["aud"] = tc.aud
			}

			_, _, err := v.Verify(context.Background(), sign(t, key, "k1", body))
			if tc.accept && err != nil {
				t.Fatalf("rejected an acceptable audience %v: %v", tc.aud, err)
			}
			if !tc.accept && err == nil {
				t.Fatalf("accepted audience %v, which does not contain %q", tc.aud, "garm")
			}
		})
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
	subjects := make([]string, len(p.Chain))
	for i, e := range p.Chain {
		subjects[i] = e.Subject
	}
	if !strings.Contains(strings.Join(subjects, ","), "orchestrator-1") {
		t.Errorf("Chain = %v, want it to record the actor", p.Chain)
	}
}

// Two issuers, one process.
//
// The governed door verifies a human's token from the enterprise IdP and the
// runner's token from the STS, in the same request path. One KeySet for a list
// of issuers cannot do that — and worse, it means whoever can answer that one
// URL may sign for every issuer on the allowlist. Each issuer brings its own
// key set, and a token is verified against ITS issuer's keys or not at all.
func TestATokenFromEitherTrustedIssuerVerifies(t *testing.T) {
	now := time.Now()

	humanKey, humanJWK := newKey(t, "idp-1")
	humanSrv := newJWKSServer(t, humanJWK)
	stsKey, stsJWK := newKey(t, "sts-1")
	stsSrv := newJWKSServer(t, stsJWK)

	v := authn.NewVerifier(authn.Config{
		Trusted: []authn.TrustedIssuer{
			{Issuer: "https://idp.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: humanSrv.URL})},
			{Issuer: "https://sts.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: stsSrv.URL})},
		},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})

	human := goodBody(now)
	p, _, err := v.Verify(context.Background(), sign(t, humanKey, "idp-1", human))
	if err != nil {
		t.Fatalf("the human's token was refused: %v", err)
	}
	if p.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", p.Subject)
	}

	agent := goodBody(now)
	agent["iss"] = "https://sts.example.com"
	agent["sub"] = "employee:jdoe"
	if _, _, err := v.Verify(context.Background(), sign(t, stsKey, "sts-1", agent)); err != nil {
		t.Fatalf("the STS's token was refused: %v", err)
	}
}

// An issuer nobody named is refused, whoever signed it. This is the check the
// whole allowlist exists for, and it must not have been weakened by routing on
// the token's own claim.
func TestATokenFromAnUnnamedIssuerIsRefused(t *testing.T) {
	now := time.Now()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)

	v := authn.NewVerifier(authn.Config{
		Trusted: []authn.TrustedIssuer{
			{Issuer: "https://idp.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: srv.URL})},
		},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})

	body := goodBody(now)
	body["iss"] = "https://someone-elses.example.com"
	_, _, err := v.Verify(context.Background(), sign(t, key, "k1", body))
	if err == nil {
		t.Fatal("a token from an issuer nobody named was accepted")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("the refusal does not say what was wrong: %v", err)
	}
}

// The loop closed.
//
// Key selection reads the UNVERIFIED iss, because a key set has to be chosen
// before a signature can be checked. That is safe only if the VERIFIED iss is
// then required to match the issuer whose keys were used — otherwise a token
// signed by one trusted issuer while claiming another's name passes, since
// both are on the allowlist and the allowlist is all the old check asked.
//
// Constructed the only way it can be: the STS's key signs a body claiming the
// IdP's iss. Routing reads iss = the IdP and fetches the IdP's keys, so the
// signature does not verify — and if routing ever reads the header's kid
// instead, or tries every key set, the verified iss check is what still
// refuses it.
func TestATokenSignedByOneIssuerCannotClaimAnothersName(t *testing.T) {
	now := time.Now()
	_, humanJWK := newKey(t, "idp-1")
	humanSrv := newJWKSServer(t, humanJWK)
	stsKey, stsJWK := newKey(t, "sts-1")
	stsSrv := newJWKSServer(t, stsJWK)

	v := authn.NewVerifier(authn.Config{
		Trusted: []authn.TrustedIssuer{
			{Issuer: "https://idp.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: humanSrv.URL})},
			{Issuer: "https://sts.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: stsSrv.URL})},
		},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})

	body := goodBody(now) // iss = https://idp.example.com
	forged := sign(t, stsKey, "sts-1", body)
	if _, _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("a token signed by the STS while claiming the IdP's name was accepted; " +
			"either issuer could then mint for the other")
	}
}

// The same kid in both key sets.
//
// Two IdPs number their keys independently, so `kid` collides sooner than
// anyone expects. Routing on the kid, or trying every key set until one
// verifies, would make this token verify under whichever set was consulted
// first — and "some trusted party signed this" is not the question. The issuer
// selects the key set; the kid only addresses a key WITHIN it.
func TestTheSameKidInBothKeySetsStaysTwoDifferentKeys(t *testing.T) {
	now := time.Now()
	humanKey, humanJWK := newKey(t, "shared")
	humanSrv := newJWKSServer(t, humanJWK)
	stsKey, stsJWK := newKey(t, "shared")
	stsSrv := newJWKSServer(t, stsJWK)

	v := authn.NewVerifier(authn.Config{
		Trusted: []authn.TrustedIssuer{
			{Issuer: "https://idp.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: humanSrv.URL})},
			{Issuer: "https://sts.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: stsSrv.URL})},
		},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})

	// Each issuer's own key, under the colliding kid, still verifies.
	if _, _, err := v.Verify(context.Background(), sign(t, humanKey, "shared", goodBody(now))); err != nil {
		t.Fatalf("the IdP's token was refused under a kid the STS also publishes: %v", err)
	}
	sts := goodBody(now)
	sts["iss"] = "https://sts.example.com"
	if _, _, err := v.Verify(context.Background(), sign(t, stsKey, "shared", sts)); err != nil {
		t.Fatalf("the STS's token was refused under a kid the IdP also publishes: %v", err)
	}

	// And the crossed pair does not: the STS's key under the IdP's name,
	// where the kid alone would have found a key that exists.
	if _, _, err := v.Verify(context.Background(), sign(t, stsKey, "shared", goodBody(now))); err == nil {
		t.Fatal("the STS's key verified a token claiming the IdP, because both key sets " +
			"publish that kid; the kid must address a key within ONE issuer's set")
	}
}

// A token with no iss at all selects nothing. It must refuse rather than fall
// through to the first entry, which would make the first-listed issuer the
// default signer for every unnamed token.
func TestATokenWithNoIssuerIsRefused(t *testing.T) {
	now := time.Now()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)

	v := authn.NewVerifier(authn.Config{
		Trusted: []authn.TrustedIssuer{
			{Issuer: "https://idp.example.com", KeySet: authn.NewKeySet(authn.KeySetConfig{URL: srv.URL})},
		},
		Audience:     "garm",
		Compartments: testRegistry(t),
		Skew:         30 * time.Second,
		Now:          func() time.Time { return now },
	})

	body := goodBody(now)
	delete(body, "iss")
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", body)); err == nil {
		t.Fatal("a token naming no issuer was accepted")
	}
}

// The single-pair form is what every existing deployment, every other test in
// this package and the conformance runner construct. It must keep working
// EXACTLY as before, or this change is a breaking one wearing a compatible
// shape.
func TestTheSingleKeySetFormStillWorksUnchanged(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)

	p, dropped, err := v.Verify(context.Background(), sign(t, key, "k1", goodBody(now)))
	if err != nil {
		t.Fatalf("the single-pair verifier refused a valid token: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped %v", dropped)
	}
	if p.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", p.Subject)
	}

	body := goodBody(now)
	body["iss"] = "https://someone-elses.example.com"
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", body)); err == nil {
		t.Error("the single-pair verifier accepted an issuer outside its allowlist")
	}
}

// A Trusted list that cannot be served is refused on the first call, the way
// Task 8's two-taxonomy Config is.
//
// NewVerifier has no error to return and every embedder's call site would
// change to add one, so the refusal is held and returned by Verify. It is not
// softened: an entry with no key set would be skipped by selection and read as
// "that issuer is not allowed", and a duplicated issuer means the second
// entry's key set is never consulted — both are configuration faults reported
// as token faults, at runtime, to whoever is paged.
func TestAnUnservableTrustedListIsRefusedOnTheFirstCall(t *testing.T) {
	now := time.Now()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	ks := func() *authn.KeySet { return authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}) }

	for _, tc := range []struct {
		name string
		cfg  authn.Config
		want string
	}{
		{"an entry with no key set",
			authn.Config{Trusted: []authn.TrustedIssuer{{Issuer: "https://idp.example.com"}}},
			"key set"},
		{"an entry with no issuer",
			authn.Config{Trusted: []authn.TrustedIssuer{{KeySet: ks()}}},
			"issuer"},
		{"the same issuer twice",
			authn.Config{Trusted: []authn.TrustedIssuer{
				{Issuer: "https://idp.example.com", KeySet: ks()},
				{Issuer: "https://idp.example.com", KeySet: ks()},
			}},
			"https://idp.example.com"},
		{"both forms at once",
			authn.Config{
				Trusted: []authn.TrustedIssuer{{Issuer: "https://idp.example.com", KeySet: ks()}},
				KeySet:  ks(),
				Issuers: []string{"https://idp.example.com"},
			},
			"Trusted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Audience = "garm"
			cfg.Compartments = testRegistry(t)
			cfg.Now = func() time.Time { return now }
			v := authn.NewVerifier(cfg)
			_, _, err := v.Verify(context.Background(), sign(t, key, "k1", goodBody(now)))
			if err == nil {
				t.Fatalf("an unservable Trusted list verified a token: %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name %s: %v", tc.want, err)
			}
		})
	}
}
