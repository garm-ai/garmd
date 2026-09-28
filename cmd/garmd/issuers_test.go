package main

import (
	"context"
	"strings"
	"testing"
)

// Paired by INDEX: the first --issuer with the first --jwks. Not by name, not
// by discovery — an operator writes them next to each other and the pairing is
// the order they were written in.
func TestIssuersAndKeySetsPairByIndex(t *testing.T) {
	got, err := trustedIssuers(
		[]string{"https://idp.example.com", "https://sts.example.com"},
		[]string{"https://idp.example.com/jwks.json", "https://sts.example.com/jwks.json"},
	)
	if err != nil {
		t.Fatalf("trustedIssuers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("%d trusted issuers, want 2", len(got))
	}
	if got[0].Issuer != "https://idp.example.com" || got[1].Issuer != "https://sts.example.com" {
		t.Errorf("issuers = %q, %q; the order the operator wrote was not kept",
			got[0].Issuer, got[1].Issuer)
	}
	// Distinct key sets, not one shared: the whole point is that the STS may
	// not sign for the IdP.
	if got[0].KeySet == nil || got[1].KeySet == nil {
		t.Fatal("an issuer was left with no key set")
	}
	if got[0].KeySet == got[1].KeySet {
		t.Error("both issuers share one key set; either could then sign for the other")
	}
}

// Mismatched counts refuse AT STARTUP. Silently pairing what there is would
// leave an issuer with no keys — every token from it refused at runtime, with
// a message about the token rather than about the configuration.
func TestMismatchedFlagCountsRefuse(t *testing.T) {
	for _, c := range []struct {
		name          string
		issuers, jwks []string
	}{
		{"more issuers than key sets",
			[]string{"https://a", "https://b"}, []string{"https://a/jwks"}},
		{"more key sets than issuers",
			[]string{"https://a"}, []string{"https://a/jwks", "https://b/jwks"}},
		{"issuers and no key sets", []string{"https://a"}, nil},
		{"key sets and no issuers", nil, []string{"https://a/jwks"}},
		{"neither", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := trustedIssuers(c.issuers, c.jwks)
			if err == nil {
				t.Fatal("a mismatched configuration was accepted")
			}
			for _, want := range []string{"--issuer", "--jwks"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error does not name %s: %v", want, err)
				}
			}
		})
	}
}

// One pair is the ordinary deployment and must stay the simplest thing to
// write: two flags, once each, exactly as before this was repeatable.
func TestASinglePairIsStillTheOrdinaryCase(t *testing.T) {
	got, err := trustedIssuers(
		[]string{"https://garmdev.invalid/idp"},
		[]string{"http://127.0.0.1:7450/.well-known/jwks.json"},
	)
	if err != nil {
		t.Fatalf("trustedIssuers: %v", err)
	}
	if len(got) != 1 || got[0].Issuer != "https://garmdev.invalid/idp" {
		t.Fatalf("got %+v, want one entry for the dev IdP", got)
	}
}

// A duplicate issuer is a configuration mistake with a silent outcome: the
// first entry wins every lookup and the second's key set is never consulted,
// so tokens signed by it are refused with a message about the key.
func TestADuplicateIssuerIsRefused(t *testing.T) {
	_, err := trustedIssuers(
		[]string{"https://a", "https://a"},
		[]string{"https://a/jwks", "https://b/jwks"},
	)
	if err == nil {
		t.Fatal("the same issuer was accepted twice; the second key set would never " +
			"be consulted")
	}
	if !strings.Contains(err.Error(), "https://a") {
		t.Errorf("the error does not name the duplicate: %v", err)
	}
}

// The grant flags are separate and stay singular: one STS mints approvals.
// With ONE --jwks that is the pair an operator wrote and --grant-jwks defaults
// to it. With several there is no default to have.
//
// Defaulting to the first would verify an approval claiming the STS's name
// against the IdP's keys — the cross-signing hole the token path just closed,
// reopened one flag over, because the grant verifier checks the issuer against
// its own allowlist and the signature against whatever key set it was handed.
// Nothing downstream notices, and approvals come from the STS, which is rarely
// the first --jwks written.
func TestARepeatedJWKSHasNoUnambiguousGrantDefault(t *testing.T) {
	two := []string{"https://idp.example.com/jwks.json", "https://sts.example.com/jwks.json"}

	// Two --jwks and no --grant-jwks: nothing to default to, and refused at
	// startup rather than guessed.
	if got := grantJWKS(serveOpts{jwksURLs: two}); got != "" {
		t.Errorf("grant JWKS = %q, want none: with two --jwks there is no pair to read", got)
	}
	err := checkGrantFlags(serveOpts{
		jwksURLs: two, audience: "garm", grantIssuer: "https://sts.example.com",
	})
	if err == nil {
		t.Fatal("a repeated --jwks with no --grant-jwks was accepted; approvals would be " +
			"verified against whichever key set was written first")
	}
	for _, want := range []string{"--grant-jwks", "--jwks"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}

	// One --jwks: the ordinary deployment, and it still defaults.
	one := serveOpts{jwksURLs: two[:1], audience: "garm", grantIssuer: "https://sts.example.com"}
	if got := grantJWKS(one); got != one.jwksURLs[0] {
		t.Errorf("grant JWKS = %q, want the only --jwks %q", got, one.jwksURLs[0])
	}
	if err := checkGrantFlags(one); err != nil {
		t.Errorf("the one-pair deployment was refused: %v", err)
	}

	// An explicit --grant-jwks wins, however many --jwks there are.
	o := serveOpts{jwksURLs: two, audience: "garm", grantIssuer: "https://sts.example.com",
		grantJWKS: "https://sts.example.com/jwks.json"}
	if got := grantJWKS(o); got != o.grantJWKS {
		t.Errorf("grant JWKS = %q, want the explicit %q", got, o.grantJWKS)
	}
	if err := checkGrantFlags(o); err != nil {
		t.Errorf("an explicit --grant-jwks alongside two --jwks was refused: %v", err)
	}
}

// The refusal is scoped to deployments that verify approvals at all. Two
// issuers and no --grant-issuer is a perfectly ordinary tool plane — step 5 is
// off, a MODE_GRANT catalogue will not mount, and there is nothing for a
// --grant-jwks to be ambiguous about.
func TestTwoIssuersWithoutAGrantIssuerStillStart(t *testing.T) {
	o := serveOpts{
		issuers: []string{"https://idp.example.com", "https://sts.example.com"},
		jwksURLs: []string{"https://idp.example.com/jwks.json",
			"https://sts.example.com/jwks.json"},
		audience: "garm",
	}
	// The pairing itself must be accepted first, as runServe does, or this
	// test would pass for a config the daemon refuses one line earlier.
	if _, err := trustedIssuers(o.issuers, o.jwksURLs); err != nil {
		t.Fatalf("two paired issuers were refused: %v", err)
	}
	if err := checkGrantFlags(o); err != nil {
		t.Fatalf("a two-issuer deployment with no --grant-issuer was refused: %v", err)
	}
	v, err := grantVerifier(context.Background(), nil, gatedCatalogue(t), o)
	if err != nil {
		t.Fatalf("grantVerifier: %v", err)
	}
	if v != nil {
		t.Error("a grant verifier was built with no --grant-issuer")
	}
}

// The pair carries its own JWKS URL, so nothing downstream re-derives the
// pairing by index. Two parallel slices indexed in three places is one
// off-by-one away from a startup line naming the wrong key set for an issuer,
// and from a metadata check that asks the wrong endpoint about it.
func TestATrustedPairCarriesItsKeySetURL(t *testing.T) {
	got, err := trustedIssuers(
		[]string{"https://idp.example.com", "https://sts.example.com"},
		[]string{"https://idp.example.com/jwks.json", "https://sts.example.com/jwks.json"},
	)
	if err != nil {
		t.Fatalf("trustedIssuers: %v", err)
	}
	if got[0].JWKS != "https://idp.example.com/jwks.json" ||
		got[1].JWKS != "https://sts.example.com/jwks.json" {
		t.Errorf("JWKS URLs = %q, %q; the pair does not carry the key set it was built from",
			got[0].JWKS, got[1].JWKS)
	}
}

// What trustedIssuers produces has to be a Config the verifier will actually
// serve, not merely a well-shaped slice: authn refuses a Trusted list it
// cannot serve on the first Verify, which on the daemon path is the first
// request rather than startup. Pairing that satisfies this helper must also
// satisfy that one.
func TestThePairingBuildsAVerifierThatWillServe(t *testing.T) {
	trusted, err := trustedIssuers(
		[]string{"https://idp.example.com", "https://sts.example.com"},
		[]string{"https://idp.example.com/jwks.json", "https://sts.example.com/jwks.json"},
	)
	if err != nil {
		t.Fatalf("trustedIssuers: %v", err)
	}
	seen := map[string]bool{}
	for _, tr := range trusted {
		if tr.Issuer == "" || tr.KeySet == nil {
			t.Fatalf("an entry the verifier will refuse: %+v", tr)
		}
		if seen[tr.Issuer] {
			t.Fatalf("issuer %q appears twice", tr.Issuer)
		}
		seen[tr.Issuer] = true
	}
}
