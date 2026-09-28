package main

import (
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

// The grant flags are separate and stay singular: one STS mints approvals,
// and --grant-jwks defaults to the FIRST --jwks because that is the pair an
// operator writes when there is only one.
func TestTheGrantJWKSDefaultsToTheFirstKeySet(t *testing.T) {
	o := serveOpts{
		jwksURLs: []string{"https://idp.example.com/jwks.json",
			"https://sts.example.com/jwks.json"},
		audience:    "garm",
		grantIssuer: "https://sts.example.com",
	}
	if got := grantJWKS(o); got != "https://idp.example.com/jwks.json" {
		t.Errorf("grant JWKS = %q, want the first --jwks", got)
	}
	o.grantJWKS = "https://sts.example.com/jwks.json"
	if got := grantJWKS(o); got != o.grantJWKS {
		t.Errorf("grant JWKS = %q, want the explicit %q", got, o.grantJWKS)
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
