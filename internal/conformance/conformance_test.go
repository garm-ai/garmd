//go:build conformance

// This file runs ONLY under -tags conformance, and never in the normal
// suite: it needs a live minter, and a test that quietly passes when its
// subject is absent is worse than no test.
package conformance_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/garm-ai/garmd/internal/conformance"
)

var (
	suitePath = flag.String("suite", "", "path to a conformance suite JSON file")
	idpURL    = flag.String("idp", "", "base URL of a running minter")

	minterKind  = flag.String("minter", "get", "minter shape to drive: get|form")
	clientID    = flag.String("client-id", "", "client id (form minter only)")
	clientKey   = flag.String("client-key", "", "path to a PEM-encoded EC private key (form minter only)")
	tokenEndAud = flag.String("token-endpoint-aud", "", "audience the client_assertion must name (form minter only)")
)

// buildMinter selects a Minter from -minter, and fails outright — never
// falls back, never skips — if the selected shape is missing what it needs.
// A conformance run that silently checked nothing, or checked the wrong
// minter shape, is the exact failure this package exists to prevent.
func buildMinter(t *testing.T) conformance.Minter {
	t.Helper()
	switch *minterKind {
	case "get":
		return conformance.HTTPMinter{BaseURL: *idpURL}
	case "form":
		if *clientID == "" || *clientKey == "" || *tokenEndAud == "" {
			t.Fatal("-minter=form requires -client-id, -client-key and -token-endpoint-aud; " +
				"a form minter missing any of these must fail, not fall back to -minter=get")
		}
		pemBytes, err := os.ReadFile(*clientKey)
		if err != nil {
			t.Fatalf("reading -client-key: %v", err)
		}
		key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatal(err)
		}
		return conformance.FormMinter{
			BaseURL:  *idpURL,
			ClientID: *clientID,
			Audience: *tokenEndAud,
			Key:      key,
		}
	default:
		t.Fatalf("-minter=%q is not a recognized minter shape; want get|form", *minterKind)
		return nil
	}
}

func TestMinterConformance(t *testing.T) {
	// Not t.Skip. A conformance run invoked without its arguments has
	// checked nothing, and reporting ok for that is the failure mode this
	// whole package exists to prevent.
	if *suitePath == "" || *idpURL == "" {
		t.Fatal("-suite and -idp are both required; " +
			"a conformance run with nothing to check must not report ok")
	}

	s, err := conformance.LoadSuite(*suitePath)
	if err != nil {
		t.Fatal(err)
	}
	results, err := conformance.Run(context.Background(), s,
		buildMinter(t),
		*idpURL+"/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s: %v", r.Case, r.Err)
			continue
		}
		t.Logf("%s: ok", r.Case)
	}
}
