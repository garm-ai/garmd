//go:build conformance

// This file runs ONLY under -tags conformance, and never in the normal
// suite: it needs a live minter, and a test that quietly passes when its
// subject is absent is worse than no test.
package conformance_test

import (
	"context"
	"flag"
	"testing"

	"github.com/garm-ai/garmd/internal/conformance"
)

var (
	suitePath = flag.String("suite", "", "path to a conformance suite JSON file")
	idpURL    = flag.String("idp", "", "base URL of a running minter")
)

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
		conformance.HTTPMinter{BaseURL: *idpURL},
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
