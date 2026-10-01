package serve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/tool"
)

// A compartment SET is a bitset, and which bit a name gets depends on the
// whole generation: policy.Registry assigns bits by sorted index, so adding
// one declaration renumbers every name after it.
//
// That makes a Principal's compartments meaningful only against the registry
// that folded them. The verifier's taxonomy became swappable in task 8 and
// the chain's comes from the plane, so the two can be on different clocks —
// and a bitset folded under one generation, read under another, is not a
// narrower answer or a wider one. It is a DIFFERENT answer: here a caller
// holding "financial" under the verifier's generation reads as holding
// "support" under the chain's, and walks through a support-gated tool.
//
// The fix is that a request pins one generation: the handler reads the plane
// once, and the fold happens against THAT plane's registry.
func TestARequestFoldsAgainstThePlanesOwnGeneration(t *testing.T) {
	// The generation being served. Sorted: financial=bit0, support=bit1.
	gen1 := []*toolv1.Decl{{Name: "financial"}, {Name: "support"}}
	// A later generation the verifier is holding. Sorted: billing=bit0,
	// financial=bit1, support=bit2 — "financial" has moved onto the bit
	// "support" occupies in gen1, which is the whole hazard in one line.
	gen2, err := policy.NewRegistry([]*toolv1.Decl{
		{Name: "billing"}, {Name: "financial"}, {Name: "support"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cat := &catalogue.Catalogue{
		Digest:       aDigest,
		Compartments: gen1,
		Defs: []tool.Def{{
			FullMethod:   route,
			FQN:          fqn,
			Name:         "get_status",
			Input:        message(),
			Output:       message(),
			Verb:         toolv1.Verb_VERB_READ,
			MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			// Gated on support, which this caller does not hold under any
			// reading of its token.
			Compartments: []string{"support"},
		}},
		DescriptorHashes: map[string]string{thePkg: good},
	}

	i := newIDP(t)
	inv := &fakeInvoker{fill: "x"}
	verifier := authn.NewVerifier(authn.Config{
		KeySet:   authn.NewKeySet(authn.KeySetConfig{URL: i.URL}),
		Issuers:  []string{e2eIssuer},
		Audience: "garm",
		// The verifier is a generation ahead of the plane, which is exactly
		// what an independently swappable source makes possible.
		CompartmentSource: authn.NewSwappable(gen2),
	})
	h := authn.Middleware(&Handler{
		Store:      &countingStore{c: cat},
		Invoker:    inv,
		Log:        discardLogger(),
		Principals: authn.PrincipalFunc(verifier, nil),
		HashKey:    []byte("a generation-drift hash key"),
		Recorder:   &record.Memory{},
	})

	token := i.mintGarm(t, map[string]any{
		"clearance":    "CLEARANCE_INTERNAL",
		"kind":         "USER",
		"verbs":        []string{"VERB_READ"},
		"compartments": []string{"financial"},
	}, time.Hour)

	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(""))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code == http.StatusOK {
		t.Errorf("a caller holding only financial passed a support-gated tool: "+
			"its bitset was folded under one generation and read under another (%s)",
			w.Body.String())
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool was invoked %d times for a caller that holds no compartment "+
			"it declares", n)
	}
}
