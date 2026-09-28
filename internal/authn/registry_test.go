package authn_test

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"sync"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
)

func registryOf(t *testing.T, names ...string) *policy.Registry {
	t.Helper()
	decls := make([]*toolv1.Decl, 0, len(names))
	for _, n := range names {
		decls = append(decls, &toolv1.Decl{Name: n})
	}
	reg, err := policy.NewRegistry(decls)
	if err != nil {
		t.Fatalf("building a registry from %v: %v", names, err)
	}
	return reg
}

// swappableHarness is verify_test.go's own harness with the taxonomy behind a
// swappable pointer instead of fixed. Built here rather than by changing
// harness, so every existing test keeps exercising the fixed-registry path
// that the conformance runner and every embedder use.
func swappableHarness(t *testing.T, src *authn.Swappable) (*authn.Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	return authn.NewVerifier(authn.Config{
		KeySet:            authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
		Issuers:           []string{"https://idp.example.com"},
		Audience:          "garm",
		CompartmentSource: src,
		Skew:              30 * time.Second,
	}), key
}

// asserting returns verify_test.go's good token body with these compartments.
func asserting(now time.Time, compartments ...string) map[string]any {
	body := goodBody(now)
	names := make([]any, 0, len(compartments))
	for _, c := range compartments {
		names = append(names, c)
	}
	body["garm"].(map[string]any)["compartments"] = names
	return body
}

// The taxonomy comes from the CATALOGUE, and the catalogue reloads.
//
// A verifier holding the registry it was constructed with dropped every
// compartment a new generation added: tokens asserting the new name lost that
// authority, silently, until someone restarted the process. It failed in the
// safe direction — narrower, never wider — and it failed with nothing to see,
// which is the objectionable half.
func TestASwappedRegistryIsReadByTheNextVerification(t *testing.T) {
	now := time.Now()
	src := authn.NewSwappable(registryOf(t, "financial"))
	v, key := swappableHarness(t, src)
	token := sign(t, key, "k1", asserting(now, "financial", "pii-contact"))

	_, dropped, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "pii-contact" {
		t.Fatalf("dropped = %v, want [pii-contact]: the first generation does not "+
			"declare it", dropped)
	}

	// A new catalogue declares it. Nothing restarts.
	src.Set(registryOf(t, "financial", "pii-contact"))

	p, dropped, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify after the swap: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v after the new generation declared it; the caller is "+
			"still narrower than its token claims", dropped)
	}
	if names := src.Registry().Names(p.Compartments); len(names) != 2 {
		t.Errorf("the principal holds %v, want both compartments", names)
	}
}

// A name no generation declares is still dropped rather than refused. An
// IdP-side typo must cost that caller that compartment, not the whole token —
// a deploy skew between the IdP and the catalogue would otherwise be an
// outage.
func TestAnUndeclaredNameIsStillDroppedAfterASwap(t *testing.T) {
	now := time.Now()
	src := authn.NewSwappable(registryOf(t, "financial"))
	v, key := swappableHarness(t, src)
	src.Set(registryOf(t, "financial", "pii-contact"))

	token := sign(t, key, "k1", asserting(now, "financial", "typo-compartment"))
	_, dropped, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("a token naming an undeclared compartment was refused outright: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "typo-compartment" {
		t.Errorf("dropped = %v, want [typo-compartment]", dropped)
	}
}

// Nil is not a taxonomy. A verifier reading "unconfigured" as "no restrictions"
// is the wrong way round, and Set must not be able to produce that state.
func TestSettingNilLeavesTheRegistryThatWasServing(t *testing.T) {
	reg := registryOf(t, "financial")
	src := authn.NewSwappable(reg)
	src.Set(nil)
	if src.Registry() != reg {
		t.Error("Set(nil) replaced a working taxonomy with nothing, and every token's " +
			"compartments would now be dropped")
	}
}

// A Config with neither a source nor a registry is a verifier that cannot
// resolve a single compartment name. Refusing beats deciding with nothing.
func TestAVerifierWithNoTaxonomyAtAllRefuses(t *testing.T) {
	now := time.Now()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	v := authn.NewVerifier(authn.Config{
		KeySet:   authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
		Issuers:  []string{"https://idp.example.com"},
		Audience: "garm",
	})
	if _, _, err := v.Verify(context.Background(), sign(t, key, "k1", goodBody(now))); err == nil {
		t.Error("a verifier with no compartment taxonomy verified a token")
	}
}

// The reload happens WHILE calls are in flight; that is the whole point of not
// restarting. Under -race this pins that publishing a generation and folding
// against one are not a data race — and the assertion is BEHAVIOURAL, because
// the race detector only sees the word and not the answer.
//
// The two generations put the asserted names on different bits: in genA
// financial=0 and pii-contact=1; in genB billing=0 and financial=1, with
// pii-contact undeclared. So a fold that read one whole generation returns
// either no drops (genA) or exactly [pii-contact] (genB), and anything else —
// a drop of financial, both names dropped, a name neither generation could
// have produced — is a fold that saw a generation nobody published.
func TestSwappingWhileVerifyingIsRaceFree(t *testing.T) {
	now := time.Now()
	genA := registryOf(t, "financial", "pii-contact")
	genB := registryOf(t, "billing", "financial")
	src := authn.NewSwappable(genA)
	v, key := swappableHarness(t, src)
	token := sign(t, key, "k1", asserting(now, "financial", "pii-contact"))

	// One verification first, so the key set is cached and the readers below
	// contend on the registry rather than on the JWKS fetch.
	if _, _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	gens := []*policy.Registry{genA, genB}

	var writer, readers sync.WaitGroup
	stop := make(chan struct{})
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			src.Set(gens[i%len(gens)])
		}
	}()

	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 50; j++ {
				p, dropped, err := v.Verify(context.Background(), token)
				if err != nil {
					t.Errorf("Verify during a swap: %v", err)
					return
				}
				switch {
				case len(dropped) == 0:
					// genA: both names declared, so the principal holds two
					// bits and the registry that folded them says so.
					if got := genA.Names(p.Compartments); len(got) != 2 {
						t.Errorf("nothing was dropped, so both names resolved, "+
							"but the principal holds %v", got)
						return
					}
				case len(dropped) == 1 && dropped[0] == "pii-contact":
					// genB: financial resolved, pii-contact is undeclared
					// there and is dropped rather than refused.
					if got := genB.Names(p.Compartments); len(got) != 1 ||
						got[0] != "financial" {
						t.Errorf("pii-contact was dropped, so this was genB, "+
							"but the principal holds %v under it", got)
						return
					}
				default:
					t.Errorf("dropped = %v: no published generation could have "+
						"produced that, so a fold read a half-installed one", dropped)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}

// The verifier's taxonomy and the CHAIN's taxonomy are two pointers that can
// be on two clocks, and a compartment bitset means nothing away from the
// registry that produced it (policy assigns bits by sorted index, so one
// added declaration renumbers everything after it).
//
// So a request pins one generation: the surface puts the plane's registry on
// the context and the fold uses THAT, whatever the verifier happens to be
// holding. internal/serve/generation_test.go pins the consequence end to end;
// this pins the precedence.
func TestTheContextRegistryWinsOverTheConfiguredSource(t *testing.T) {
	now := time.Now()
	// The verifier's own source declares it. The request's generation does
	// not, and the request is the one that decides.
	src := authn.NewSwappable(registryOf(t, "financial", "pii-contact"))
	v, key := swappableHarness(t, src)
	token := sign(t, key, "k1", asserting(now, "financial", "pii-contact"))

	ctx := authn.WithRegistry(context.Background(), registryOf(t, "financial"))
	_, dropped, err := v.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "pii-contact" {
		t.Fatalf("dropped = %v, want [pii-contact]: the fold used the verifier's "+
			"own generation instead of the request's", dropped)
	}
}

// A context carrying no registry leaves the configured source deciding, so
// every caller with no plane — the conformance runner, an embedder — is
// untouched by the context path existing.
func TestNoContextRegistryFallsBackToTheConfiguredSource(t *testing.T) {
	now := time.Now()
	src := authn.NewSwappable(registryOf(t, "financial", "pii-contact"))
	v, key := swappableHarness(t, src)
	token := sign(t, key, "k1", asserting(now, "financial", "pii-contact"))

	if _, dropped, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: %v", err)
	} else if len(dropped) != 0 {
		t.Errorf("dropped = %v from a source declaring both names", dropped)
	}
}

// Two taxonomies on one Config is a question with no good answer. Documenting
// which wins is not the same as making the other one impossible, and a Config
// carrying both is a caller who believes something untrue about their own
// deployment — which is worth refusing rather than resolving.
func TestAConfigSettingBothTaxonomiesIsRefused(t *testing.T) {
	now := time.Now()
	key, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	v := authn.NewVerifier(authn.Config{
		KeySet:            authn.NewKeySet(authn.KeySetConfig{URL: srv.URL}),
		Issuers:           []string{"https://idp.example.com"},
		Audience:          "garm",
		Compartments:      registryOf(t, "financial"),
		CompartmentSource: authn.NewSwappable(registryOf(t, "financial")),
	})
	_, _, err := v.Verify(context.Background(), sign(t, key, "k1", goodBody(now)))
	if err == nil {
		t.Fatal("a Config naming two taxonomies verified a token; one of them is " +
			"being ignored and the operator has no way to know which")
	}
	if !strings.Contains(err.Error(), "CompartmentSource") {
		t.Errorf("the refusal does not name the conflicting fields: %v", err)
	}
}
