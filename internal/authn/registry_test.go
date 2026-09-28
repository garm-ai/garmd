package authn_test

import (
	"context"
	"crypto/ecdsa"
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
// against one are not a data race, and that every fold sees some whole
// generation rather than a half-installed one: both registries here declare
// "financial", so a verification that observed neither would drop it.
func TestSwappingWhileVerifyingIsRaceFree(t *testing.T) {
	now := time.Now()
	src := authn.NewSwappable(registryOf(t, "financial"))
	v, key := swappableHarness(t, src)
	token := sign(t, key, "k1", asserting(now, "financial"))

	// One verification first, so the key set is cached and the readers below
	// contend on the registry rather than on the JWKS fetch.
	if _, _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Both generations are built on this goroutine: registryOf calls
	// t.Fatalf, which may only be called from the goroutine running the test.
	gens := []*policy.Registry{
		registryOf(t, "financial", "pii-contact"),
		registryOf(t, "financial", "support"),
	}

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
				p, _, err := v.Verify(context.Background(), token)
				if err != nil {
					t.Errorf("Verify during a swap: %v", err)
					return
				}
				if p.Compartments == 0 {
					t.Error("a fold during a swap saw no taxonomy at all")
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}
