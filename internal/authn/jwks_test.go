package authn_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/garm-ai/garmd/internal/authn"
)

// newKey returns an ECDSA signing key and its JWK, tagged with kid.
func newKey(t *testing.T, kid string) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k, jose.JSONWebKey{Key: k.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}
}

// jwksServer serves a key set and counts how many times it was fetched, so a
// test can assert on refresh behaviour rather than on timing.
type jwksServer struct {
	*httptest.Server
	hits atomic.Int64
	keys atomic.Pointer[jose.JSONWebKeySet]
	fail atomic.Bool
}

func newJWKSServer(t *testing.T, keys ...jose.JSONWebKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.keys.Store(&jose.JSONWebKeySet{Keys: keys})
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "the IdP is having a moment", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(s.keys.Load())
	}))
	t.Cleanup(s.Close)
	return s
}

func TestKeySetServesFromCacheWithoutRefetching(t *testing.T) {
	_, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	ks := authn.NewKeySet(authn.KeySetConfig{URL: srv.URL})

	for i := 0; i < 3; i++ {
		if _, err := ks.Key(context.Background(), "k1"); err != nil {
			t.Fatalf("Key(k1) attempt %d: %v", i, err)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("fetched the key set %d times for three lookups of a cached kid; want 1", got)
	}
}

// The property that keeps /readyz green through a blip: a key set already
// fetched and still inside its TTL is served without touching the IdP, so an
// IdP outage is invisible until the TTL runs out.
func TestKeySetServesThroughATransientOutage(t *testing.T) {
	_, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	ks := authn.NewKeySet(authn.KeySetConfig{URL: srv.URL, TTL: time.Hour})

	if _, err := ks.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}
	srv.fail.Store(true)

	if _, err := ks.Key(context.Background(), "k1"); err != nil {
		t.Errorf("a cached, unexpired key stopped verifying during an IdP outage: %v", err)
	}
}

// The other half, and the one that must not fail open: once the cache is
// stale, an unreachable IdP is a hard failure. Serving an older key because
// the refresh failed would keep a revoked key working exactly when it matters.
func TestKeySetRefusesWhenTheCacheIsStaleAndTheRefreshFails(t *testing.T) {
	_, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	now := time.Now()
	ks := authn.NewKeySet(authn.KeySetConfig{
		URL: srv.URL, TTL: time.Minute,
		Now: func() time.Time { return now },
	})

	if _, err := ks.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}
	now = now.Add(2 * time.Minute) // TTL elapsed
	srv.fail.Store(true)

	if _, err := ks.Key(context.Background(), "k1"); err == nil {
		t.Error("a stale cache plus a failed refresh returned a key; it must fail closed " +
			"rather than keep serving a key the IdP may have revoked")
	}
}

// A token carrying a garbage kid must not turn into unbounded IdP traffic:
// one refetch per cooldown window, however many bad tokens arrive.
func TestUnknownKidRefetchesAtMostOncePerWindow(t *testing.T) {
	_, jwk := newKey(t, "k1")
	srv := newJWKSServer(t, jwk)
	now := time.Now()
	ks := authn.NewKeySet(authn.KeySetConfig{
		URL: srv.URL, TTL: time.Hour, RefreshCooldown: time.Minute,
		Now: func() time.Time { return now },
	})
	if _, err := ks.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}
	before := srv.hits.Load()

	for i := 0; i < 20; i++ {
		if _, err := ks.Key(context.Background(), "attacker-supplied"); err == nil {
			t.Fatal("an unknown kid returned a key")
		}
	}
	if extra := srv.hits.Load() - before; extra > 1 {
		t.Errorf("20 lookups of an unknown kid caused %d refetches; want at most 1 "+
			"— otherwise a garbage kid is a way to hammer the IdP", extra)
	}
}

// Key rotation has to work, or the cooldown above would be a denial of
// service against ourselves: once the window passes, a genuinely new kid is
// picked up.
func TestUnknownKidIsFoundAfterTheWindowPasses(t *testing.T) {
	_, k1 := newKey(t, "k1")
	srv := newJWKSServer(t, k1)
	now := time.Now()
	ks := authn.NewKeySet(authn.KeySetConfig{
		URL: srv.URL, TTL: time.Hour, RefreshCooldown: time.Minute,
		Now: func() time.Time { return now },
	})
	if _, err := ks.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}
	if _, err := ks.Key(context.Background(), "k2"); err == nil {
		t.Fatal("k2 resolved before it was published")
	}

	_, k2 := newKey(t, "k2")
	srv.keys.Store(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k1, k2}})
	now = now.Add(2 * time.Minute)

	if _, err := ks.Key(context.Background(), "k2"); err != nil {
		t.Errorf("a rotated-in key was not picked up after the cooldown: %v", err)
	}
}
