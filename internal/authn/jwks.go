package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Why a dependency here, and only here.
//
// This package decides who anyone is, so every import is supply-chain surface
// on the most sensitive component in the build. go-jose is taken for the JOSE
// primitives — JWK parsing and JWS verification — and nothing else. Those are
// the parts where a hand-rolled version is not 150 lines of fetch-and-cache
// but a from-scratch implementation of signature verification, and a subtle
// mistake there is silent and total.
//
// What is NOT delegated is everything in this file: caching, refresh, rate
// limiting and the failure semantics. Those are policy, they are where this
// system's requirements live (serve through an outage, fail closed when
// stale, never let a garbage kid become IdP traffic), and a library's
// defaults for them are somebody else's risk appetite.

const (
	defaultTTL             = 10 * time.Minute
	defaultRefreshCooldown = 1 * time.Minute
	// A key set is small. This bounds a hostile or broken endpoint that
	// would otherwise stream until memory ran out, before any parsing.
	maxKeySetBytes = 1 << 20
)

// KeySetConfig configures a KeySet. Only URL is required.
type KeySetConfig struct {
	URL string

	// TTL is how long a fetched key set is served without refetching.
	// Past it, a lookup must refresh, and a failed refresh is an error
	// rather than a fallback to the keys already held.
	TTL time.Duration

	// RefreshCooldown is the minimum interval between refetches triggered
	// by an unknown kid. It is what stops a token with a garbage kid from
	// turning into unbounded traffic at the IdP.
	RefreshCooldown time.Duration

	HTTPClient *http.Client
	Now        func() time.Time
}

// KeySet is a cached JWKS, addressed by `kid`.
//
// Safe for concurrent use. The lock is held across the HTTP fetch
// deliberately: a thundering herd of requests arriving on a cold or stale
// cache should produce ONE fetch, and the alternative — release, fetch,
// re-acquire — produces one fetch per goroutine at exactly the moment the
// IdP is least able to serve them.
type KeySet struct {
	url             string
	http            *http.Client
	ttl             time.Duration
	refreshCooldown time.Duration
	now             func() time.Time

	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

func NewKeySet(cfg KeySetConfig) *KeySet {
	ks := &KeySet{
		url:             cfg.URL,
		http:            cfg.HTTPClient,
		ttl:             cfg.TTL,
		refreshCooldown: cfg.RefreshCooldown,
		now:             cfg.Now,
	}
	if ks.http == nil {
		ks.http = &http.Client{Timeout: 10 * time.Second}
	}
	if ks.ttl == 0 {
		ks.ttl = defaultTTL
	}
	if ks.refreshCooldown == 0 {
		ks.refreshCooldown = defaultRefreshCooldown
	}
	if ks.now == nil {
		ks.now = time.Now
	}
	return ks
}

// Key returns the key published under kid.
//
// Three cases, and the difference between them is the whole point:
//
//   - kid is held and the set is fresh: served from cache, no network. This
//     is what keeps verification working through a transient IdP outage.
//   - the set is stale: refresh, and a failed refresh is an ERROR. Serving a
//     key the IdP may have revoked because we could not reach it is the one
//     failure mode this must not have.
//   - kid is unknown: refresh at most once per cooldown window, so a token
//     carrying a garbage kid cannot be used to hammer the IdP, while a
//     genuinely rotated-in key is still picked up within the window.
func (k *KeySet) Key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	fresh := k.keys != nil && k.now().Sub(k.fetchedAt) < k.ttl

	if fresh {
		if key, ok := k.keys[kid]; ok {
			return key, nil
		}
		// Unknown kid against a fresh set: either a rotation we have not
		// seen, or a token we will reject. Rate-limit the difference.
		if k.now().Sub(k.lastAttempt) < k.refreshCooldown {
			return jose.JSONWebKey{}, fmt.Errorf("authn: no key %q in the key set", kid)
		}
	}

	if err := k.refreshLocked(ctx); err != nil {
		return jose.JSONWebKey{}, err
	}
	key, ok := k.keys[kid]
	if !ok {
		return jose.JSONWebKey{}, fmt.Errorf("authn: no key %q in the key set", kid)
	}
	return key, nil
}

func (k *KeySet) refreshLocked(ctx context.Context) error {
	k.lastAttempt = k.now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return fmt.Errorf("authn: building the key set request: %w", err)
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return fmt.Errorf("authn: fetching the key set: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authn: fetching the key set: %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return fmt.Errorf("authn: reading the key set: %w", err)
	}
	if len(body) > maxKeySetBytes {
		return fmt.Errorf("authn: key set larger than %d bytes", maxKeySetBytes)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("authn: parsing the key set: %w", err)
	}
	if len(set.Keys) == 0 {
		// An empty set is not a valid state to cache: it would make every
		// token fail with "no key" until the TTL expired, and it usually
		// means the endpoint is wrong rather than that the IdP has no keys.
		return fmt.Errorf("authn: the key set at %s contains no keys", k.url)
	}

	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, key := range set.Keys {
		if key.KeyID == "" {
			// Without a kid there is nothing to address the key by, and
			// trying every key in turn is how algorithm-confusion bugs get
			// their opening. Skip it rather than guess.
			continue
		}
		keys[key.KeyID] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("authn: no key in the set at %s carries a kid", k.url)
	}

	k.keys = keys
	k.fetchedAt = k.now()
	return nil
}
