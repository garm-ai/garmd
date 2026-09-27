package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/garm-ai/garmd/internal/conformance"
	jose "github.com/go-jose/go-jose/v4"
)

// fakeMinter is an in-process stand-in. It cannot be devkit: garmd may not
// import a minter, which is the constraint this whole package works around.
type fakeMinter struct {
	key    *ecdsa.PrivateKey
	bodies map[string]map[string]any // mint["user"] -> token body
	refuse map[string]bool
}

func (f *fakeMinter) Token(_ context.Context, params map[string]string) (string, error) {
	k := params["user"]
	if f.refuse[k] {
		return "", fmt.Errorf("minter refused %q", k)
	}
	body, ok := f.bodies[k]
	if !ok {
		return "", fmt.Errorf("no persona %q", k)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(body)
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// jwksFor serves the public half of key.
func jwksFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: key.Public(), KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func body(now time.Time, sub, clearance string, comps, verbs []any, act map[string]any) map[string]any {
	b := map[string]any{
		"iss": "https://minter.test", "sub": sub, "aud": []any{"garm"},
		"jti": "t-" + sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"garm": map[string]any{
			"clearance": clearance, "compartments": comps,
			"verbs": verbs, "kind": "USER",
		},
	}
	if act != nil {
		b["act"] = act
	}
	return b
}

func TestRunPassesWhenTheFoldMatches(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_RESTRICTED",
			[]any{"financial", "pii-contact"}, []any{"READ", "WRITE"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial", "pii-contact", "support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Kind: "PRINCIPAL_KIND_USER",
				Clearance:    "CLEARANCE_RESTRICTED",
				Compartments: []string{"pii-contact", "financial"}, // order must not matter
				Verbs:        []string{"VERB_READ", "VERB_WRITE"},
			},
		}},
	}

	res, err := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("expected a pass, got %+v", res)
	}
}

func TestRunReportsAMismatchedFold(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_INTERNAL",
			[]any{"support"}, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"financial", "pii-contact", "support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_RESTRICTED",
				Compartments: []string{"support"}, Verbs: []string{"VERB_READ"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("a minter emitting INTERNAL passed a case expecting RESTRICTED")
	}
	if !strings.Contains(res[0].Err.Error(), "clearance") {
		t.Fatalf("the error must name the field that disagreed: %v", res[0].Err)
	}
}

// Review Focus 3. An unreachable minter must FAIL the case, never skip it.
func TestRunFailsWhenTheMinterIsUnreachable(t *testing.T) {
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{}} // knows nobody
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "alice direct", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{Clearance: "CLEARANCE_PUBLIC"},
		}},
	}

	res, err := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if err != nil {
		t.Fatalf("an unreachable minter is a case failure, not a run failure: %v", err)
	}
	if len(res) != 1 || res[0].Err == nil {
		t.Fatal("an unreachable minter produced no failure; the run would report ok")
	}
}

func TestRunHonoursMintError(t *testing.T) {
	key := newECKey(t)
	m := &fakeMinter{key: key, refuse: map[string]bool{"alice": true}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a refusal the suite expected was reported as a failure: %v", res[0].Err)
	}
}

func TestRunFailsWhenAnExpectedRefusalSucceeds(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_PUBLIC", nil, []any{"READ"}, nil),
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{
			{Name: "should be refused", Mint: map[string]string{"user": "alice"}, MintError: true},
		},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err == nil {
		t.Fatal("the minter granted a delegation the suite says it must refuse")
	}
}

// Review Focus 4. The drop list is part of the contract.
func TestRunAssertsDroppedCompartments(t *testing.T) {
	now := time.Now()
	key := newECKey(t)
	m := &fakeMinter{key: key, bodies: map[string]map[string]any{
		"alice": body(now, "user:alice", "CLEARANCE_INTERNAL",
			[]any{"support", "finance"}, []any{"READ"}, nil), // `finance` is a typo
	}}
	s := &conformance.Suite{
		Issuer: "https://minter.test", Audience: "garm",
		Compartments: []string{"support"},
		Cases: []conformance.Case{{
			Name: "typo is dropped", Mint: map[string]string{"user": "alice"},
			Expect: &conformance.Expect{
				Subject: "user:alice", Clearance: "CLEARANCE_INTERNAL",
				Compartments: []string{"support"}, Verbs: []string{"VERB_READ"},
				Dropped: []string{"finance"},
			},
		}},
	}

	res, _ := conformance.Run(context.Background(), s, m, jwksFor(t, key))
	if res[0].Err != nil {
		t.Fatalf("a correctly-dropped compartment was reported as a failure: %v", res[0].Err)
	}
}
