package authn_test

import (
	"testing"

	"github.com/garm-ai/garmd/internal/authn"
)

func TestParseClaimsReadsNestedActChain(t *testing.T) {
	raw := map[string]any{
		"iss":    "https://idp.acme.internal",
		"sub":    "user:ada@acme.com",
		"aud":    "garm://tools",
		"jti":    "01JBX",
		"tenant": "acme",
		"garm": map[string]any{
			"clearance":    "CONFIDENTIAL",
			"compartments": []any{"pii-contact", "support"},
			"verbs":        []any{"READ", "WRITE"},
		},
		"act": map[string]any{
			"sub": "agent:support-copilot",
			"garm": map[string]any{
				"clearance":    "INTERNAL",
				"compartments": []any{"support"},
				"verbs":        []any{"READ"},
			},
			"act": map[string]any{
				"sub":  "svc:orchestrator",
				"garm": map[string]any{"clearance": "INTERNAL", "verbs": []any{"READ"}},
			},
		},
	}

	c, err := authn.ParseClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user:ada@acme.com" || c.Tenant != "acme" {
		t.Fatalf("top-level claims: %+v", c)
	}
	if c.Act == nil || c.Act.Subject != "agent:support-copilot" {
		t.Fatalf("first actor: %+v", c.Act)
	}
	if c.Act.Act == nil || c.Act.Act.Subject != "svc:orchestrator" {
		t.Fatalf("second actor: %+v", c.Act)
	}
	if got := c.Depth(); got != 3 {
		t.Fatalf("Depth() = %d, want 3 (subject + two actors)", got)
	}
}

func TestParseClaimsRejectsMissingOrUnspecifiedClearance(t *testing.T) {
	for name, garm := range map[string]any{
		"no garm claim":         nil,
		"empty garm claim":      map[string]any{},
		"unspecified clearance": map[string]any{"clearance": "CLEARANCE_UNSPECIFIED"},
		"unknown clearance":     map[string]any{"clearance": "SECRET"},
		"empty string":          map[string]any{"clearance": ""},
	} {
		raw := map[string]any{"sub": "user:x"}
		if garm != nil {
			raw["garm"] = garm
		}
		if _, err := authn.ParseClaims(raw); err == nil {
			t.Fatalf("%s: accepted; an unusable clearance must be rejected, never defaulted", name)
		}
	}
}

func TestParseClaimsAcceptsBareAndPrefixedClearanceNames(t *testing.T) {
	// IdPs will mint one or the other; both must work, and they must agree.
	for _, s := range []string{"CONFIDENTIAL", "CLEARANCE_CONFIDENTIAL"} {
		c, err := authn.ParseClaims(map[string]any{
			"sub":  "user:x",
			"garm": map[string]any{"clearance": s},
		})
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if c.Garm.Clearance != "CLEARANCE_CONFIDENTIAL" {
			t.Fatalf("%q normalised to %q", s, c.Garm.Clearance)
		}
	}
}

// A token is attacker-supplied input parsed before anything has decided to
// trust the caller, so the two ways parsing itself can be a denial of
// service both need pinning.

// An `act` chain nested arbitrarily deep would exhaust the stack before
// verification ever rejected the token. Depth is bounded, and the bound
// costs nothing real: the chain fold INTERSECTS authority at every level,
// so a long chain can never grant what a short one could not.
func TestParseClaimsRefusesAnUnboundedActChain(t *testing.T) {
	leaf := map[string]any{"sub": "svc:leaf", "garm": map[string]any{"clearance": "INTERNAL"}}
	for i := 0; i < 5000; i++ {
		leaf = map[string]any{"sub": "svc:x", "garm": map[string]any{"clearance": "INTERNAL"}, "act": leaf}
	}
	if _, err := authn.ParseClaims(leaf); err == nil {
		t.Fatal("accepted a 5000-deep act chain")
	}
}

// Every value off the wire is `any`. A type assertion without comma-ok
// panics on a hostile token, which is a crash anyone holding a token can
// trigger. Nothing here may panic — an error is the only acceptable
// outcome for garbage.
func TestParseClaimsNeverPanicsOnHostileShapes(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"garm is a string":      {"sub": "u", "garm": "CONFIDENTIAL"},
		"garm is a list":        {"sub": "u", "garm": []any{"x"}},
		"clearance is a number": {"sub": "u", "garm": map[string]any{"clearance": 3}},
		"compartments is a map": {"sub": "u", "garm": map[string]any{"clearance": "INTERNAL", "compartments": map[string]any{"a": 1}}},
		"compartments mixed":    {"sub": "u", "garm": map[string]any{"clearance": "INTERNAL", "compartments": []any{"ok", 7, nil}}},
		"act is a string":       {"sub": "u", "garm": map[string]any{"clearance": "INTERNAL"}, "act": "nope"},
		"sub is a number":       {"sub": 42, "garm": map[string]any{"clearance": "INTERNAL"}},
		"exp is a string":       {"sub": "u", "exp": "soon", "garm": map[string]any{"clearance": "INTERNAL"}},
		"empty":                 {},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on hostile input: %v", r)
				}
			}()
			_, _ = authn.ParseClaims(raw) // error is fine; a panic is not
		})
	}
}

// A single string where a list is expected is a real IdP difference, not
// hostility, and must not fail the token.
func TestParseClaimsAcceptsAScalarCompartment(t *testing.T) {
	c, err := authn.ParseClaims(map[string]any{
		"sub":  "user:x",
		"garm": map[string]any{"clearance": "INTERNAL", "compartments": "support"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Garm.Compartments) != 1 || c.Garm.Compartments[0] != "support" {
		t.Fatalf("got %+v", c.Garm.Compartments)
	}
}

// Kind is attribution, not authorization: a token that omits it is still a
// perfectly good token. Refusing one would break every token minted before
// this field existed, to gain nothing — nothing in the chain reads it.
func TestKindDefaultsToUnspecifiedAndIsNeverFatal(t *testing.T) {
	c, err := authn.ParseClaims(map[string]any{
		"sub": "alice",
		"garm": map[string]any{
			"clearance": "CLEARANCE_INTERNAL",
		},
	})
	if err != nil {
		t.Fatalf("a token with no kind was refused: %v", err)
	}
	if c.Garm.Kind != "" {
		t.Errorf("Kind = %q, want empty for a token that did not say", c.Garm.Kind)
	}
}

func TestKindIsNormalisedLikeClearance(t *testing.T) {
	for _, in := range []string{"agent", "AGENT", "PRINCIPAL_KIND_AGENT", " Agent "} {
		c, err := authn.ParseClaims(map[string]any{
			"sub":  "bot",
			"garm": map[string]any{"clearance": "CLEARANCE_INTERNAL", "kind": in},
		})
		if err != nil {
			t.Fatalf("kind %q was refused: %v", in, err)
		}
		if c.Garm.Kind != "PRINCIPAL_KIND_AGENT" {
			t.Errorf("kind %q normalised to %q, want PRINCIPAL_KIND_AGENT", in, c.Garm.Kind)
		}
	}
}

// An unknown kind is dropped, not fatal — the same stance SetLenient takes on
// an unknown compartment. An IdP that learns a new principal kind before garm
// does should cost attribution detail, not availability.
func TestAnUnknownKindIsDroppedNotFatal(t *testing.T) {
	c, err := authn.ParseClaims(map[string]any{
		"sub":  "thing",
		"garm": map[string]any{"clearance": "CLEARANCE_INTERNAL", "kind": "WORKFLOW"},
	})
	if err != nil {
		t.Fatalf("an unknown kind was fatal: %v", err)
	}
	if c.Garm.Kind != "" {
		t.Errorf("Kind = %q, want empty for a kind this build does not know", c.Garm.Kind)
	}
}
