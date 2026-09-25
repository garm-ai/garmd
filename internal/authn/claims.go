// Package authn turns a signed token into the Principal the tool policy
// chain consumes.
//
// It is deliberately a separate package from toolplane: the policy chain
// takes a Principal through Config.PrincipalFunc and does not care where it
// came from, which is the seam that lets identity be stubbed in tests and
// replaced here without touching enforcement.
package authn

import (
	"fmt"
	"strings"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
)

// GarmClaims is the `garm` claim: the authority an identity asserts.
type GarmClaims struct {
	Clearance    string
	Compartments []string
	Verbs        []string
	ToolSets     []string

	// Kind is what is calling — user, agent or service — normalised to a
	// toolv1.PrincipalKind name, or empty when the token did not say or
	// named one this build does not know.
	//
	// Attribution, never authorization: nothing in the chain reads it. An
	// absent or unknown kind is therefore not an error, the same stance
	// SetLenient takes on an unknown compartment — an IdP that learns a new
	// principal kind before garm does should cost attribution detail, not
	// availability.
	Kind string
}

// Claims is one identity in a delegation chain. Act is the RFC 8693 `act`
// claim — the party acting on this subject's behalf — and nests to whatever
// depth the issuer minted.
type Claims struct {
	Issuer, Subject, Audience, Tenant, ID string
	ExpiresAt, IssuedAt                   time.Time
	Garm                                  GarmClaims
	Act                                   *Claims
}

// Depth counts the subject plus every actor in the chain.
func (c *Claims) Depth() int {
	n := 0
	for cur := c; cur != nil; cur = cur.Act {
		n++
	}
	return n
}

// ParseClaims reads a decoded token body.
//
// Every value arrives as `any` off the wire, so every assertion is comma-ok:
// a type assertion that panics here is a denial of service reachable by
// anyone who can present a token, and this code runs before anything has
// decided whether to trust the caller.
func ParseClaims(raw map[string]any) (*Claims, error) {
	return parseClaims(raw, 0)
}

// maxChainDepth bounds recursion. A token whose `act` nests ten thousand
// deep would otherwise exhaust the stack before verification ever rejected
// it — and the chain fold intersects authority at every level, so a long
// chain cannot grant anything a short one could not.
const maxChainDepth = 16

func parseClaims(raw map[string]any, depth int) (*Claims, error) {
	if depth >= maxChainDepth {
		return nil, fmt.Errorf("act chain deeper than %d; refusing to parse further", maxChainDepth)
	}
	c := &Claims{
		Issuer:   str(raw, "iss"),
		Subject:  str(raw, "sub"),
		Audience: str(raw, "aud"),
		Tenant:   str(raw, "tenant"),
		ID:       str(raw, "jti"),
	}
	c.ExpiresAt = unixTime(raw, "exp")
	c.IssuedAt = unixTime(raw, "iat")

	garmRaw, ok := raw["garm"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("token for %q carries no `garm` claim; "+
			"authority is never inferred", c.Subject)
	}
	clearance, err := normaliseClearance(str(garmRaw, "clearance"))
	if err != nil {
		return nil, fmt.Errorf("token for %q: %w", c.Subject, err)
	}
	c.Garm = GarmClaims{
		Clearance:    clearance,
		Compartments: strSlice(garmRaw, "compartments"),
		Verbs:        strSlice(garmRaw, "verbs"),
		ToolSets:     strSlice(garmRaw, "tool_sets"),
		Kind:         normaliseKind(str(garmRaw, "kind")),
	}

	if actRaw, ok := raw["act"].(map[string]any); ok {
		act, err := parseClaims(actRaw, depth+1)
		if err != nil {
			return nil, err
		}
		c.Act = act
	}
	return c, nil
}

// normaliseClearance accepts the bare and prefixed spellings, because an IdP
// will mint one or the other and both must mean the same thing. An unknown
// or unspecified name is an error rather than a zero value: defaulting here
// would hand an unusable token the lowest clearance silently, which is a
// policy decision disguised as parsing.
// normaliseKind maps a token's `garm.kind` to a PrincipalKind name.
//
// Returns "" for absent, unknown, or UNSPECIFIED. There is no error return
// on purpose: see GarmClaims.Kind.
func normaliseKind(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "PRINCIPAL_KIND_") {
		s = "PRINCIPAL_KIND_" + s
	}
	v, ok := toolv1.PrincipalKind_value[s]
	if !ok || toolv1.PrincipalKind(v) == toolv1.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED {
		return ""
	}
	return s
}

func normaliseClearance(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "", fmt.Errorf("`garm.clearance` is empty")
	}
	if !strings.HasPrefix(s, "CLEARANCE_") {
		s = "CLEARANCE_" + s
	}
	v, ok := toolv1.Clearance_value[s]
	if !ok {
		return "", fmt.Errorf("unknown clearance %q", s)
	}
	if toolv1.Clearance(v) == toolv1.Clearance_CLEARANCE_UNSPECIFIED {
		return "", fmt.Errorf("clearance is UNSPECIFIED; a token must state one")
	}
	return s, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// strSlice tolerates a single string where a list is expected — IdPs differ
// on single-element claims — and drops non-string entries rather than
// failing the whole token on one malformed element.
func strSlice(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

// unixTime reads NumericDate, which arrives as float64 through encoding/json
// and as int64 from some decoders.
func unixTime(m map[string]any, k string) time.Time {
	switch v := m[k].(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC()
	case int64:
		return time.Unix(v, 0).UTC()
	case int:
		return time.Unix(int64(v), 0).UTC()
	}
	return time.Time{}
}
