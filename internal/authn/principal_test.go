package authn_test

import (
	"strings"
	"testing"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garm/policy"
)

type claimLevel struct {
	sub          string
	clearance    string
	compartments []string
	verbs        []string
}

// chainClaims builds a delegation chain outermost-first: the first level is
// the subject, each subsequent level is an actor acting on its behalf.
func chainClaims(levels ...claimLevel) *authn.Claims {
	var head, prev *authn.Claims
	for _, l := range levels {
		c := &authn.Claims{
			Subject: l.sub,
			Garm: authn.GarmClaims{
				Clearance:    "CLEARANCE_" + l.clearance,
				Compartments: l.compartments,
				Verbs:        l.verbs,
			},
		}
		if prev == nil {
			head = c
		} else {
			prev.Act = c
		}
		prev = c
	}
	return head
}

func testRegistry(t *testing.T) *policy.Registry {
	t.Helper()
	decls := make([]*toolv1.Decl, 0, 3)
	for _, n := range []string{"financial", "pii-contact", "support"} {
		decls = append(decls, &toolv1.Decl{Name: n})
	}
	reg, err := policy.NewRegistry(decls)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestFoldIntersectsTheChain(t *testing.T) {
	reg := testRegistry(t)
	c := chainClaims(
		claimLevel{"user:ada", "CONFIDENTIAL", []string{"pii-contact", "support"}, []string{"READ", "WRITE"}},
		claimLevel{"agent:copilot", "INTERNAL", []string{"support"}, []string{"READ"}},
	)

	p, dropped, err := authn.Fold(c, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if p.Clearance != toolv1.Clearance_CLEARANCE_INTERNAL {
		t.Fatalf("clearance = %v, want the MINIMUM over the chain", p.Clearance)
	}
	if names := reg.Names(p.Compartments); len(names) != 1 || names[0] != "support" {
		t.Fatalf("compartments = %v, want the INTERSECTION", names)
	}
	if !p.Verbs.Has(toolv1.Verb_VERB_READ) || p.Verbs.Has(toolv1.Verb_VERB_WRITE) {
		t.Fatal("verbs must be the intersection; WRITE was not held by the actor")
	}
	if p.Subject != "user:ada" || p.Actor != "agent:copilot" {
		t.Fatalf("subject/actor: %q / %q", p.Subject, p.Actor)
	}
	if len(p.Chain) != 2 {
		t.Fatalf("Chain = %v, want both identities recorded for the ledger", p.Chain)
	}
}

// The property that matters more than any single example: adding a hop can
// never widen authority, whatever the added hop claims.
func TestFoldNeverWidens(t *testing.T) {
	reg := testRegistry(t)
	base := chainClaims(claimLevel{"user:ada", "INTERNAL", []string{"support"}, []string{"READ"}})
	basePrincipal, _, err := authn.Fold(base, reg)
	if err != nil {
		t.Fatal(err)
	}

	greedy := chainClaims(
		claimLevel{"user:ada", "INTERNAL", []string{"support"}, []string{"READ"}},
		claimLevel{"agent:greedy", "RESTRICTED",
			[]string{"financial", "pii-contact", "support"},
			[]string{"READ", "WRITE", "DESTRUCTIVE"}},
	)
	got, _, err := authn.Fold(greedy, reg)
	if err != nil {
		t.Fatal(err)
	}
	if int32(got.Clearance) > int32(basePrincipal.Clearance) {
		t.Fatal("a greedy actor raised the effective clearance")
	}
	if got.Compartments&^basePrincipal.Compartments != 0 {
		t.Fatal("a greedy actor added compartments")
	}
	if got.Verbs&^basePrincipal.Verbs != 0 {
		t.Fatal("a greedy actor added verbs")
	}
}

// A delegation chain is a blast radius. Four levels is the documented
// ceiling; a fifth is refused rather than folded, because a token that deep
// is far likelier to be a confused-deputy loop than a real workflow.
func TestFoldRejectsChainDeeperThanFour(t *testing.T) {
	reg := testRegistry(t)
	five := chainClaims(
		claimLevel{"user:ada", "INTERNAL", []string{"support"}, []string{"READ"}},
		claimLevel{"agent:a", "INTERNAL", []string{"support"}, []string{"READ"}},
		claimLevel{"agent:b", "INTERNAL", []string{"support"}, []string{"READ"}},
		claimLevel{"agent:c", "INTERNAL", []string{"support"}, []string{"READ"}},
		claimLevel{"agent:d", "INTERNAL", []string{"support"}, []string{"READ"}},
	)
	_, _, err := authn.Fold(five, reg)
	if err == nil {
		t.Fatal("a five-deep chain was folded")
	}
	if !strings.Contains(err.Error(), "4") {
		t.Errorf("error does not name the limit: %v", err)
	}
}

func TestFoldDropsUnknownCompartmentsAndReportsThem(t *testing.T) {
	// An IdP typo must cost that caller access, not cause an outage.
	reg := testRegistry(t)
	c := chainClaims(claimLevel{"user:ada", "INTERNAL", []string{"support", "finance"}, []string{"READ"}})
	p, dropped, err := authn.Fold(c, reg)
	if err != nil {
		t.Fatalf("an unknown compartment must not fail the token: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "finance" {
		t.Fatalf("dropped = %v, want [finance] recorded for the ledger", dropped)
	}
	if names := reg.Names(p.Compartments); len(names) != 1 || names[0] != "support" {
		t.Fatalf("compartments = %v; the unknown one must be absent, the known one kept", names)
	}
}

// A direct token has no actor, and Chain still records the one identity.
func TestFoldDirectTokenHasNoActor(t *testing.T) {
	reg := testRegistry(t)
	p, _, err := authn.Fold(chainClaims(
		claimLevel{"user:ada", "INTERNAL", []string{"support"}, []string{"READ"}}), reg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Actor != "" {
		t.Errorf("Actor = %q, want empty for a direct token", p.Actor)
	}
	if len(p.Chain) != 1 || p.Chain[0] != "user:ada" {
		t.Errorf("Chain = %v", p.Chain)
	}
}

// The folded principal's Kind describes the SUBJECT — whose authority is
// being exercised — not the actor exercising it. Actor is a separate field
// and the chain records the rest.
func TestFoldTakesTheSubjectsKind(t *testing.T) {
	reg := testRegistry(t)
	claims := &authn.Claims{
		Subject: "alice",
		Garm:    authn.GarmClaims{Clearance: "CLEARANCE_CONFIDENTIAL", Kind: "PRINCIPAL_KIND_USER"},
		Act: &authn.Claims{
			Subject: "triage-bot",
			Garm:    authn.GarmClaims{Clearance: "CLEARANCE_INTERNAL", Kind: "PRINCIPAL_KIND_AGENT"},
		},
	}

	p, _, err := authn.Fold(claims, reg)
	if err != nil {
		t.Fatalf("Fold: %v", err)
	}
	if p.Kind != toolv1.PrincipalKind_PRINCIPAL_KIND_USER {
		t.Errorf("Kind = %v, want USER: the authority being exercised is alice's, "+
			"and the agent exercising it is recorded as Actor", p.Kind)
	}
	if p.Actor != "triage-bot" {
		t.Errorf("Actor = %q, want triage-bot", p.Actor)
	}
	// And folding still narrows: the agent's lower clearance wins.
	if p.Clearance != toolv1.Clearance_CLEARANCE_INTERNAL {
		t.Errorf("Clearance = %v, want INTERNAL", p.Clearance)
	}
}

// Kind must not become an authorization input by accident. This pins that a
// principal with no kind is otherwise identical to one with a kind — if a
// future change makes the chain read it, this fails.
func TestKindDoesNotAffectAuthority(t *testing.T) {
	reg := testRegistry(t)
	base := func(kind string) *authn.Claims {
		return &authn.Claims{
			Subject: "x",
			Garm: authn.GarmClaims{
				Clearance:    "CLEARANCE_CONFIDENTIAL",
				Compartments: []string{"financial"},
				Verbs:        []string{"VERB_READ"},
				Kind:         kind,
			},
		}
	}
	withKind, _, err := authn.Fold(base("PRINCIPAL_KIND_AGENT"), reg)
	if err != nil {
		t.Fatal(err)
	}
	without, _, err := authn.Fold(base(""), reg)
	if err != nil {
		t.Fatal(err)
	}
	if withKind.Clearance != without.Clearance ||
		withKind.Compartments != without.Compartments ||
		withKind.Verbs != without.Verbs {
		t.Error("kind changed the principal's authority; it is attribution and must " +
			"never gate anything, or there are two vocabularies to consult when a " +
			"call is refused")
	}
}

// Consistent with the rest of folding: a delegated session cannot widen the
// sets its delegator scoped it to.
func TestToolSetsFoldByIntersectionAcrossTheChain(t *testing.T) {
	reg := testRegistry(t)

	for _, tc := range []struct {
		name      string
		user, bot []string
		want      []string
		wantNil   bool
	}{
		{name: "both scoped: intersection", user: []string{"a", "b"}, bot: []string{"b", "c"}, want: []string{"b"}},
		{name: "user unscoped: the agent's scope stands", user: nil, bot: []string{"b"}, want: []string{"b"}},
		{name: "agent unscoped: no widening, no narrowing", user: []string{"a"}, bot: nil, want: []string{"a"}},
		{name: "neither scoped: unscoped", user: nil, bot: nil, wantNil: true},
		{name: "disjoint: nothing, not everything", user: []string{"a"}, bot: []string{"z"}, want: []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, err := authn.Fold(&authn.Claims{
				Subject: "u",
				Garm:    authn.GarmClaims{Clearance: "CLEARANCE_INTERNAL", ToolSets: tc.user},
				Act: &authn.Claims{
					Subject: "bot",
					Garm:    authn.GarmClaims{Clearance: "CLEARANCE_INTERNAL", ToolSets: tc.bot},
				},
			}, reg)
			if err != nil {
				t.Fatalf("Fold: %v", err)
			}
			if tc.wantNil {
				if p.ToolSets != nil {
					t.Errorf("ToolSets = %v, want nil (unscoped)", p.ToolSets)
				}
				return
			}
			if len(p.ToolSets) != len(tc.want) {
				t.Fatalf("ToolSets = %v, want %v", p.ToolSets, tc.want)
			}
			for i, want := range tc.want {
				if p.ToolSets[i] != want {
					t.Errorf("ToolSets = %v, want %v", p.ToolSets, tc.want)
				}
			}
			if len(tc.want) == 0 && p.ToolSets == nil {
				t.Error("two disjoint scopes produced nil, which means UNSCOPED — " +
					"a session scoped to sets it is not entitled to must reach nothing, " +
					"not everything")
			}
		})
	}
}

// Same stance as an unknown compartment: it costs that caller reach and does
// not fail the token. Here it is self-enforcing — an undeclared name matches
// no tool — which is better than a check something has to remember.
func TestAnUndeclaredSetInAClaimIsNotFatal(t *testing.T) {
	p, _, err := authn.Fold(&authn.Claims{
		Subject: "u",
		Garm: authn.GarmClaims{
			Clearance: "CLEARANCE_INTERNAL",
			ToolSets:  []string{"a-set-this-build-never-declared"},
		},
	}, testRegistry(t))
	if err != nil {
		t.Fatalf("an undeclared tool set failed the token: %v", err)
	}
	if len(p.ToolSets) != 1 {
		t.Errorf("ToolSets = %v; the name is carried and simply matches nothing", p.ToolSets)
	}
}
