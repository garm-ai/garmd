package serve

import (
	"net/http"
	"os"
	"slices"
	"testing"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// What a caller is OFFERED, as against what it may call.
//
// A tool set says who HOLDS a tool. It cannot say what a tool is FOR, and
// that is the question a person's client has to answer: `get_balance` is a
// tool plenty of people's claims reach and nobody should ever be shown a form
// for. So the tool declares its audience, and `ListTools` takes the one it is
// asking for.
//
// The rule is an AND and neither half is new: a tool is listed when its
// audience admits the asked-for one AND the caller's own claims reach it,
// which is step 2's predicate, unchanged. Everything below is one of those
// two halves.

// audienceHandler mounts testdata/audience.proto through the REAL loader,
// against a tool.proto this binary is older than. Building a
// catalogue.Catalogue by hand would skip the descriptors the audience is read
// out of and prove nothing.
func audienceHandler(t *testing.T, p *toolplane.Principal) *Handler {
	t.Helper()
	cat := fixtureCatalogue(t, map[string]string{
		"garm/tool/v1/tool.proto":         readServeTestdata(t, "testdata/tool.proto"),
		"bank/payments/v1/audience.proto": readServeTestdata(t, "testdata/audience.proto"),
	}, "garm/tool/v1/tool.proto", "bank/payments/v1/audience.proto")

	h := chained(&Handler{
		Store:      &countingStore{c: cat},
		Invoker:    &fakeInvoker{fill: "x"},
		Log:        discardLogger(),
		Recorder:   &record.Memory{},
		Principals: principalFunc(p),
	})
	if err := h.Prepare(cat); err != nil {
		t.Fatalf("the audience-bearing catalogue would not mount: %v", err)
	}
	return h
}

func readServeTestdata(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// cleared reaches every tool in the fixture, so nothing below is decided by
// clearance: the only thing separating one listing from another is what the
// caller asked for.
func cleared() *toolplane.Principal {
	return &toolplane.Principal{
		Subject:   "employee:jdoe",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE,
			toolv1.Verb_VERB_DESTRUCTIVE),
	}
}

func fqnsOf(l listing) []string {
	out := make([]string, 0, len(l.Tools))
	for _, tl := range l.Tools {
		out = append(out, tl.FQN)
	}
	return out
}

// The default is AGENT, and it is the default precisely so that a model's
// list is what it always was. A card carrying PERSON is not in it, and it is
// not in it because of what the tool is FOR — not a set it might be granted.
func TestAModelsDefaultListingHoldsTheAgentToolsAndNoCard(t *testing.T) {
	h := audienceHandler(t, cleared())

	w, got := listTools(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	want := []string{
		"bank.payments.v1.get_balance",
		"bank.payments.v1.get_status", // declared no audience: reads as AGENT
		"bank.payments.v1.support_assistant",
	}
	if !slices.Equal(fqnsOf(got), want) {
		t.Errorf("the default listing = %v, want %v", fqnsOf(got), want)
	}
	for _, tl := range got.Tools {
		if tl.FQN == "bank.payments.v1.initiate_payment_approval_card" {
			t.Error("a card reached a model's listing")
		}
		if tl.FQN == "bank.payments.v1.create_task" {
			t.Error("a runner's tool reached a model's listing")
		}
	}
}

// Asking explicitly is the same answer as not asking. That is what makes the
// default a default rather than a special case.
func TestAskingForAgentIsTheSameListingAsAskingForNothing(t *testing.T) {
	h := audienceHandler(t, cleared())

	_, byDefault := listTools(t, h)
	for _, body := range []string{`{"audience":"AGENT"}`, `{"audience":"AUDIENCE_AGENT"}`,
		`{"audience":"agent"}`, `{}`, ``} {
		w, got := listToolsFor(t, h, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%q: status = %d: %s", body, w.Code, w.Body.String())
		}
		if !slices.Equal(fqnsOf(got), fqnsOf(byDefault)) {
			t.Errorf("%q listed %v, want the default %v", body,
				fqnsOf(got), fqnsOf(byDefault))
		}
	}
}

// A person's client asks for PERSON and gets exactly the tools and agents
// that persona may start — which is where a hard-coded agent list goes away.
func TestAPersonsListingHoldsTheCardAndTheAgentAndNotTheAgentsTools(t *testing.T) {
	h := audienceHandler(t, cleared())

	w, got := listToolsFor(t, h, `{"audience":"PERSON"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	want := []string{
		"bank.payments.v1.initiate_payment_approval_card",
		"bank.payments.v1.support_assistant",
	}
	if !slices.Equal(fqnsOf(got), want) {
		t.Errorf("the person listing = %v, want %v", fqnsOf(got), want)
	}
}

func TestTheRunnersListingHoldsOnlyItsOwnTools(t *testing.T) {
	h := audienceHandler(t, cleared())

	w, got := listToolsFor(t, h, `{"audience":"RUNNER"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if !slices.Equal(fqnsOf(got), []string{"bank.payments.v1.create_task"}) {
		t.Errorf("the runner listing = %v, want create_task alone", fqnsOf(got))
	}
}

// The other half of the AND. An audience is not an entitlement: asking for
// PERSON does not widen anything, and a caller whose claims do not reach a
// person-facing tool is not offered it either.
func TestAskingForAnAudienceNeverWidensWhatTheClaimsReach(t *testing.T) {
	under := cleared()
	under.Clearance = toolv1.Clearance_CLEARANCE_PUBLIC
	h := audienceHandler(t, under)

	for _, body := range []string{`{"audience":"PERSON"}`, `{"audience":"RUNNER"}`, `{}`} {
		w, got := listToolsFor(t, h, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%q: status = %d: %s", body, w.Code, w.Body.String())
		}
		if len(got.Tools) != 0 {
			t.Errorf("%q listed %v to a caller cleared for none of it", body, fqnsOf(got))
		}
	}
}

// A row carries what it is for and who holds it, so a client can group a
// listing without keeping its own copy of the catalogue's vocabulary.
func TestARowCarriesItsSetsAndItsAudience(t *testing.T) {
	h := audienceHandler(t, cleared())

	_, got := listToolsFor(t, h, `{"audience":"PERSON"}`)
	byFQN := map[string]listedTool{}
	for _, tl := range got.Tools {
		byFQN[tl.FQN] = tl
	}

	card := byFQN["bank.payments.v1.initiate_payment_approval_card"]
	if !slices.Equal(card.Audience, []string{tool.AudiencePerson}) {
		t.Errorf("the card's audience = %v, want [PERSON]", card.Audience)
	}
	if !slices.Equal(card.Sets, []string{"payments"}) {
		t.Errorf("the card's sets = %v, want [payments]", card.Sets)
	}

	agent := byFQN["bank.payments.v1.support_assistant"]
	if !slices.Equal(agent.Audience, []string{tool.AudiencePerson, tool.AudienceAgent}) {
		t.Errorf("the agent's audience = %v, want [PERSON AGENT]", agent.Audience)
	}
	if !slices.Equal(agent.Sets, []string{"agents"}) {
		t.Errorf("the agent's sets = %v, want [agents]", agent.Sets)
	}

	// Declared nothing stays declared nothing. A row asserting AGENT would be
	// this endpoint putting words in an author's mouth, and it is the same
	// distinction approval_mode already keeps.
	_, agents := listTools(t, h)
	for _, tl := range agents.Tools {
		if tl.FQN != "bank.payments.v1.get_status" {
			continue
		}
		if len(tl.Audience) != 0 {
			t.Errorf("get_status declared no audience and the row says %v", tl.Audience)
		}
		if tl.Audience == nil {
			t.Error("audience marshalled as null; a documented list must stay a list")
		}
	}
}

// An audience that is not one is a 400, not a quiet fall back to the model's
// list: a client asking for "PERSONS" means to ask for something.
func TestAnAudienceThatIsNotOneIsRefused(t *testing.T) {
	h := audienceHandler(t, cleared())

	for _, body := range []string{`{"audience":"PERSONS"}`, `{"audience":"human"}`, `not json`} {
		w, _ := listToolsFor(t, h, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400: %s", body, w.Code, w.Body.String())
		}
		if e := decodeErr(t, w); e.Code != "invalid_argument" {
			t.Errorf("%q: code = %q, want invalid_argument", body, e.Code)
		}
	}
}

// A refusal must not become a way to learn what is in a catalogue.
func TestARefusedListingNamesNoTool(t *testing.T) {
	h := audienceHandler(t, cleared())
	w, _ := listToolsFor(t, h, `{"audience":"PERSONS"}`)
	for _, secret := range []string{"get_balance", "create_task", "payments", "bank."} {
		if contains(w.Body.String(), secret) {
			t.Errorf("the refusal mentions %q: %s", secret, w.Body.String())
		}
	}
}

// The agent-blind fixture declares no audience anywhere, and its listing must
// be exactly what it was. This is the promise that a catalogue built before
// audiences existed is untouched by them.
func TestTheAgentBearingCatalogueListsUnchangedByAudience(t *testing.T) {
	cat := agentCatalogue(t)
	h := chained(&Handler{
		Store:    &countingStore{c: cat},
		Invoker:  &fakeInvoker{fill: "x"},
		Log:      discardLogger(),
		Recorder: &record.Memory{},
		Principals: principalFunc(&toolplane.Principal{
			Subject:   "employee:jdoe",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
			Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
		}),
		Grants: refusingGrants{},
	})
	if err := h.Prepare(cat); err != nil {
		t.Fatalf("the agent-bearing catalogue would not mount: %v", err)
	}

	_, got := listTools(t, h)
	want := []string{"bank.agents.v1.support_assistant", "bank.agents.v1.support_assistant_run"}
	if !slices.Equal(fqnsOf(got), want) {
		t.Fatalf("the default listing = %v, want %v", fqnsOf(got), want)
	}
	for _, tl := range got.Tools {
		if len(tl.Audience) != 0 {
			t.Errorf("%s: audience = %v; the fixture declares none", tl.FQN, tl.Audience)
		}
		if !slices.Equal(tl.Sets, []string{"support"}) {
			t.Errorf("%s: sets = %v, want [support]", tl.FQN, tl.Sets)
		}
	}

	// And a person's client is offered nothing at all, because person-facing
	// is an explicit choice and this catalogue makes none.
	_, forPeople := listToolsFor(t, h, `{"audience":"PERSON"}`)
	if len(forPeople.Tools) != 0 {
		t.Errorf("a catalogue declaring no audience offered %v to a person",
			fqnsOf(forPeople))
	}
}

// A dependency the audience path must keep: the loader is what reads it, and
// it must still refuse an artifact it cannot understand rather than serving
// the half it can. Nothing about the audience fixture is allowed to make a
// malformed catalogue loadable.
func TestTheAudienceFixtureStillLoadsThroughTheOrdinaryLoader(t *testing.T) {
	cat := fixtureCatalogue(t, map[string]string{
		"garm/tool/v1/tool.proto":         readServeTestdata(t, "testdata/tool.proto"),
		"bank/payments/v1/audience.proto": readServeTestdata(t, "testdata/audience.proto"),
	}, "garm/tool/v1/tool.proto", "bank/payments/v1/audience.proto")
	if len(cat.Defs) != 5 {
		t.Fatalf("%d tools, want 5", len(cat.Defs))
	}
	if cat.SchemaVersion != catalogue.SchemaVersion {
		t.Errorf("schema version = %d", cat.SchemaVersion)
	}
}
