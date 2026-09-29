package catalogue_test

import (
	"os"
	"slices"
	"testing"
	"time"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
)

// Reading a field the binary does not have out of a catalogue that does.
//
// The linked contract has `ToolPolicy.audience` today, so the field resolves
// and the interesting path — a catalogue declaring a field this binary does
// not have — would never be taken by the real one. A catalogue carries the
// `tool.proto` it was built with, so the ARTIFACT knows a field even when the
// BINARY does not, and reading it from there is the same inversion that lets
// a tool be added without a release.
//
// The fixture reproduces exactly that arrangement and keeps it reproducible.
// `testdata/future_tool.proto` declares `audience` at field 40 rather than
// 14, the service compiles against it, and the descriptor set's options are
// then resolved against the LINKED garm.tool.v1 — which has nothing at 40, so
// the value survives in the annotation's unknown bytes, precisely as the next
// field to ship will.

func audienceCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()
	body := assemble(t, map[string]string{
		"bank/payments/v1/audience.proto": readTestdata(t, "testdata/audience.proto"),
	}, []string{"bank/payments/v1/audience.proto"})

	cat, err := catalogue.Load(body, time.Now)
	if err != nil {
		t.Fatalf("an audience-bearing catalogue would not load: %v", err)
	}
	return cat
}

func readTestdata(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func TestAToolsDeclaredAudienceIsReadFromTheCataloguesOwnDescriptors(t *testing.T) {
	cat := audienceCatalogue(t)

	want := map[string][]string{
		"bank.payments.v1.get_balance":                    {tool.AudienceAgent},
		"bank.payments.v1.initiate_payment_approval_card": {tool.AudiencePerson},
		"bank.payments.v1.create_task":                    {tool.AudienceRunner},
		"bank.payments.v1.support_assistant":              {tool.AudiencePerson, tool.AudienceAgent},
		// Declared before audiences existed: nothing recorded, which READS as
		// AGENT wherever it is applied. Recorded as empty rather than as
		// ["AGENT"] so that "the author said nothing" stays distinguishable
		// from "the author said AGENT" — the same distinction approval_mode
		// keeps between MODE_UNSPECIFIED and MODE_NONE.
		"bank.payments.v1.get_status": nil,
	}
	if len(cat.Defs) != len(want) {
		t.Fatalf("%d tools, want %d", len(cat.Defs), len(want))
	}
	for _, d := range cat.Defs {
		w, known := want[d.FQN]
		if !known {
			t.Errorf("unexpected tool %q", d.FQN)
			continue
		}
		if !slices.Equal(d.Audience, w) {
			t.Errorf("%s audience = %v, want %v", d.FQN, d.Audience, w)
		}
	}
}

// The default is what makes this addition invisible to everything that
// existed before it. A catalogue with no audiences anywhere admits an AGENT
// asking and nobody else.
func TestACatalogueWithNoAudiencesAdmitsAnAgentAndNoOneElse(t *testing.T) {
	cat, err := catalogue.Load(buildCatalogue(t, "lookup_thing"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range cat.Defs {
		if len(d.Audience) != 0 {
			t.Errorf("%s declared %v; the fixture declares none", d.FQN, d.Audience)
		}
		if !tool.AudienceAdmits(d.Audience, tool.AudienceAgent) {
			t.Errorf("%s is not offered to a model, which every tool was before "+
				"audiences existed", d.FQN)
		}
		for _, other := range []string{tool.AudiencePerson, tool.AudienceRunner} {
			if tool.AudienceAdmits(d.Audience, other) {
				t.Errorf("%s is offered to %s by omission; person-facing must be an "+
					"explicit choice", d.FQN, other)
			}
		}
	}
}

// The agent-blind fixture is a catalogue nobody wrote an audience into, and
// its two methods must stay exactly as offerable as they were. This is the
// other half of "a model's default list is unchanged": the first half is a
// tool that declares PERSON disappearing from it, and this is every tool that
// declares nothing staying in it.
func TestTheAgentBearingCatalogueDeclaresNoAudienceAndStaysAModelsToOffer(t *testing.T) {
	cat, err := catalogue.Load(agentCatalogue(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range cat.Defs {
		if len(d.Audience) != 0 {
			t.Errorf("%s acquired an audience from a catalogue that declares none: %v",
				d.FQN, d.Audience)
		}
		if !tool.AudienceAdmits(d.Audience, "") {
			t.Errorf("%s is no longer offered to a caller that asks for nothing", d.FQN)
		}
	}
}

func TestNormaliseAudienceAcceptsBothSpellingsAndRefusesTheRest(t *testing.T) {
	for in, want := range map[string]string{
		"PERSON":               tool.AudiencePerson,
		"AUDIENCE_PERSON":      tool.AudiencePerson,
		"audience_runner":      tool.AudienceRunner,
		" agent ":              tool.AudienceAgent,
		"":                     tool.AudienceUnspecified,
		"AUDIENCE_UNSPECIFIED": tool.AudienceUnspecified,
	} {
		got, ok := tool.NormaliseAudience(in)
		if !ok || got != want {
			t.Errorf("NormaliseAudience(%q) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}
	for _, bad := range []string{"PERSONS", "model", "AUDIENCE_", "human"} {
		if got, ok := tool.NormaliseAudience(bad); ok {
			t.Errorf("NormaliseAudience(%q) = (%q, true); an audience that is not one "+
				"must be refused rather than defaulted", bad, got)
		}
	}
}

// A catalogue built against a tool.proto this binary is OLDER than is still
// read correctly.
//
// This is the property that let Track D ship before garm v0.17.0 existed, and
// it must keep holding for the field after this one. The fixture is the
// shipped contract with `audience` moved to field 40: the linked ToolPolicy
// then has no field there, the value survives in the annotation's unknown
// bytes, and audience.go finds the number by NAME in the catalogue's own
// descriptors and reads it from those bytes.
//
// A test against the linked contract alone cannot cover this, because there
// the field resolves and the unknown-bytes path is never taken — so deleting
// this fixture deletes the only coverage of the mechanism.
func TestAnAudienceAtAFieldNumberThisBinaryDoesNotKnowIsStillRead(t *testing.T) {
	body := assemble(t, map[string]string{
		"garm/tool/v1/tool.proto":         readTestdata(t, "testdata/future_tool.proto"),
		"bank/payments/v1/audience.proto": readTestdata(t, "testdata/audience.proto"),
	}, []string{"garm/tool/v1/tool.proto", "bank/payments/v1/audience.proto"})

	cat, err := catalogue.Load(body, time.Now)
	if err != nil {
		t.Fatalf("a catalogue from the future would not load: %v", err)
	}

	want := map[string][]string{
		"bank.payments.v1.get_balance":                    {tool.AudienceAgent},
		"bank.payments.v1.initiate_payment_approval_card": {tool.AudiencePerson},
		"bank.payments.v1.create_task":                    {tool.AudienceRunner},
		"bank.payments.v1.support_assistant":              {tool.AudiencePerson, tool.AudienceAgent},
		"bank.payments.v1.get_status":                     nil,
	}
	for _, d := range cat.Defs {
		if !slices.Equal(d.Audience, want[d.FQN]) {
			t.Errorf("%s audience = %v, want %v — the number was found by NAME in "+
				"the catalogue's own descriptors, or it was not found at all",
				d.FQN, d.Audience, want[d.FQN])
		}
	}
}
