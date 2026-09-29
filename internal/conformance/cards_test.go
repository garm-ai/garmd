package conformance_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// The card conformance table (cards-and-tasks design §12).
//
// This package exists because two sides of an agreement must not import each
// other, and the agreement is stated declaratively instead. The minter suite
// (suite.go) is one such agreement and needs a live minter, so it runs behind
// a build tag. THIS one needs nothing running: the two sides are the contract
// — a card's `access` labels, a tool's `audience` — and this daemon's reading
// of it, and both are in the repository. So it runs in the ordinary suite,
// where a table that only runs on demand would be a table nobody runs.
//
// Every case goes through the whole chain. A projection asserted by calling
// the walk directly would pass with step 2 removed, and step 2 is half of
// what every one of these rows is about.

// ------------------------------------------------------------- the fixture

const (
	approvalCard = "/bank.cards.v1.CardsService/ApprovalCard"
	tightCard    = "/bank.cards.v1.CardsService/TightCard"
)

// cardsCatalogue loads testdata through the REAL loader, against the
// `card.proto` and `tool.proto` Track G wrote — neither of which the garm
// this binary links yet carries. That is the arrangement the whole design
// rests on: a catalogue is data, and it knows what the binary does not.
func cardsCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()

	srcs := map[string]string{
		"garm/tool/v1/tool.proto":   readTestdata(t, "testdata/tool.proto"),
		"garm/card/v1/card.proto":   readTestdata(t, "testdata/card.proto"),
		"bank/cards/v1/cards.proto": readTestdata(t, "testdata/cards.proto"),
	}
	paths := []string{
		"garm/tool/v1/tool.proto",
		"garm/card/v1/card.proto",
		"bank/cards/v1/cards.proto",
	}
	// Source first, so the fixture's own tool.proto and card.proto win over
	// the linked registry. That is the point of the fixture.
	res := protocompile.WithStandardImports(protocompile.CompositeResolver{
		&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(srcs)},
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, protoregistry.NotFound
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}),
	})
	compiled, err := (&protocompile.Compiler{Resolver: res}).Compile(context.Background(), paths...)
	if err != nil {
		t.Fatalf("compiling the card fixture: %v", err)
	}

	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var collect func(fd protoreflect.FileDescriptor)
	collect = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imps := fd.Imports()
		for i := 0; i < imps.Len(); i++ {
			collect(imps.Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
	}
	for _, f := range compiled {
		collect(f)
	}

	// The round trip the producer does: the tool annotations resolve against
	// the LINKED garm.tool.v1, which has no `audience`, so that value survives
	// in the annotation's unknown bytes — exactly as in production.
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	set = &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).
		Unmarshal(raw, set); err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(&cataloguev1.Catalogue{
		AnnotationSchemaVersion: 1,
		Files:                   set,
		Compartments: []*toolv1.Decl{
			{Name: "financial"}, {Name: "compliance"},
		},
		Provenance: &cataloguev1.Provenance{Producer: "conformance_test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalogue.Load(body, time.Now)
	if err != nil {
		t.Fatalf("the card catalogue would not load: %v", err)
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

// cardsCore mounts the catalogue and answers each procedure with the card the
// case supplies, as protojson against the catalogue's own descriptor.
func cardsCore(
	t *testing.T, cat *catalogue.Catalogue, rec *record.Memory, answers map[string]string,
) *toolplane.Core {
	t.Helper()
	core, err := toolplane.NewCore(toolplane.CoreConfig{
		HashKey:      []byte("conformance-key"),
		Recorder:     rec,
		Compartments: cat.Compartments,
	})
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	if err := core.AddTools(cat.Defs); err != nil {
		t.Fatalf("the card catalogue would not mount: %v", err)
	}
	for _, d := range cat.Defs {
		out, in := d.Output, d.Input
		body := answers[d.FullMethod]
		err := core.Register(d.FullMethod,
			func() proto.Message { return dynamicpb.NewMessage(in) },
			func(context.Context, proto.Message) (proto.Message, error) {
				m := dynamicpb.NewMessage(out)
				if body != "" {
					if err := protojson.Unmarshal([]byte(body), m); err != nil {
						t.Fatalf("the fixture answer is not a %s: %v", out.FullName(), err)
					}
				}
				return m, nil
			})
		if err != nil {
			t.Fatalf("Register %s: %v", d.FullMethod, err)
		}
	}
	return core
}

func cardsViewer(
	t *testing.T, core *toolplane.Core, name string, cl toolv1.Clearance, comps ...string,
) *toolplane.Principal {
	t.Helper()
	set, err := core.Registry().Set(comps)
	if err != nil {
		t.Fatalf("compartments %v: %v", comps, err)
	}
	return &toolplane.Principal{
		Subject:      name,
		Kind:         toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance:    cl,
		Compartments: set,
		Verbs:        toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
	}
}

// ------------------------------------------------------------- the table

// cardCase is one row: a viewer, a card a tool served, and what this daemon
// owes them.
type cardCase struct {
	// The viewer.
	clearance    toolv1.Clearance
	compartments []string

	// The endpoint, and the card its tool answered with.
	procedure string
	card      string

	// What garmd owes. code is the chain's own spelling ("" for a served
	// answer); withheld is Disclosure, exactly and in order; present and
	// absent are values that must and must not have survived; errorKind and
	// errorDetail are what the ledger row says when the call was refused.
	code        string
	withheld    []string
	present     []string
	absent      []string
	errorKind   string
	errorDetail string
}

// The card of design §10.3: one fact every approver may see, one the
// compliance compartment gates.
const conformanceCard = `{
  "kind": "TASK", "title": "Approve a payment", "state": "OPEN",
  "body": [
    {"facts": {"facts": [
      {"label": "Amount", "value": "GBP 1000.00", "field": "amount_minor_units"},
      {"label": "Screening", "value": "no-sanctions-hit", "field": "screening",
       "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
    ]}}
  ]
}`

// A Section with one child the viewer reaches and one they do not.
const conformanceSectionCard = `{
  "kind": "TASK", "title": "Approve a payment", "state": "OPEN",
  "body": [
    {"section": {"title": "Context", "elements": [
      {"text": {"text": "beneficiary-is-acme"}},
      {"text": {"text": "adverse-media-hit"},
       "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
    ]}}
  ]
}`

// An override that copied an INTERNAL field's policy onto a card served by a
// RESTRICTED + [financial] endpoint.
const conformanceMislabelledCard = `{
  "kind": "TASK", "title": "Approve a payment", "state": "OPEN",
  "body": [
    {"facts": {"facts": [
      {"label": "Amount", "value": "GBP 1000.00", "field": "amount_minor_units"}
    ]}},
    {"text": {"text": "beneficiary-is-acme"}, "access": {"clearance": "CLEARANCE_INTERNAL"}}
  ]
}`

func TestCardConformance(t *testing.T) {
	for name, tc := range map[string]cardCase{
		// One fact at RESTRICTED + [financial], two viewers, one endpoint.
		// The difference is in the footer and in the ledger, never in the
		// tool's code.
		"a duty manager at INTERNAL does not reach a financial fact": {
			clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			procedure: approvalCard, card: conformanceCard,
			withheld: []string{"screening"},
			present:  []string{"GBP 1000.00"},
			absent:   []string{"no-sanctions-hit", "Screening"},
		},
		"an approver at RESTRICTED with financial reaches it": {
			clearance: toolv1.Clearance_CLEARANCE_RESTRICTED, compartments: []string{"financial"},
			procedure: approvalCard, card: conformanceCard,
			present: []string{"GBP 1000.00", "no-sanctions-hit"},
		},

		// A Section keeps what the viewer reaches and loses what they do not.
		// The section itself stands: a group with one child left is still a
		// group, and only a section whose EVERY child went goes whole.
		"a section keeps its reachable child and names the withheld one": {
			clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			procedure: approvalCard, card: conformanceSectionCard,
			withheld: []string{"body[0].elements[1]"},
			present:  []string{"beneficiary-is-acme", "Context"},
			absent:   []string{"adverse-media-hit"},
		},
		"a section whose every child is withheld goes whole": {
			clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			procedure: approvalCard,
			card: `{"kind": "TASK", "title": "Approve", "state": "OPEN", "body": [
        {"section": {"title": "Compliance", "elements": [
          {"text": {"text": "adverse-media-hit"},
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
        ]}}
      ]}`,
			withheld: []string{"body[0]"},
			absent:   []string{"adverse-media-hit", "Compliance"},
		},

		// Floor 1. The whole card, to an approver who reaches every label in
		// it: the refusal is not about this viewer, it is about a card built
		// against a policy nobody checked.
		"an element labelled below the endpoint refuses the whole card": {
			clearance: toolv1.Clearance_CLEARANCE_RESTRICTED, compartments: []string{"financial"},
			procedure: tightCard, card: conformanceMislabelledCard,
			code:        "internal",
			errorKind:   toolplane.ErrorKindCardInvalid,
			errorDetail: "card_invalid: label_below_endpoint: body[1]",
		},

		// The same endpoint, the same viewer, a card whose labels are all at
		// or above it. Served — so the refusal above is the LABEL and not the
		// endpoint.
		"the same endpoint serves a card labelled at or above it": {
			clearance: toolv1.Clearance_CLEARANCE_RESTRICTED, compartments: []string{"financial"},
			procedure: tightCard,
			card: `{"kind": "TASK", "title": "Approve", "state": "OPEN", "body": [
        {"text": {"text": "beneficiary-is-acme"},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]}`,
			present: []string{"beneficiary-is-acme"},
		},

		// A card whose OWN label the viewer misses is not an empty card. It
		// is the answer a tool they may not see gets, for the same reason.
		"a card the viewer does not reach is not found": {
			clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			procedure: approvalCard,
			card: `{"kind": "TASK", "title": "Approve", "state": "OPEN",
        "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}`,
			code: "not_found",
		},

		// The endpoint gate is still the endpoint gate. A caller below it
		// never reaches the card walk at all.
		"a caller below the endpoint never sees the card": {
			clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			procedure: tightCard, card: conformanceCard,
			code: "not_found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cat := cardsCatalogue(t)
			rec := &record.Memory{}
			core := cardsCore(t, cat, rec, map[string]string{tc.procedure: tc.card})

			p := cardsViewer(t, core, "user:conformance", tc.clearance, tc.compartments...)
			req := dynamicpb.NewMessage(inputOf(t, cat, tc.procedure))
			resp, err := core.Invoke(context.Background(), p, tc.procedure, req)

			gotCode := ""
			if err != nil {
				gotCode = toolplane.CodeOfForTest(err)
			}
			if gotCode != tc.code {
				t.Fatalf("code = %q, want %q (err = %v)", gotCode, tc.code, err)
			}

			events := rec.Events()
			if len(events) != 1 {
				t.Fatalf("%d ledger rows, want exactly one", len(events))
			}
			ev := events[0]
			if tc.errorKind != "" && ev.ErrorKind != tc.errorKind {
				t.Errorf("error_kind = %q, want %q", ev.ErrorKind, tc.errorKind)
			}
			if tc.errorDetail != "" && ev.ErrorDetail != tc.errorDetail {
				t.Errorf("error_detail = %q, want %q", ev.ErrorDetail, tc.errorDetail)
			}
			if tc.code != "" {
				if resp != nil {
					t.Errorf("a refused call still returned a message")
				}
				return
			}

			got := render(t, resp)
			for _, s := range tc.present {
				if !strings.Contains(got, s) {
					t.Errorf("%q is missing from the card: %s", s, got)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(got, s) {
					t.Errorf("%q survived for a viewer who does not reach it: %s", s, got)
				}
			}
			if w := disclosureOf(t, resp); !slices.Equal(w, tc.withheld) {
				t.Errorf("disclosure = %v, want %v", w, tc.withheld)
			}
			// What the card says was withheld and what the ledger counted are
			// one number. A footer the row cannot account for is a projection
			// nobody can audit.
			if ev.RedactionCount != len(tc.withheld) {
				t.Errorf("the row counts %d redactions, want %d",
					ev.RedactionCount, len(tc.withheld))
			}
			// Never a value, ever, on the row.
			for _, s := range tc.absent {
				if strings.Contains(ev.ErrorDetail, s) {
					t.Errorf("a withheld value reached the ledger: %q", ev.ErrorDetail)
				}
			}
		})
	}
}

func inputOf(t *testing.T, cat *catalogue.Catalogue, procedure string) protoreflect.MessageDescriptor {
	t.Helper()
	for _, d := range cat.Defs {
		if d.FullMethod == procedure {
			return d.Input
		}
	}
	t.Fatalf("no tool at %s", procedure)
	return nil
}

func render(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatalf("marshalling the card: %v", err)
	}
	return string(b)
}

// disclosureOf reads back what the card says was withheld from this viewer.
func disclosureOf(t *testing.T, m proto.Message) []string {
	t.Helper()
	msg := m.ProtoReflect()
	fd := msg.Descriptor().Fields().ByName("disclosure")
	if fd == nil || !msg.Has(fd) {
		return nil
	}
	d := msg.Get(fd).Message()
	wf := d.Descriptor().Fields().ByName("withheld_fields")
	if wf == nil {
		return nil
	}
	list := d.Get(wf).List()
	out := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		out = append(out, list.Get(i).String())
	}
	return out
}

// ------------------------------------------------------------ the audience

// A PERSON tool is absent from an AGENT listing, and the two halves of the
// rule are separable: the audience decides what a caller is OFFERED, the
// claims decide what they may CALL, and neither stands in for the other.
func TestAudienceConformance(t *testing.T) {
	cat := cardsCatalogue(t)
	core := cardsCore(t, cat, &record.Memory{}, nil)

	// A viewer who reaches every tool in the fixture, so nothing below is
	// decided by clearance.
	p := cardsViewer(t, core, "user:conformance",
		toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")

	for want, expect := range map[string][]string{
		// The default. Two cards carry PERSON and neither is offered.
		tool.AudienceAgent: {"bank.cards.v1.get_balance"},
		"":                 {"bank.cards.v1.get_balance"},
		tool.AudiencePerson: {
			"bank.cards.v1.approval_card",
			"bank.cards.v1.tight_card",
		},
		tool.AudienceRunner: {},
	} {
		var got []string
		for _, d := range core.Catalog(p, toolplane.CatalogFilter{Audience: want}) {
			got = append(got, d.FQN)
		}
		if len(expect) == 0 && len(got) != 0 {
			t.Errorf("audience %q listed %v, want nothing", want, got)
			continue
		}
		if len(expect) > 0 && !slices.Equal(got, expect) {
			t.Errorf("audience %q listed %v, want %v", want, got, expect)
		}
	}

	// And the other half: the tool an AGENT listing omits is one the SAME
	// caller may still reach, because an audience is what a tool is for and
	// not an entitlement. It is a listing rule, and KNOWN-GAPS says so.
	if _, visible := core.ToolByFQN(p, "bank.cards.v1.approval_card"); !visible {
		t.Error("a PERSON card is invisible to a caller whose claims reach it; " +
			"an audience must narrow what is OFFERED and nothing else")
	}
}
