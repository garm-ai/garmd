package toolplane_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// The card walk: step 8's second half (cards-and-tasks design §3).
//
// garmd learns ONE type. Everything here is driven through the real chain —
// Invoke, not a helper — because the point of the design is that a card fetch
// is an ordinary governed call and the projection happens where every other
// projection happens.
//
// The card vocabulary is a FIXTURE (testdata/card.proto), not an import — CI
// refuses a build dependency on `contracts/garm/card`, because garmd knows
// this one type by NAME. The fixture is a byte copy of the contract's own
// card.proto, and pinning the shape here is what makes the assumption
// legible: TestTheCardFixturePinsTheFieldNumbersTheDesignFixes is what fails
// loudly the next time the copy is refreshed and a number has moved.

const (
	cardApprovalProcedure = "/bank.payments.v1.PaymentsService/InitiatePaymentApprovalCard"
	cardQueueProcedure    = "/bank.payments.v1.PaymentsService/ListTasks"
)

// cardFixture compiles testdata/card.proto and testdata/payments_cards.proto.
//
// The SOURCE resolver comes first, so a fixture path always wins over the
// linked registry. garm.card.v1 is not in this binary and must not be — the
// day it is, this ordering is what keeps the fixture the thing under test.
func cardFixture(t *testing.T) *protoregistry.Files {
	t.Helper()
	return cardFixtureFrom(t, readFixture(t, "testdata/card.proto"))
}

// cardFixtureFrom compiles the fixture with a card vocabulary the caller
// supplies, so a test can ask what happens when the contract moves.
func cardFixtureFrom(t *testing.T, cardProto string) *protoregistry.Files {
	t.Helper()

	srcs := map[string]string{
		"garm/card/v1/card.proto":               cardProto,
		"bank/payments/v1/payments_cards.proto": readFixture(t, "testdata/payments_cards.proto"),
	}
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
	compiled, err := (&protocompile.Compiler{Resolver: res}).Compile(context.Background(),
		"garm/card/v1/card.proto", "bank/payments/v1/payments_cards.proto")
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

	// The round trip the real producer does: protocompile leaves options as
	// dynamic messages, and the garm.tool.v1 annotations have to resolve
	// against the LINKED extension types before policy.Compile can read them.
	// The card templates (50201-50203) resolve against nothing here, which is
	// exactly their production state — garmd never links garm.card.v1.
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	set = &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).
		Unmarshal(raw, set); err != nil {
		t.Fatal(err)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatalf("resolving the card fixture: %v", err)
	}
	return files
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func msgDesc(t *testing.T, files *protoregistry.Files, name string) protoreflect.MessageDescriptor {
	t.Helper()
	d, err := files.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is not a message", name)
	}
	return md
}

// cardTools are the two endpoints of the fixture, declared exactly as their
// proto declares them. Built by hand rather than loaded through
// internal/catalogue so that this package tests the WALK and not the loader.
func cardTools(t *testing.T, files *protoregistry.Files) []toolplane.ToolDef {
	t.Helper()
	ref := msgDesc(t, files, "garm.card.v1.TaskRef")
	return []toolplane.ToolDef{
		{
			FullMethod:   cardApprovalProcedure,
			FQN:          "bank.payments.v1.initiate_payment_approval_card",
			Name:         "initiate_payment_approval_card",
			Verb:         toolv1.Verb_VERB_READ,
			MinClearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
			Compartments: []string{"financial"},
			Input:        ref,
			Output:       msgDesc(t, files, "garm.card.v1.Card"),
		},
		{
			FullMethod:   cardQueueProcedure,
			FQN:          "bank.payments.v1.list_tasks",
			Name:         "list_tasks",
			Verb:         toolv1.Verb_VERB_READ,
			MinClearance: toolv1.Clearance_CLEARANCE_PUBLIC,
			Input:        ref,
			Output:       msgDesc(t, files, "bank.payments.v1.Queue"),
		},
	}
}

// cardCore mounts the fixture and answers every call with the JSON the case
// gives, unmarshalled against the fixture's own descriptor.
func cardCore(
	t *testing.T, files *protoregistry.Files, rec *record.Memory, answers map[string]string,
) *toolplane.Core {
	t.Helper()
	core, err := toolplane.NewCore(toolplane.CoreConfig{
		HashKey:  []byte("test-key"),
		Recorder: rec,
		Compartments: []*toolv1.Decl{
			{Name: "financial"}, {Name: "compliance"},
		},
	})
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	defs := cardTools(t, files)
	if err := core.AddTools(defs); err != nil {
		t.Fatalf("AddTools: %v", err)
	}
	ref := msgDesc(t, files, "garm.card.v1.TaskRef")
	for _, d := range defs {
		out := d.Output
		body := answers[d.FullMethod]
		err := core.Register(d.FullMethod,
			func() proto.Message { return dynamicpb.NewMessage(ref) },
			func(context.Context, proto.Message) (proto.Message, error) {
				if body == "" {
					return nil, nil
				}
				m := dynamicpb.NewMessage(out)
				if err := protojson.Unmarshal([]byte(body), m); err != nil {
					t.Fatalf("the fixture answer is not a %s: %v", out.FullName(), err)
				}
				return m, nil
			})
		if err != nil {
			t.Fatalf("Register %s: %v", d.FullMethod, err)
		}
	}
	return core
}

// viewer builds a principal at a clearance holding named compartments.
func viewer(t *testing.T, core *toolplane.Core, name string,
	cl toolv1.Clearance, comps ...string) *toolplane.Principal {
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

func emptyRef(t *testing.T, files *protoregistry.Files) proto.Message {
	t.Helper()
	return dynamicpb.NewMessage(msgDesc(t, files, "garm.card.v1.TaskRef"))
}

// textOf renders a projected card as JSON, for assertions about what survived.
func textOf(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := protojson.Marshal(m)
	if err != nil {
		t.Fatalf("marshalling the answer: %v", err)
	}
	return string(b)
}

// ---------------------------------------------------------------- the pin

// The field numbers §1.1 fixes, asserted against the fixture.
//
// This is the assumption the whole walk rests on, written down once. When the
// contract's card.proto changes, testdata/card.proto is replaced with the
// released file and this test is what says whether the numbers still agree.
func TestTheCardFixturePinsTheFieldNumbersTheDesignFixes(t *testing.T) {
	files := cardFixture(t)
	for name, want := range map[string]protoreflect.FieldNumber{
		"garm.card.v1.Card":    10,
		"garm.card.v1.Element": 10,
		"garm.card.v1.Fact":    4,
		"garm.card.v1.Choice":  3,
	} {
		md := msgDesc(t, files, name)
		fd := md.Fields().ByName("access")
		if fd == nil {
			t.Errorf("%s has no `access` field; the design (§1.1) gives it one", name)
			continue
		}
		if fd.Number() != want {
			t.Errorf("%s.access is field %d, want %d", name, fd.Number(), want)
		}
		if fd.Message() == nil || fd.Message().FullName() != "garm.card.v1.Label" {
			t.Errorf("%s.access is not a garm.card.v1.Label", name)
		}
	}
	lbl := msgDesc(t, files, "garm.card.v1.Label")
	if fd := lbl.Fields().ByName("clearance"); fd == nil || fd.Number() != 1 {
		t.Error("Label.clearance is not field 1")
	}
	if fd := lbl.Fields().ByName("compartments"); fd == nil || fd.Number() != 2 || !fd.IsList() {
		t.Error("Label.compartments is not repeated field 2")
	}
}

// A card mounts. Nothing else in this file means anything if it does not:
// garm.card.v1 is RECURSIVE (Element → Section → Element) and its interior
// carries no field policies at all, so policy.Compile refuses it outright.
// Treating the type as an opaque leaf is what makes a card-serving catalogue
// serveable, and it is the half of the design that has no test of its own
// anywhere else.
func TestACardServingCatalogueMounts(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	cardCore(t, files, rec, nil) // AddTools would have failed the test already
}

// ------------------------------------------------------------------ rule 1

// The design's own worked example (§10.3), both halves.
//
// One endpoint, two approvers, two cards. The difference is in the footer and
// in the ledger, never in the tool's code.
const cardWithACompartmentedFact = `{
  "kind": "TASK", "title": "Initiate a payment", "state": "OPEN",
  "body": [
    {"facts": {"facts": [
      {"label": "Amount", "value": "1000.00", "field": "amount_minor_units",
       "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}},
      {"label": "Screening", "value": "no-sanctions-hit", "field": "screening",
       "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]}}
    ]}, "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
  ]
}`

func TestAFactTheViewerDoesNotReachIsRemovedAndNamedInTheDisclosure(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardApprovalProcedure: cardWithACompartmentedFact,
	})

	// amir: RESTRICTED, [financial] — not [compliance].
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "no-sanctions-hit") || strings.Contains(got, "Screening") {
		t.Errorf("the compliance-only fact survived for a viewer without the "+
			"compartment: %s", got)
	}
	if !strings.Contains(got, "1000.00") {
		t.Errorf("the fact the viewer DOES reach was removed too: %s", got)
	}
	if !strings.Contains(got, `"withheldFields":["screening"]`) {
		t.Errorf("Disclosure does not name the withheld fact by its `field`: %s", got)
	}

	// priya: RESTRICTED, [financial, compliance] — nothing withheld.
	priya := viewer(t, core, "user:priya", toolv1.Clearance_CLEARANCE_RESTRICTED,
		"financial", "compliance")
	resp, err = core.Invoke(context.Background(), priya, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused for a viewer who reaches every label: %v", err)
	}
	full := textOf(t, resp)
	if !strings.Contains(full, "Screening") {
		t.Errorf("the compliance fact was withheld from a compliance officer: %s", full)
	}
	if strings.Contains(full, "withheldFields") {
		t.Errorf("a Disclosure was written for a viewer nothing was withheld from: %s", full)
	}

	// Two rows, and the redaction count is the difference between them.
	events := rec.Events()
	if len(events) != 2 {
		t.Fatalf("%d ledger rows, want one per fetch", len(events))
	}
	if events[0].RedactionCount != 1 {
		t.Errorf("amir's row counts %d redactions, want 1", events[0].RedactionCount)
	}
	if events[1].RedactionCount != 0 {
		t.Errorf("priya's row counts %d redactions, want 0", events[1].RedactionCount)
	}
}

// A withheld element is named by PATH when it has no `field` of its own, and
// never by its value or its caption.
func TestTheDisclosureNamesAPathAndNeverAValue(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"text": {"text": "The balance is overdrawn"},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]}}
      ]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "overdrawn") {
		t.Fatalf("the withheld text reached the viewer: %s", got)
	}
	if !strings.Contains(got, `"withheldFields":["body[0]"]`) {
		t.Errorf("Disclosure = %s, want the path body[0]", got)
	}
}

// A Section is a group, and a child of it that is withheld is withheld alone.
func TestASectionKeepsItsReachableChildrenWhenOneIsWithheld(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"section": {"title": "Context", "elements": [
          {"text": {"text": "Beneficiary is ACME"},
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}},
          {"text": {"text": "Screening hit"},
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "Screening hit") {
		t.Fatalf("the withheld child survived: %s", got)
	}
	if !strings.Contains(got, "Beneficiary is ACME") {
		t.Errorf("the section lost the child the viewer DOES reach: %s", got)
	}
	if !strings.Contains(got, `"withheldFields":["body[0].elements[1]"]`) {
		t.Errorf("Disclosure = %s, want the child's path", got)
	}
}

// "A Section whose every child is withheld is withheld whole" (§3.2 rule 1).
// The viewer is told ONE thing was withheld, because from where they stand
// one thing was.
func TestASectionWhoseEveryChildIsWithheldGoesWhole(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"section": {"title": "Compliance", "elements": [
          {"text": {"text": "Screening hit"},
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "Compliance") {
		t.Fatalf("an empty section survived: %s", got)
	}
	if !strings.Contains(got, `"withheldFields":["body[0]"]`) {
		t.Errorf("Disclosure = %s, want the SECTION's own path and not its child's", got)
	}
}

// A card whose own access the viewer does not reach is not an empty card: it
// is NotFound, the same closed answer step 2 gives for a tool they may not
// see (§3.2 rule 1, §11).
func TestAUnaryCardTheViewerDoesNotReachIsNotFound(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]},
      "body": []
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err == nil {
		t.Fatalf("a card the viewer does not reach was served: %s", textOf(t, resp))
	}
	if got := toolplane.CodeOfForTest(err); got != "not_found" {
		t.Errorf("code = %q, want not_found", got)
	}
}

// The same label, in a LIST: dropped from the page rather than failing it.
func TestACardInAPageIsDroppedRatherThanFailingThePage(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardQueueProcedure: `{
      "cards": [
        {"kind": "TASK", "title": "A payment", "state": "OPEN",
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}},
        {"kind": "TASK", "title": "A sanctions review", "state": "OPEN",
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial", "compliance"]}}
      ],
      "cursor": "next"
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardQueueProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the page was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "sanctions") {
		t.Fatalf("a card outside the viewer's reach stayed on the page: %s", got)
	}
	if !strings.Contains(got, "A payment") {
		t.Errorf("the card the viewer reaches was dropped too: %s", got)
	}
	if ev := rec.Events(); len(ev) != 1 || ev[0].RedactionCount != 1 {
		t.Errorf("the dropped card is not on the ledger row: %+v", ev)
	}
}

// ------------------------------------------------------------------ floor 1

// §10.3 frames 7 and 8: the override copied an INTERNAL field's policy onto a
// card whose endpoint is RESTRICTED+[financial]. The whole card is refused,
// the caller learns nothing, and the ledger names the element.
func TestAnElementLabelledBelowTheEndpointRefusesTheWholeCard(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"facts": {"facts": [
          {"label": "Amount", "value": "1000.00",
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
        ]}, "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}},
        {"section": {"title": "Context", "elements": [
          {"text": {"text": "Beneficiary is ACME"},
           "access": {"clearance": "CLEARANCE_INTERNAL"}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]
    }`,
	})
	priya := viewer(t, core, "user:priya", toolv1.Clearance_CLEARANCE_RESTRICTED,
		"financial", "compliance")
	resp, err := core.Invoke(context.Background(), priya, cardApprovalProcedure, emptyRef(t, files))
	if err == nil {
		t.Fatalf("a mislabelled card was served: %s", textOf(t, resp))
	}
	if got := toolplane.CodeOfForTest(err); got != "internal" {
		t.Errorf("code = %q, want internal (500)", got)
	}
	// Never a partial card: the fact the viewer WAS entitled to must not have
	// reached them either.
	if resp != nil {
		t.Errorf("a refused card still returned a message: %s", textOf(t, resp))
	}

	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want 1", len(events))
	}
	if events[0].ErrorKind != toolplane.ErrorKindCardInvalid {
		t.Errorf("error_kind = %q, want %q", events[0].ErrorKind, toolplane.ErrorKindCardInvalid)
	}
	// It names the SECTION floor and not the endpoint's, because the element
	// is inside a Section labelled RESTRICTED + [financial] and that is the
	// floor it is actually under. An operator told "label_below_endpoint"
	// would go and check the tool's min_clearance and find nothing wrong.
	want := "card_invalid: label_below_section: body[1].elements[0]"
	if events[0].ErrorDetail != want {
		t.Errorf("error_detail = %q, want %q", events[0].ErrorDetail, want)
	}
	// And nothing the card carried is on the row.
	if strings.Contains(events[0].ErrorDetail, "ACME") ||
		strings.Contains(events[0].ErrorDetail, "1000.00") {
		t.Errorf("a card VALUE reached the ledger: %q", events[0].ErrorDetail)
	}
}

// A compartment the endpoint requires and the element omits is below the
// floor too: a label is not "tight enough" merely by having the clearance.
func TestAnElementMissingTheEndpointsCompartmentIsBelowTheFloor(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [{"text": {"text": "x"}, "access": {"clearance": "CLEARANCE_RESTRICTED"}}]
    }`,
	})
	priya := viewer(t, core, "user:priya", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	if _, err := core.Invoke(context.Background(), priya, cardApprovalProcedure,
		emptyRef(t, files)); err == nil {
		t.Fatal("an element labelled RESTRICTED with no compartments passed a " +
			"RESTRICTED+[financial] endpoint")
	}
	if ev := rec.Events(); len(ev) != 1 ||
		ev[0].ErrorKind != toolplane.ErrorKindCardInvalid {
		t.Errorf("the row does not say card_invalid: %+v", ev)
	}
}

// ------------------------------------------------------- the missing label

// "Absent means the card endpoint's own policy, never PUBLIC" (§1.1).
//
// The element below carries no `access` at all. On a RESTRICTED+[financial]
// endpoint it must be read at RESTRICTED+[financial] — so an element an
// override forgot to label cannot be handed out at PUBLIC, which is exactly
// the mistake floor 1 exists beside.
func TestAnUnlabelledElementIsReadAtTheEndpointsPolicyAndNotAtPublic(t *testing.T) {
	files := cardFixture(t)
	// The queue's endpoint is PUBLIC, so the floor there IS public — and an
	// unlabelled element on a card in it is readable by anyone the endpoint
	// admits. That is the honest answer, not a hole: the endpoint is the
	// floor, and this case is here to say the floor is read from the
	// ENDPOINT rather than assumed.
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardQueueProcedure: `{
      "cards": [{"kind": "TASK", "title": "A payment", "state": "OPEN",
                 "body": [{"text": {"text": "unlabelled"}}]}]
    }`,
	})
	anyone := viewer(t, core, "user:anyone", toolv1.Clearance_CLEARANCE_PUBLIC)
	resp, err := core.Invoke(context.Background(), anyone, cardQueueProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the queue was refused: %v", err)
	}
	if !strings.Contains(textOf(t, resp), "unlabelled") {
		t.Error("an unlabelled element was withheld on a PUBLIC endpoint, where the " +
			"floor is PUBLIC")
	}
}

// The same card, served by the RESTRICTED+[financial] endpoint, to a viewer
// who reaches the endpoint. Nothing is withheld — the floor is what they
// already passed at step 2 — and that is the point: the missing label costs
// nothing to a legitimate viewer and everything to a caller below it.
func TestAnUnlabelledElementSurvivesForAViewerWhoReachesTheEndpoint(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [{"text": {"text": "unlabelled"}}]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	if !strings.Contains(textOf(t, resp), "unlabelled") {
		t.Error("an unlabelled element was withheld from a viewer who reaches the endpoint")
	}
}

// A compartment nobody declared is one nobody holds: the element is withheld
// rather than treated as unrestricted. The direction this must never fail in.
func TestAnUndeclaredCompartmentOnALabelWithholdsTheElement(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [{"text": {"text": "secret"},
                "access": {"clearance": "CLEARANCE_RESTRICTED",
                           "compartments": ["financial", "not-a-declared-compartment"]}}]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	if strings.Contains(textOf(t, resp), "secret") {
		t.Error("an element naming an undeclared compartment was served; an unknown " +
			"compartment must narrow reach, never widen it")
	}
}

// Nothing in garm.card.v1 beyond the type and its labels is read. The fixture
// carries the templates (result_card, task_card, card_role) exactly so this
// can be asserted rather than assumed.
func TestTheCardTemplatesAreNotReadAndDoNotReachTheAnswer(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{"kind": "TASK", "title": "Approve", "state": "OPEN"}`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	for _, word := range []string{"result_card", "task_card", "card_role", "Template"} {
		if strings.Contains(textOf(t, resp), word) {
			t.Errorf("the answer mentions %q; garmd reads the type and nothing else", word)
		}
	}
}

// A card vocabulary this build has not met refuses the card.
//
// The residual risk of pinning a contract that has not shipped is that it
// ships differently. The direction that matters is the quiet one: a renamed
// or renumbered `access` read as "no label" would put every element back at
// the endpoint's floor — which the caller has already passed — and publish
// the lot. So drift is a refusal, and this is the test that says so.
func TestACardVocabularyThisBuildHasNotMetIsRefused(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"Element.access moved off field 10": func(s string) string {
			return strings.Replace(s, "  Label access = 10;\n}", "  Label access = 11;\n}", 1)
		},
		"Card.access renamed": func(s string) string {
			return strings.Replace(s, "Label            access           = 10;",
				"Label            label            = 10;", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			src := edit(readFixture(t, "testdata/card.proto"))
			if src == readFixture(t, "testdata/card.proto") {
				t.Fatal("the edit matched nothing; the fixture moved under this test")
			}
			files := cardFixtureFrom(t, src)
			rec := &record.Memory{}
			core := cardCore(t, files, rec, map[string]string{
				cardApprovalProcedure: `{
          "kind": "TASK", "title": "Approve", "state": "OPEN",
          "body": [{"text": {"text": "secret"}}]
        }`,
			})
			amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
			resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure,
				emptyRef(t, files))
			if err == nil {
				t.Fatalf("a drifted card vocabulary was served: %s", textOf(t, resp))
			}
			ev := rec.Events()
			if len(ev) != 1 || ev[0].ErrorKind != toolplane.ErrorKindCardInvalid {
				t.Fatalf("the row does not say card_invalid: %+v", ev)
			}
			t.Logf("refused: %s", ev[0].ErrorDetail)
		})
	}
}

// An input's CHOICES are elements too, and so is everything else in the card
// that carries a label.
//
// The walk is generic over "this message has an `access` of type
// garm.card.v1.Label", not over a list of message names, which is what makes
// `body`, `actions`, `refs` and the interior of an `Input` one rule rather
// than four. Today the contract labels Element, Fact, Choice and the Card;
// the day it labels an Action, nothing here changes.
func TestAChoiceTheViewerDoesNotReachIsRemovedFromItsInput(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardApprovalProcedure: `{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"input": {"id": "reason", "label": "Reason", "choice": {"choices": [
          {"title": "Looks right", "value": "ok"},
          {"title": "Sanctions concern", "value": "sanctions",
           "access": {"clearance": "CLEARANCE_RESTRICTED",
                      "compartments": ["financial", "compliance"]}}
        ]}},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ],
      "actions": [{"id": "approve", "label": "Approve"}],
      "refs": [{"kind": "RUN", "subject_id": "run_1", "title": "The run"}]
    }`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardApprovalProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the card was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "Sanctions concern") {
		t.Errorf("a choice outside the viewer's reach stayed in the form: %s", got)
	}
	if !strings.Contains(got, "Looks right") {
		t.Errorf("the choice the viewer reaches was dropped too: %s", got)
	}
	if !strings.Contains(got, `"withheldFields":["body[0].choices[1]"]`) {
		t.Errorf("Disclosure = %s, want the choice's path", got)
	}
	// Unlabelled siblings are read at the endpoint's floor, which this viewer
	// passed. An action or a ref the contract does not label is not thereby
	// dropped.
	for _, keep := range []string{"approve", "run_1"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was dropped; an unlabelled element takes the endpoint's "+
				"policy, which this viewer reaches: %s", keep, got)
		}
	}
}

// A Section is a floor for its children, per call.
//
// The contract says a child may be labelled higher than its Section and never
// lower, and lint C8 checks it — on a TEMPLATE. An override builds a card in
// Go, has no template to lint, and reaches a viewer all the same. So the same
// rule is enforced at render time, which is the only place every card passes
// through whatever built it.
//
// The leak it closes is specific: an endpoint at INTERNAL, a Section at
// RESTRICTED + [financial], and a child inside it at INTERNAL. The child
// clears the ENDPOINT floor, so floor 1 has nothing to say about it — and a
// viewer at INTERNAL would be shown a fact from a section whose heading they
// are not cleared to see.
func TestAChildLabelledBelowItsSectionRefusesTheWholeCard(t *testing.T) {
	files := cardFixture(t)
	rec := &record.Memory{}
	core := cardCore(t, files, rec, map[string]string{
		cardQueueProcedure: `{"cards": [{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"section": {"title": "Compliance", "elements": [
          {"text": {"text": "adverse-media-hit"},
           "access": {"clearance": "CLEARANCE_INTERNAL"}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]
    }]}`,
	})
	// Deliberately a viewer who reaches EVERY label in the card. The refusal
	// is not about this viewer: it is about a card whose own structure
	// contradicts itself, and it would be the same refusal for anyone.
	priya := viewer(t, core, "user:priya", toolv1.Clearance_CLEARANCE_RESTRICTED,
		"financial", "compliance")
	resp, err := core.Invoke(context.Background(), priya, cardQueueProcedure, emptyRef(t, files))
	if err == nil {
		t.Fatalf("a child labelled below its section was served: %s", textOf(t, resp))
	}
	if got := toolplane.CodeOfForTest(err); got != "internal" {
		t.Errorf("code = %q, want internal (500)", got)
	}
	ev := rec.Events()
	if len(ev) != 1 {
		t.Fatalf("%d ledger rows, want 1", len(ev))
	}
	if ev[0].ErrorKind != toolplane.ErrorKindCardInvalid {
		t.Errorf("error_kind = %q, want %q", ev[0].ErrorKind, toolplane.ErrorKindCardInvalid)
	}
	want := "card_invalid: label_below_section: cards[0].body[0].elements[0]"
	if ev[0].ErrorDetail != want {
		t.Errorf("error_detail = %q, want %q", ev[0].ErrorDetail, want)
	}
}

// A child labelled HIGHER than its Section is the case the rule exists to
// permit: one fact inside a compliance section that only the head of
// compliance sees. It must be served, and withheld from whoever does not
// reach it — not refused.
func TestAChildLabelledAboveItsSectionIsProjectedAndNotRefused(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardQueueProcedure: `{"cards": [{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"section": {"title": "Compliance", "elements": [
          {"text": {"text": "screening-was-run"},
           "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}},
          {"text": {"text": "adverse-media-hit"},
           "access": {"clearance": "CLEARANCE_RESTRICTED",
                      "compartments": ["financial", "compliance"]}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED", "compartments": ["financial"]}}
      ]
    }]}`,
	})
	amir := viewer(t, core, "user:amir", toolv1.Clearance_CLEARANCE_RESTRICTED, "financial")
	resp, err := core.Invoke(context.Background(), amir, cardQueueProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("a child labelled above its section was refused: %v", err)
	}
	got := textOf(t, resp)
	if strings.Contains(got, "adverse-media-hit") {
		t.Errorf("the tighter child survived for a viewer without the compartment: %s", got)
	}
	if !strings.Contains(got, "screening-was-run") {
		t.Errorf("the child at the section's own label was dropped: %s", got)
	}
}

// An UNLABELLED child inside a labelled Section takes the SECTION's label,
// not the endpoint's.
//
// That is the same sentence as "absent means the enclosing policy, never
// PUBLIC", applied one level in. Without it a card could put an unlabelled
// fact inside a compliance section and hand it to everyone the endpoint
// admits — a leak by omission, which is the shape the floors exist for.
func TestAnUnlabelledChildTakesItsSectionsLabel(t *testing.T) {
	files := cardFixture(t)
	core := cardCore(t, files, &record.Memory{}, map[string]string{
		cardQueueProcedure: `{"cards": [{
      "kind": "TASK", "title": "Approve", "state": "OPEN",
      "body": [
        {"section": {"title": "Compliance", "elements": [
          {"text": {"text": "unlabelled-inside-compliance"}}
        ]},
         "access": {"clearance": "CLEARANCE_RESTRICTED",
                    "compartments": ["financial", "compliance"]}}
      ]
    }]}`,
	})
	// Reaches the endpoint (PUBLIC) and not the section.
	anyone := viewer(t, core, "user:anyone", toolv1.Clearance_CLEARANCE_PUBLIC)
	resp, err := core.Invoke(context.Background(), anyone, cardQueueProcedure, emptyRef(t, files))
	if err != nil {
		t.Fatalf("the queue was refused: %v", err)
	}
	if strings.Contains(textOf(t, resp), "unlabelled-inside-compliance") {
		t.Errorf("an unlabelled element inside a compliance section reached a "+
			"viewer who cannot see the section: %s", textOf(t, resp))
	}
}
