package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// What a model is allowed to know exists.
//
// The listing IS step 2's predicate, not a second list that agrees with it
// today: Core.Catalog is the same Visible the chain denies with. A hand-written
// second list would stop agreeing the first time one of them changed, and
// neither side would look wrong — the model would simply be shown a tool it
// could never call, attempt it every turn, and be denied every turn.

// bankish is two tools at different clearances, one of them gated and
// compartmented. Small, and enough to tell three personas apart.
func bankish() *catalogue.Catalogue {
	return &catalogue.Catalogue{
		Digest:       aDigest,
		Compartments: []*toolv1.Decl{{Name: "financial"}},
		Defs: []tool.Def{
			{
				FullMethod:   "/t.v1.S/Get",
				FQN:          "t.v1.get_status",
				Name:         "get_status",
				Title:        "Read a status",
				Description:  "Returns the current status.",
				Verb:         toolv1.Verb_VERB_READ,
				MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
				Input:        message(),
				Output:       message(),
				WhenToUse:    "When the caller asks whether something is running.",
				WhenNotToUse: "To change anything.",
				OnError:      "Report the failure; do not retry.",
			},
			{
				FullMethod:           "/t.v1.S/Pay",
				FQN:                  "t.v1.initiate_payment",
				Name:                 "initiate_payment",
				Title:                "Initiate a payment",
				Description:          "Moves money.",
				Verb:                 toolv1.Verb_VERB_DESTRUCTIVE,
				MinClearance:         toolv1.Clearance_CLEARANCE_RESTRICTED,
				Compartments:         []string{"financial"},
				Input:                message(),
				Output:               message(),
				ApprovalMode:         toolv1.Approval_MODE_GRANT,
				ApproverMinClearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
				MaxGrantAge:          15 * time.Minute,
				MaterialFields:       []string{"producer"},
			},
		},
		DescriptorHashes: map[string]string{thePkg: good},
	}
}

type listing struct {
	CatalogueDigest string       `json:"catalogue_digest"`
	Tools           []listedTool `json:"tools"`
}

// listedTool is the wire shape read back, spelled here rather than imported
// from listtools.go: a test that unmarshalled into the type the handler
// marshalled from would agree with itself no matter what the JSON names were,
// and those names are the contract Track D builds against.
type listedTool struct {
	FQN            string   `json:"fqn"`
	Method         string   `json:"method"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Verb           string   `json:"verb"`
	ApprovalMode   string   `json:"approval_mode"`
	MaterialFields []string `json:"material_fields"`
	Guidance       struct {
		WhenToUse    string `json:"when_to_use"`
		WhenNotToUse string `json:"when_not_to_use"`
		OnError      string `json:"on_error"`
	} `json:"guidance"`
	InputSchema map[string]any `json:"input_schema"`
}

func listTools(t *testing.T, h *Handler) (*httptest.ResponseRecorder, listing) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, ListToolsPath, strings.NewReader("{}"))
	r.Header.Set("Content-Type", contentJSON)
	w := call(t, h, r)
	var got listing
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("the response is not the documented shape: %v (%s)", err, w.Body)
		}
	}
	return w, got
}

// One catalogue VALUE for the store and for Prepare. Planes are keyed on
// pointer identity, so preparing a second, equal catalogue would build a chain
// nothing ever uses and leave the request to build its own — passing, but
// testing something other than what it says.
func personaHandler(t *testing.T, p *toolplane.Principal, rec *record.Memory) *Handler {
	t.Helper()
	// The payment tool declares MODE_GRANT, so the catalogue does not mount at
	// all without a verifier. It is never reached by a listing — this endpoint
	// runs no chain — but it has to be present for the tool to be listed.
	return personaHandlerWith(t, p, rec, refusingGrants{})
}

func personaHandlerWith(t *testing.T, p *toolplane.Principal, rec *record.Memory,
	g toolplane.GrantVerifier) *Handler {

	t.Helper()
	cat := bankish()
	h := chained(&Handler{
		Store:      &countingStore{c: cat},
		Invoker:    &fakeInvoker{fill: "x"},
		Log:        discardLogger(),
		Recorder:   rec,
		Principals: principalFunc(p),
		Grants:     g,
	})
	if err := h.Prepare(cat); err != nil {
		t.Fatalf("the fixture catalogue would not mount: %v", err)
	}
	return h
}

// gatedGrants refuses only what declares a gate, which is what the real
// verifier does (internal/grants: a tool whose ApprovalMode is not MODE_GRANT
// returns before any check). refusingGrants refuses everything, and against it
// an ungated tool answers grant_required too — which would make the agreement
// test below unable to tell "reached step 5" from "reached the tool".
type gatedGrants struct{}

func (gatedGrants) Verify(_ context.Context, _ *toolplane.Principal, t toolplane.ToolDef,
	_ proto.Message) error {

	if t.ApprovalMode != toolv1.Approval_MODE_GRANT {
		return nil
	}
	return grants.ErrGrantRequired
}

// A teller: INTERNAL, no compartments. Sees the read tool and must not learn
// that the payment tool exists — a listing that named it would be an
// enumeration of what this caller is not cleared for, and existence is itself
// information.
func TestATellerSeesOnlyWhatTheChainWouldLetThrough(t *testing.T) {
	rec := &record.Memory{}
	h := personaHandler(t, &toolplane.Principal{
		Subject:   "employee:jdoe",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
	}, rec)

	w, got := listTools(t, h)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got.CatalogueDigest != aDigest {
		t.Errorf("catalogue_digest = %q, want %q", got.CatalogueDigest, aDigest)
	}
	if len(got.Tools) != 1 {
		t.Fatalf("%d tools listed, want 1: %+v", len(got.Tools), got.Tools)
	}
	if got.Tools[0].FQN != "t.v1.get_status" {
		t.Errorf("fqn = %q, want t.v1.get_status", got.Tools[0].FQN)
	}
	if strings.Contains(w.Body.String(), "initiate_payment") {
		t.Error("the listing names a tool this caller may not see; existence is itself " +
			"information")
	}

	// The endpoint is not a tool and writes no row on success. Every poll of a
	// catalogue producing a ledger row would bury the calls in listings.
	if n := len(rec.Events()); n != 0 {
		t.Errorf("%d ledger rows for a successful listing, want 0", n)
	}
}

// An approver: RESTRICTED and financial. Sees both, and the gated one carries
// everything a caller needs to ask for an approval without reading the
// annotation by hand.
func TestAnApproverSeesTheGatedToolWithItsMaterialFields(t *testing.T) {
	h := personaHandler(t, &toolplane.Principal{
		Subject:   "employee:amir",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE,
			toolv1.Verb_VERB_DESTRUCTIVE),
		Compartments: compartmentsOf(t, bankish(), "financial"),
	}, &record.Memory{})

	w, got := listTools(t, h)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if len(got.Tools) != 2 {
		t.Fatalf("%d tools listed, want 2: %+v", len(got.Tools), got.Tools)
	}
	// Sorted by FQN, so two listings can be diffed. An unsorted one appears to
	// change on every call.
	if got.Tools[0].FQN != "t.v1.get_status" || got.Tools[1].FQN != "t.v1.initiate_payment" {
		t.Fatalf("the listing is not sorted by FQN: %v", []string{
			got.Tools[0].FQN, got.Tools[1].FQN})
	}

	pay := got.Tools[1]
	if pay.Method != "/t.v1.S/Pay" {
		t.Errorf("method = %q, want /t.v1.S/Pay: a caller dispatches on this", pay.Method)
	}
	if pay.Verb != "VERB_DESTRUCTIVE" {
		t.Errorf("verb = %q, want VERB_DESTRUCTIVE", pay.Verb)
	}
	if pay.ApprovalMode != "MODE_GRANT" {
		t.Errorf("approval_mode = %q, want MODE_GRANT", pay.ApprovalMode)
	}
	if len(pay.MaterialFields) != 1 || pay.MaterialFields[0] != "producer" {
		t.Errorf("material_fields = %v; without them a caller cannot build an approval "+
			"request and must read the annotation by hand", pay.MaterialFields)
	}
	if pay.Title != "Initiate a payment" || pay.Description != "Moves money." {
		t.Errorf("title/description = %q/%q", pay.Title, pay.Description)
	}
	if _, ok := pay.InputSchema["properties"]; !ok {
		t.Errorf("input_schema has no properties: %v", pay.InputSchema)
	}
	if s, _ := pay.InputSchema["$schema"].(string); s != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %q, want the draft 2020-12 URL", s)
	}

	read := got.Tools[0]
	if read.Guidance.WhenToUse != "When the caller asks whether something is running." {
		t.Errorf("guidance.when_to_use = %q; the prose the model needs most to pick "+
			"the right tool is missing", read.Guidance.WhenToUse)
	}
	if read.Guidance.WhenNotToUse != "To change anything." {
		t.Errorf("guidance.when_not_to_use = %q", read.Guidance.WhenNotToUse)
	}
	if read.Guidance.OnError != "Report the failure; do not retry." {
		t.Errorf("guidance.on_error = %q", read.Guidance.OnError)
	}
}

// The narrowing does not stop at which TOOLS are listed. A field this caller
// may not write is absent from the schema it is shown — not present and
// rejected later — and that is the rule the listing exists to deliver (spec
// §5.3): a model attempts every field it is shown, a field it cannot write
// produces a step-3 rejection naming a path it cannot interpret, and it
// retries identically. An unprojected schema teaches the model to fail.
//
// `approver_note` on the fixture message is writable only at RESTRICTED, so
// two personas looking at the SAME tool must be shown two different schemas.
func TestTheInputSchemaIsNarrowedToTheCallersOwnFields(t *testing.T) {
	teller := personaHandler(t, &toolplane.Principal{
		Subject:   "employee:jdoe",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
	}, &record.Memory{})
	tw, tg := listTools(t, teller)
	if tw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", tw.Code, tw.Body.String())
	}
	if len(tg.Tools) != 1 {
		t.Fatalf("%d tools listed, want 1", len(tg.Tools))
	}

	props, _ := tg.Tools[0].InputSchema["properties"].(map[string]any)
	if _, ok := props["producer"]; !ok {
		t.Errorf("the field this caller MAY write is missing too, so the schema is "+
			"empty rather than narrowed: %v", props)
	}
	if _, ok := props["approver_note"]; ok {
		t.Errorf("approver_note is advertised to a caller who cannot write it; the "+
			"model will attempt it every turn and be rejected at step 3: %v", props)
	}
	for _, r := range required(t, tg.Tools[0].InputSchema) {
		if r == "approver_note" {
			t.Error("approver_note is REQUIRED of a caller who may not write it, which " +
				"describes a tool nobody at this clearance can call")
		}
	}
	// The name itself, anywhere in the body. A field hidden from properties and
	// left in a description or a required list is still disclosed.
	if strings.Contains(tw.Body.String(), "approver_note") {
		t.Errorf("the listing names a field this caller may not write: %s", tw.Body.String())
	}

	approver := personaHandler(t, &toolplane.Principal{
		Subject:   "employee:amir",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE,
			toolv1.Verb_VERB_DESTRUCTIVE),
		Compartments: compartmentsOf(t, bankish(), "financial"),
	}, &record.Memory{})
	aw, ag := listTools(t, approver)
	if aw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", aw.Code, aw.Body.String())
	}

	// Same tool, same generation, a different schema. Without this half the
	// test above would pass against a projection that dropped the field for
	// everybody.
	var read *listedTool
	for i := range ag.Tools {
		if ag.Tools[i].FQN == "t.v1.get_status" {
			read = &ag.Tools[i]
		}
	}
	if read == nil {
		t.Fatalf("the approver was not shown t.v1.get_status: %+v", ag.Tools)
	}
	aprops, _ := read.InputSchema["properties"].(map[string]any)
	if _, ok := aprops["approver_note"]; !ok {
		t.Errorf("a caller who MAY write approver_note is not shown it, so the "+
			"projection is not narrowing per caller — it is dropping the field: %v", aprops)
	}
	if !containsString(required(t, read.InputSchema), "approver_note") {
		t.Errorf("approver_note is not required of the caller who may write it: %v",
			read.InputSchema["required"])
	}
}

// required reads the JSON Schema `required` list, which is absent rather than
// empty when nothing is required.
func required(t *testing.T, s map[string]any) []string {
	t.Helper()
	raw, ok := s["required"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		str, ok := v.(string)
		if !ok {
			t.Fatalf("required carries a non-string: %v", v)
		}
		out = append(out, str)
	}
	return out
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// A caller cleared for nothing gets an empty ARRAY, not null and not a 404.
// A model handed `null` has to special-case it, and a 404 would say the
// endpoint is missing when the answer is that this caller may use no tools.
func TestACallerClearedForNothingGetsAnEmptyList(t *testing.T) {
	h := personaHandler(t, &toolplane.Principal{
		Subject:   "customer:C-1",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_PUBLIC,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
	}, &record.Memory{})

	w, got := listTools(t, h)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if len(got.Tools) != 0 {
		t.Errorf("%d tools listed for a caller cleared for none", len(got.Tools))
	}
	if !strings.Contains(w.Body.String(), `"tools":[]`) {
		t.Errorf("tools is not an empty array: %s", w.Body.String())
	}
}

// Unauthenticated is 401 WITH a ledger row, exactly as the tool route — the
// one outcome nobody authenticated for is the one an auditor most wants to
// see, and a listing endpoint that answered 401 outside the chain would be a
// hole in that record.
func TestAnUnauthenticatedListingIs401AndIsLedgered(t *testing.T) {
	rec := &record.Memory{}
	h := &Handler{
		Store:    &countingStore{c: bankish()},
		Invoker:  &fakeInvoker{fill: "x"},
		Log:      discardLogger(),
		HashKey:  []byte("a test hash key"),
		Recorder: rec,
		Grants:   refusingGrants{},
		Principals: func(context.Context) (*toolplane.Principal, error) {
			return nil, errNoCredential
		},
	}

	w, _ := listTools(t, h)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if events[0].Tool != ListToolsPath {
		t.Errorf("the row names %q, want %q", events[0].Tool, ListToolsPath)
	}
	if got := w.Header().Get(EventHeader); got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q, want %q", got, events[0].ID)
	}
}

// The endpoint is not a tool, so it is not routable as one and a GET is not a
// way to read the catalogue out of a browser.
func TestListToolsIsAPostAndIsNotATool(t *testing.T) {
	h := personaHandler(t, admitted(), &record.Memory{})

	w := call(t, h, httptest.NewRequest(http.MethodGet, ListToolsPath, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", w.Code)
	}

	for _, d := range bankish().Defs {
		if d.FullMethod == ListToolsPath {
			t.Fatal("the listing path is also a tool route")
		}
	}
}

// A catalogue that declares a tool AT the listing route will not mount.
//
// The surface answers this path before it looks a route up, so such a tool
// would be permanently shadowed: never invoked, never refused, and never
// reported — the catalogue would say the tool is served and every call to it
// would come back as somebody else's tool list. Refusing at mount makes that a
// startup failure naming the tool, which is the one place an author can act on
// it, and a reload introducing one keeps the previous generation serving.
func TestACatalogueDeclaringTheListingRouteWillNotMount(t *testing.T) {
	cat := bankish()
	cat.Defs = append(cat.Defs, tool.Def{
		FullMethod:   ListToolsPath,
		FQN:          "t.v1.shadowed",
		Name:         "shadowed",
		Verb:         toolv1.Verb_VERB_READ,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        message(),
		Output:       message(),
	})
	h := chained(&Handler{
		Store:   &countingStore{c: cat},
		Invoker: &fakeInvoker{fill: "x"},
		Log:     discardLogger(),
		Grants:  refusingGrants{},
	})

	err := h.Prepare(cat)
	if err == nil {
		t.Fatal("a catalogue declaring a tool at the listing route mounted; every call " +
			"to that tool would silently return a tool list")
	}
	if !contains(err.Error(), "t.v1.shadowed") {
		t.Errorf("the refusal does not name the tool, so an author cannot fix it: %v", err)
	}
	if !contains(err.Error(), ListToolsPath) {
		t.Errorf("the refusal does not name the route it collides with: %v", err)
	}

	// And the reload pre-flight refuses it too, which is what keeps the
	// previous generation serving rather than swapping to one that cannot be
	// governed.
	if err := h.Check(cat); err == nil {
		t.Error("the pre-flight admitted it, so a reload would swap to it")
	}
}

// The listing and the chain cannot disagree, checked by CALLING every tool
// the catalogue declares rather than by re-reading the predicate.
//
// This is the property the whole design rests on and the one a reader is
// entitled to doubt: "same predicate" is a claim about code, and this is the
// observation. A listed tool must get past step 2 — it may still be stopped
// later, by an approval it has not obtained, which is a different sentence
// with a next move — and an omitted tool must be refused there, with the
// not_found that is indistinguishable from a route this build does not serve.
func TestTheListingAndTheChainAgreeToolByTool(t *testing.T) {
	for _, persona := range []struct {
		name string
		p    *toolplane.Principal
	}{
		{"a teller", &toolplane.Principal{
			Subject:   "employee:jdoe",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
			Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
		}},
		{"an approver", &toolplane.Principal{
			Subject:   "employee:amir",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
			Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
			Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE,
				toolv1.Verb_VERB_DESTRUCTIVE),
			Compartments: compartmentsOf(t, bankish(), "financial"),
		}},
		{"a customer", &toolplane.Principal{
			Subject:   "customer:C-1",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
			Clearance: toolv1.Clearance_CLEARANCE_PUBLIC,
			Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
		}},
		// Cleared for get_status and holding the wrong verb for it. The other
		// personas differ from the tools they cannot see on clearance AND
		// compartment AND verb at once, so a listing that read only clearance
		// would agree with the chain on all of them. This one isolates the
		// verb: INTERNAL is enough, financial is not needed, and WRITE alone is
		// the single reason the read tool is omitted.
		{"a writer who holds no read verb", &toolplane.Principal{
			Subject:   "service:importer",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_SERVICE,
			Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_WRITE),
		}},
	} {
		t.Run(persona.name, func(t *testing.T) {
			h := personaHandlerWith(t, persona.p, &record.Memory{}, gatedGrants{})
			_, got := listTools(t, h)

			listed := map[string]bool{}
			for _, tl := range got.Tools {
				listed[tl.Method] = true
			}

			for _, d := range bankish().Defs {
				req := httptest.NewRequest(http.MethodPost, d.FullMethod,
					strings.NewReader("{}"))
				req.Header.Set("Content-Type", contentJSON)
				w := call(t, h, req)
				code := ""
				if w.Code != http.StatusOK {
					code = decodeErr(t, w).Code
				}

				if listed[d.FullMethod] && code == "not_found" {
					t.Errorf("%s is listed and step 2 denies it: the model would attempt "+
						"it every turn and be refused every turn", d.FQN)
				}
				// An ungated listed tool goes all the way. A gated one stops at
				// step 5 with grant_required, which is a refusal WITH a next
				// move and not the listing disagreeing with the chain.
				if listed[d.FullMethod] && d.ApprovalMode != toolv1.Approval_MODE_GRANT &&
					w.Code != http.StatusOK {
					t.Errorf("%s is listed and answered %d/%q rather than being called",
						d.FQN, w.Code, code)
				}
				if !listed[d.FullMethod] && code != "not_found" {
					t.Errorf("%s is omitted from the listing and the chain answered %q "+
						"rather than not_found: the listing is hiding a tool this "+
						"caller may in fact call", d.FQN, code)
				}
			}
		})
	}
}

// A listing is one generation's, whole. The handler reads the store once and
// pins that plane, so a swap landing mid-request cannot produce a body whose
// digest names one catalogue and whose tools came from another — which is the
// failure a caller has no way to detect, because both halves look valid.
func TestAListingIsSelfConsistentAcrossAReload(t *testing.T) {
	next := bankish()
	next.Digest = "sha256:feedface"
	next.Defs = []tool.Def{{
		FullMethod:   "/t.v1.S/List",
		FQN:          "t.v1.list_accounts",
		Name:         "list_accounts",
		Verb:         toolv1.Verb_VERB_READ,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        message(),
		Output:       message(),
	}}

	h := chained(&Handler{
		Store:      &swappingStore{gens: []*catalogue.Catalogue{bankish(), next}},
		Invoker:    &fakeInvoker{fill: "x"},
		Log:        discardLogger(),
		Recorder:   &record.Memory{},
		Grants:     refusingGrants{},
		Principals: principalFunc(admitted()),
	})

	// Two listings, either side of the swap. Each must belong entirely to the
	// generation its own digest names.
	for i := 0; i < 2; i++ {
		w, got := listTools(t, h)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
		}
		if hdr := w.Header().Get("Garm-Catalogue-Digest"); hdr != got.CatalogueDigest {
			t.Fatalf("the header says %q and the body says %q", hdr, got.CatalogueDigest)
		}
		want := "t.v1.get_status"
		if got.CatalogueDigest == next.Digest {
			want = "t.v1.list_accounts"
		}
		if len(got.Tools) != 1 || got.Tools[0].FQN != want {
			t.Fatalf("catalogue %s listed %+v, want exactly %s",
				got.CatalogueDigest, got.Tools, want)
		}
	}
}

// swappingStore hands out a later generation on each read, which is what a
// reload looks like from inside the handler.
type swappingStore struct {
	gens []*catalogue.Catalogue
	n    int
}

func (s *swappingStore) Current() *catalogue.Catalogue {
	c := s.gens[min(s.n, len(s.gens)-1)]
	s.n++
	return c
}

// The body is the caller's own projection and nothing else. A listing is the
// most-polled surface here and the easiest place for policy detail to leak
// out by accident — a compartment name, another caller's clearance, the
// redaction plan that decided what this schema shows.
func TestTheListingCarriesNoPolicyInternals(t *testing.T) {
	h := personaHandler(t, &toolplane.Principal{
		Subject:   "employee:amir",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE,
			toolv1.Verb_VERB_DESTRUCTIVE),
		Compartments: compartmentsOf(t, bankish(), "financial"),
	}, &record.Memory{})

	w, _ := listTools(t, h)

	for _, leak := range []string{
		"financial",            // the compartment gating the tool
		"CLEARANCE_RESTRICTED", // what it takes to reach it
		"min_clearance",        // and the field that says so
		"MinClearance",
		"compartment",
		"redact",
		"employee:amir", // who asked
	} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the listing carries %q, which is policy the caller was never "+
				"shown and cannot act on: %s", leak, w.Body.String())
		}
	}
}

// compartmentsOf resolves names against the catalogue's own taxonomy, because
// a CompartmentSet's bit assignment is only stable within one registry.
func compartmentsOf(t *testing.T, cat *catalogue.Catalogue, names ...string) policy.CompartmentSet {
	t.Helper()
	reg, err := policy.NewRegistry(cat.Compartments)
	if err != nil {
		t.Fatal(err)
	}
	set, err := reg.Set(names)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
