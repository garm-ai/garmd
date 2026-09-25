package toolplane_test

import (
	"sync"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy/testdata"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// ---- sensitive fixture values, named so tests can grep for them by name ----

const (
	sensitiveEmail = "ada@corp.com"
	sensitiveIBAN  = "GB33BUKB20201555555555"
	sensitiveNatID = "NI-99-88-77"
)

// sensitiveValues is every value in fullProfile() that must never survive a
// call from a principal without the clearance/compartments to see it.
var sensitiveValues = []string{sensitiveEmail, sensitiveIBAN, sensitiveNatID}

func fullProfile() *testdata.Profile {
	return &testdata.Profile{
		Id:         "u_8123",
		Locale:     "en-GB",
		Email:      proto.String(sensitiveEmail),
		NationalId: proto.String(sensitiveNatID),
		Billing:    &testdata.Billing{CardLast4: "1111", Iban: sensitiveIBAN},
		Tags:       map[string]string{"tier": "gold"},
	}
}

func lowClearancePrincipal() toolplane.Principal {
	return toolplane.Principal{
		Subject:   "user:analytics",
		Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
	}
}

func mapTestPrincipal() toolplane.Principal {
	return toolplane.Principal{
		Subject:      "user:map-test",
		Clearance:    toolv1.Clearance_CLEARANCE_CONFIDENTIAL,
		Compartments: 1,
		Verbs:        toolplane.NewVerbSet(toolv1.Verb_VERB_WRITE),
	}
}

const restrictedUpdateProcedure = "/toolplane.test/RestrictedUpdate"

func restrictedUpdateToolDef() toolplane.ToolDef {
	pd := (*testdata.Profile)(nil).ProtoReflect().Descriptor()
	return toolplane.ToolDef{
		FullMethod:   restrictedUpdateProcedure,
		Name:         "restricted_update",
		Verb:         toolv1.Verb_VERB_WRITE,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        pd,
		Output:       pd,
	}
}

// repeatedUpdateProcedure is a second synthetic RPC, over testdata.
// SearchResponse (repeated Profile), for the repeated-message-nested
// write-clearance test.
const repeatedUpdateProcedure = "/toolplane.test/RepeatedUpdate"

func repeatedUpdateToolDef() toolplane.ToolDef {
	sd := (*testdata.SearchResponse)(nil).ProtoReflect().Descriptor()
	return toolplane.ToolDef{
		FullMethod:   repeatedUpdateProcedure,
		Name:         "repeated_update",
		Verb:         toolv1.Verb_VERB_WRITE,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        sd,
		Output:       sd,
	}
}

// compartmentGatedProcedure requires a compartment ("support") that
// lowClearancePrincipal and most other test principals never hold, isolating
// the visibility gate's compartment branch from its clearance and verb
// branches.
const compartmentGatedProcedure = "/toolplane.test/CompartmentGated"

const unregisteredResponseProcedure = "/toolplane.test/UnregisteredResponse"

const nonProtoResponseProcedure = "/toolplane.test/NonProtoResponse"

func nonProtoResponseToolDef() toolplane.ToolDef {
	pd := (*testdata.Profile)(nil).ProtoReflect().Descriptor()
	return toolplane.ToolDef{
		FullMethod:   nonProtoResponseProcedure,
		Name:         "non_proto_response",
		Verb:         toolv1.Verb_VERB_READ,
		MinClearance: toolv1.Clearance_CLEARANCE_PUBLIC,
		Input:        pd,
		Output:       pd,
	}
}

// nonProtoPayload carries a sensitive value so a test can assert it did not
// reach the wire, not merely that the call failed somewhere.
type nonProtoPayload struct {
	NationalID string `json:"national_id"`
}

// ---- non-tool sibling procedures ----

// siblingEnforcedProcedure is a NON-tool RPC: it is mounted on the Server's
// mux behind the same interceptor, but no ToolDef names it, exactly like an
// unannotated or exclude: true method sitting next to a tool on a service
// MountService mounted whole. Its messages (testdata.Profile) ARE classified
// on this Server, because another tool registered them — so the interceptor
// must run the full field-level chain over it rather than pass it through.
const siblingEnforcedProcedure = "/toolplane.test/SiblingEnforced"

// siblingUnknownTypeProcedure is the other half: a non-tool RPC over
// testdata.Billing, a message this Server never compiled a plan for (Billing
// is reached only as a nested type inside Profile's plan, never as a root).
// With no classification for its messages, the interceptor has nothing to
// enforce WITH, so it must refuse rather than serve.
const siblingUnknownTypeProcedure = "/toolplane.test/SiblingUnknownType"

type ledgerCapture struct {
	mu   sync.Mutex
	last toolplane.Redactions
}

func (c *ledgerCapture) get() toolplane.Redactions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func publicPrincipal() toolplane.Principal {
	return toolplane.Principal{
		Subject:   "user:public",
		Clearance: toolv1.Clearance_CLEARANCE_PUBLIC,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ, toolv1.Verb_VERB_WRITE),
	}
}
