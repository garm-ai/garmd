package toolplane_test

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// fakeAvailability is a toolplane.AvailabilitySource a test controls
// directly, with no NATS and no svcwatch behind it — svcwatch_test.go
// already exercises the real reconciliation rules; these tests exercise
// only that Core CONSULTS whatever AvailabilitySource it is given, at the
// right point in the chain, without re-deciding the answer itself.
//
// lastKey records the argument Availability was called with. Without this,
// a test asserting only that Availability was CALLED cannot tell a correct
// lookup key (ToolDef.FQN) from a broken one (an empty string, say, if
// core.go ever called Availability(t.FullMethod) or forgot to set FQN on
// the ToolDef in the first place) — every test here would stay green under
// either, because fakeAvailability used to discard the argument entirely.
type fakeAvailability struct {
	ok      bool
	reason  string
	calls   int
	lastKey string
}

func (f *fakeAvailability) Availability(key string) (bool, string) {
	f.calls++
	f.lastKey = key
	return f.ok, f.reason
}

// TestUnavailableToolRefusesBeforeTheResolverRunsButStaysVisible is the
// property that matters most about step 6's availability gate: a tool an
// AvailabilitySource marks unavailable is refused WITHOUT the resolver ever
// running (no wasted call, no side effect from a service that cannot
// actually be reached), yet Visible — the catalogue's own predicate — is
// completely unaffected. Availability and visibility must be provably
// different axes, not merely documented as such.
func TestUnavailableToolRefusesBeforeTheResolverRunsButStaysVisible(t *testing.T) {
	rec := &countingRecorder{}
	resolverCalled := false
	core := testCore(t, rec, func(context.Context, proto.Message) (proto.Message, error) {
		resolverCalled = true
		return okResolver(context.Background(), nil)
	})
	src := &fakeAvailability{ok: false, reason: "no live instance of garm.test.v1.WidgetService"}
	core.SetAvailability(src)

	p := testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL)
	_, err := core.Invoke(context.Background(), p, testProcedure, testRequest())
	if err == nil {
		t.Fatal("an unavailable tool's call succeeded")
	}
	if got := toolplane.CodeOfForTest(err); got != "unavailable" {
		t.Errorf("code = %q, want %q", got, "unavailable")
	}
	if resolverCalled {
		t.Error("the resolver ran despite the tool being unavailable — a wasted call to a " +
			"service the availability check just said cannot be reached")
	}
	if src.calls == 0 {
		t.Fatal("Core never consulted the AvailabilitySource")
	}
	if src.lastKey != coreToolFQN {
		t.Errorf("Availability was called with %q, want the tool's FQN %q — a wrong key here "+
			"still refuses the call (fakeAvailability.ok is false regardless), which is why "+
			"this assertion, not the call's own outcome, is what catches it", src.lastKey, coreToolFQN)
	}

	// Visibility is untouched: the SAME tool, asked about through Visible
	// (what the catalogue uses), is still visible to a cleared principal.
	tool, ok := coreLookupForTest(core, testProcedure)
	if !ok {
		t.Fatal("the tool disappeared from the registry entirely")
	}
	if !core.Visible(p, tool) {
		t.Error("an unavailable tool is no longer Visible; availability must not fold into " +
			"the catalogue's visibility predicate (§5.8)")
	}

	ev := rec.event()
	if ev.ErrorDetail == "" {
		t.Error("the ledger row carries no detail for an availability refusal")
	}
}

// TestAvailableToolRunsTheResolverNormally is the other half: when the
// AvailabilitySource says yes, Core behaves exactly as it did before this
// task — nothing about the ordinary path changes.
func TestAvailableToolRunsTheResolverNormally(t *testing.T) {
	rec := &countingRecorder{}
	core := testCore(t, rec, okResolver)
	src := &fakeAvailability{ok: true}
	core.SetAvailability(src)

	p := testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL)
	resp, err := core.Invoke(context.Background(), p, testProcedure, testRequest())
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp == nil {
		t.Fatal("no response")
	}
	if src.lastKey != coreToolFQN {
		t.Errorf("Availability was called with %q, want the tool's FQN %q", src.lastKey, coreToolFQN)
	}
}

// TestNilAvailabilitySourceSkipsTheCheck: a Core that never calls
// SetAvailability behaves exactly as one predating this task — the check is
// SKIPPED, not failed closed, because a Core with no NATS-backed tool has
// nothing to ask.
func TestNilAvailabilitySourceSkipsTheCheck(t *testing.T) {
	rec := &countingRecorder{}
	core := testCore(t, rec, okResolver)
	// No SetAvailability call.

	p := testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL)
	if _, err := core.Invoke(context.Background(), p, testProcedure, testRequest()); err != nil {
		t.Fatalf("Invoke with no AvailabilitySource wired: %v", err)
	}
}

// coreLookupForTest is core.Visible's own precondition — a ToolDef — read
// back via the catalogue, which is the only exported way to get one out
// short of a brand-new accessor this test does not otherwise need.
func coreLookupForTest(core *toolplane.Core, fullMethod string) (toolplane.ToolDef, bool) {
	// The catalogue is keyed by FQN, and coreToolDef() sets none, so this
	// helper goes through Catalog with a permissive filter instead and
	// matches on FullMethod, which coreToolDef DOES set.
	for _, t := range core.Catalog(&toolplane.Principal{
		Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
	}, toolplane.CatalogFilter{}) {
		if t.FullMethod == fullMethod {
			return t, true
		}
	}
	return toolplane.ToolDef{}, false
}
