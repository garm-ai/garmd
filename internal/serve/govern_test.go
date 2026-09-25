package serve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// These are the tests the surface exists to pass. Everything in serve_test.go
// asks whether a call is ROUTED correctly; these ask whether it is GOVERNED,
// which is a different question and the one this daemon is for.
//
// The shape they share: assert the status, and assert the tool was never
// invoked. A refusal that still called the tool is not a refusal, and it is
// the failure that looks fine from outside — the caller sees an error and the
// side effect happened anyway.

func TestAnUnauthenticatedCallNeverReachesTheTool(t *testing.T) {
	inv := &fakeInvoker{fill: "x"}
	h := chained(&Handler{
		Store:   &countingStore{c: aCatalogue()},
		Invoker: inv,
		Principals: func(context.Context) (*toolplane.Principal, error) {
			return nil, errors.New("no bearer token on the request")
		},
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool was invoked %d times for a caller who never authenticated", n)
	}
	// The reason must not come back. "no bearer token" is harmless, but the
	// same path carries "signature invalid for key X" and "token expired at
	// T", which tell an attacker which half of their forgery to fix.
	if strings.Contains(w.Body.String(), "bearer") {
		t.Errorf("the refusal quotes the verifier's own words: %s", w.Body.String())
	}
}

// A build with no way to identify a caller must refuse everything. The
// alternative is a daemon that treats "I could not tell who this is" as
// "anonymous, allow" — which is how a governance layer becomes a proxy
// without anyone deciding to make it one.
func TestAHandlerWithNoPrincipalSourceRefusesEveryCall(t *testing.T) {
	inv := &fakeInvoker{fill: "x"}
	h := &Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  inv,
		HashKey:  []byte("a test hash key"),
		Recorder: &record.Memory{},
		// Principals deliberately nil.
	}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool was invoked %d times by a build that cannot identify callers", n)
	}
}

// Step 1 runs BEFORE the route is looked up, so an unauthenticated caller
// cannot learn which tools exist by watching 404 turn into 401.
//
// If this ever regresses, anyone with a socket can enumerate the catalogue
// one path at a time — and the catalogue is exactly the thing worth not
// disclosing.
func TestAnUnauthenticatedCallerCannotProbeWhichToolsExist(t *testing.T) {
	deny := func(context.Context) (*toolplane.Principal, error) {
		return nil, errors.New("nope")
	}
	h := chained(&Handler{
		Store:      &countingStore{c: aCatalogue()},
		Invoker:    &fakeInvoker{},
		Principals: deny,
	})

	real := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))
	fake := call(t, h, httptest.NewRequest(http.MethodPost, "/no.such.V1/Nope", strings.NewReader("")))

	if real.Code != fake.Code {
		t.Errorf("a declared route answered %d and an undeclared one %d; the difference "+
			"tells an unauthenticated caller which tools this deployment serves",
			real.Code, fake.Code)
	}
	if real.Body.String() != fake.Body.String() {
		t.Errorf("the bodies differ, which discloses the same thing:\n declared: %s\n unknown:  %s",
			real.Body.String(), fake.Body.String())
	}
}

// Clearance is enforced, and the tool is never reached.
//
// The fixture tool declares CLEARANCE_INTERNAL. A PUBLIC caller holds a
// perfectly valid identity and is simply not cleared for this tool, which is
// the ordinary case rather than the exceptional one.
func TestACallerBelowTheToolsClearanceIsRefusedWithoutReachingIt(t *testing.T) {
	inv := &fakeInvoker{fill: "x"}
	under := admitted()
	under.Clearance = toolv1.Clearance_CLEARANCE_PUBLIC

	h := chained(&Handler{
		Store:      &countingStore{c: aCatalogue()},
		Invoker:    inv,
		Principals: principalFunc(under),
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code == http.StatusOK {
		t.Fatalf("a PUBLIC caller reached an INTERNAL tool: %s", w.Body.String())
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool was invoked %d times for a caller it does not admit", n)
	}
	// 404, not 403. A tool this caller may not see must be indistinguishable
	// from one that does not exist, because existence is itself information —
	// and TestARouteTheCatalogueDoesNotDeclareIsUnimplemented pins the other
	// half of that pair.
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a tool the caller may not see must answer "+
			"exactly as a tool that is not here", w.Code)
	}
}

// A caller holding the wrong VERB is refused even at the right clearance.
// Clearance says how sensitive; the verb says what kind of action. A reader
// who could call a destructive tool by being cleared enough would make the
// verb decorative.
func TestAClearedCallerWithoutTheVerbIsStillRefused(t *testing.T) {
	inv := &fakeInvoker{fill: "x"}
	wrongVerb := admitted()
	wrongVerb.Verbs = toolplane.NewVerbSet(toolv1.Verb_VERB_DESTRUCTIVE)

	h := chained(&Handler{
		Store:      &countingStore{c: aCatalogue()},
		Invoker:    inv,
		Principals: principalFunc(wrongVerb),
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code == http.StatusOK {
		t.Fatalf("a caller without VERB_READ called a VERB_READ tool: %s", w.Body.String())
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool was invoked %d times for a caller holding the wrong verb", n)
	}
}

// Every outcome leaves a row, refusals included.
//
// A refused call is the one an auditor most wants to see, and it is the one a
// surface is most likely to answer before the chain ever runs — which is
// exactly what happened to step 1 until the surface started routing its
// failure back through Unauthenticated.
func TestEveryOutcomeIsLedgered(t *testing.T) {
	for _, tc := range []struct {
		name       string
		principals func(context.Context) (*toolplane.Principal, error)
	}{
		{"a call that succeeds", principalFunc(admitted())},
		{"a call refused for clearance", func(context.Context) (*toolplane.Principal, error) {
			p := admitted()
			p.Clearance = toolv1.Clearance_CLEARANCE_PUBLIC
			return p, nil
		}},
		{"a call that never authenticated", func(context.Context) (*toolplane.Principal, error) {
			return nil, errors.New("no token")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &record.Memory{}
			h := chained(&Handler{
				Store:      &countingStore{c: aCatalogue()},
				Invoker:    &fakeInvoker{fill: "x"},
				Recorder:   rec,
				Principals: tc.principals,
			})

			call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

			if len(rec.Events()) == 0 {
				t.Error("no ledger row; a call that happened and left no trace is the " +
					"failure this whole design is against")
			}
		})
	}
}

// A catalogue this deployment cannot govern must be refused BEFORE the
// listener binds, not one request at a time afterwards.
//
// The distinction is the whole value of the mount refusal. A process that
// binds and then answers 503 to everything reads as healthy to an
// orchestrator: it rolls out across every replica and is discovered by a
// caller. Prepare is what makes it a startup failure instead.
func TestACatalogueThisDeploymentCannotGovernIsRefusedUpFront(t *testing.T) {
	cat := aCatalogue()
	// The declaration nobody here can honour: an approval gate with no
	// verifier configured.
	cat.Defs[0].ApprovalMode = toolv1.Approval_MODE_GRANT

	h := chained(&Handler{Store: &countingStore{c: cat}, Invoker: &fakeInvoker{}})

	err := h.Prepare(cat)
	if err == nil {
		t.Fatal("a tool declaring MODE_GRANT was accepted with no GrantVerifier; it " +
			"would be served with none of the approval its schema promises")
	}
	if !strings.Contains(err.Error(), "GrantVerifier") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// The same catalogue, with the step configured, prepares cleanly — so the
// refusal is about this deployment's capability and not a permanent ban.
func TestACatalogueWhoseStepsAreConfiguredPreparesCleanly(t *testing.T) {
	h := chained(&Handler{Store: &countingStore{c: aCatalogue()}, Invoker: &fakeInvoker{}})
	if err := h.Prepare(aCatalogue()); err != nil {
		t.Fatalf("an ordinary catalogue would not prepare: %v", err)
	}
}
