package toolplane_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/policy/testdata"
	"github.com/garm-ai/garm/policy/testdata/testdatagarm"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// testProcedure is the one procedure the core tests register. It is
// deliberately not one of the fixture service's real procedures: these tests
// exercise Core directly, with no connect handler and no HTTP anywhere.
const testProcedure = "/toolplane.test/CoreInvoke"

// The three resolvers the table below switches between. One line each, kept
// here rather than in helpers_test.go so a reader of the test can see
// exactly what each case does.

func okResolver(context.Context, proto.Message) (proto.Message, error) {
	return &testdata.Profile{Id: "u_1", Locale: "en-GB"}, nil
}

func errResolver(context.Context, proto.Message) (proto.Message, error) {
	return nil, errors.New("resolver failed")
}

func panicResolver(context.Context, proto.Message) (proto.Message, error) {
	panic("resolver blew up")
}

// countingRecorder counts ledger events and keeps the last one, so a test
// can assert both "exactly one" and "and it said the right thing".
type countingRecorder struct {
	mu   sync.Mutex
	n    int
	last ledger.Event
}

func (r *countingRecorder) Record(_ context.Context, ev ledger.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	r.last = ev
}

func (r *countingRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *countingRecorder) event() ledger.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// coreToolDef is the tool testProcedure serves: MinClearance INTERNAL, so a
// PUBLIC principal fails the visibility gate and a CONFIDENTIAL one clears
// it.
// coreToolFQN is coreToolDef's FQN, exported to this test package as a
// constant so a test that needs to assert an AvailabilitySource was
// consulted with THIS tool's identity (not some other value, and not the
// zero value) does not have to re-derive it.
const coreToolFQN = "toolplane.test.core_invoke"

func coreToolDef() toolplane.ToolDef {
	pd := (*testdata.Profile)(nil).ProtoReflect().Descriptor()
	return toolplane.ToolDef{
		FullMethod:   testProcedure,
		Name:         "core_invoke",
		FQN:          coreToolFQN,
		Verb:         toolv1.Verb_VERB_READ,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        pd,
		Output:       pd,
	}
}

func testPrincipal(clearance toolv1.Clearance) *toolplane.Principal {
	return &toolplane.Principal{
		Subject:   "user:core",
		Tenant:    "acme",
		Clearance: clearance,
		Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
	}
}

// testRequest is a Profile setting only `id`, which is CLEARANCE_PUBLIC to
// read and therefore to write: the input check must not be what refuses any
// of these cases.
func testRequest() proto.Message { return &testdata.Profile{Id: "u_1"} }

// coreOption customizes the CoreConfig testCore builds, for the tests that
// install one of the pluggable steps.
type coreOption func(*toolplane.CoreConfig)

func withFGA(f toolplane.FGAChecker) coreOption {
	return func(c *toolplane.CoreConfig) { c.FGA = f }
}

func withGrants(g toolplane.GrantVerifier) coreOption {
	return func(c *toolplane.CoreConfig) { c.Grants = g }
}

func testCore(
	t *testing.T, rec ledger.Recorder, fn toolplane.ResolverFunc, opts ...coreOption,
) *toolplane.Core {
	t.Helper()
	cfg := toolplane.CoreConfig{
		HashKey:      []byte("test-key"),
		Compartments: testdatagarm.Compartments,
		Recorder:     rec,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	core, err := toolplane.NewCore(cfg)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	if err := core.AddTools([]toolplane.ToolDef{coreToolDef()}); err != nil {
		t.Fatalf("AddTools: %v", err)
	}
	if err := core.Register(testProcedure,
		func() proto.Message { return &testdata.Profile{} }, fn); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return core
}

// Exactly one ledger event per terminal path — including a resolver that
// panics. Before the core this was spread across the interceptor's return
// paths, so a new return was a silently missing event. In the core it is one
// defer.
func TestInvokeLedgersExactlyOnceIncludingPanic(t *testing.T) {
	// wantErr says what the case's NAME already claims. Without it the
	// "denied at authz" row passes whether Invoke denies the call or hands
	// back the profile, which would make this table blind to the one
	// regression it is best placed to catch.
	for name, tc := range map[string]struct {
		resolver  toolplane.ResolverFunc
		clearance toolv1.Clearance
		wantErr   bool
	}{
		"happy path":      {okResolver, toolv1.Clearance_CLEARANCE_CONFIDENTIAL, false},
		"denied at authz": {okResolver, toolv1.Clearance_CLEARANCE_PUBLIC, true},
		"resolver errors": {errResolver, toolv1.Clearance_CLEARANCE_CONFIDENTIAL, true},
		"resolver panics": {panicResolver, toolv1.Clearance_CLEARANCE_CONFIDENTIAL, true},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &countingRecorder{}
			core := testCore(t, rec, tc.resolver)
			_, err := core.Invoke(context.Background(), testPrincipal(tc.clearance),
				testProcedure, testRequest())
			if tc.wantErr && err == nil {
				t.Fatal("the call succeeded; this case is supposed to be refused")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("the call was refused: %v", err)
			}
			if rec.count() != 1 {
				t.Fatalf("recorded %d events, want exactly 1", rec.count())
			}
		})
	}
}

// http.ErrAbortHandler is the one panic the chain must NOT convert. net/http
// and connect's own recover both re-raise it, because it means "drop this
// connection, write nothing"; turning it into an error response would be
// this package inventing an answer the handler deliberately withheld. The
// ledger row is still owed, and still exactly one.
func TestInvokeReRaisesErrAbortHandler(t *testing.T) {
	rec := &countingRecorder{}
	core := testCore(t, rec, func(context.Context, proto.Message) (proto.Message, error) {
		panic(http.ErrAbortHandler)
	})

	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler re-raised unchanged", r)
		}
		if rec.count() != 1 {
			t.Errorf("recorded %d events for an aborted call, want exactly 1", rec.count())
		}
	}()

	_, _ = core.Invoke(context.Background(),
		testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL), testProcedure, testRequest())
	t.Fatal("Invoke swallowed http.ErrAbortHandler and returned normally")
}

// A panicking resolver must not take the process down, and must not look
// like a successful call.
func TestInvokeConvertsAResolverPanicIntoAnError(t *testing.T) {
	rec := &countingRecorder{}
	core := testCore(t, rec, panicResolver)
	_, err := core.Invoke(context.Background(),
		testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL), testProcedure, testRequest())
	if err == nil {
		t.Fatal("a panicking resolver returned no error")
	}
	// The ledger row must not read as a call that went fine. An event that
	// escapes a panic with outcome "ok" is worse than no event at all.
	if got := rec.event().Outcome; got != ledger.OutcomeError {
		t.Fatalf("ledger outcome = %q after a panic, want %q", got, ledger.OutcomeError)
	}
}

// ---- step 1: a surface that skipped it ----

// Invoke is exported and is the ONLY entry point MCP and cmd/garm will have.
// A surface that hands it no Principal has skipped step 1, and every step
// below dereferences one. Before the guard this panicked, the chain's own
// recover caught it, and the ledger row read "resolver panicked: invalid
// memory address" for a call that never reached a resolver — a refusal
// disguised as a crash.
func TestInvokeRefusesANilPrincipalWithoutPanicking(t *testing.T) {
	rec := &countingRecorder{}
	ran := false
	core := testCore(t, rec, func(context.Context, proto.Message) (proto.Message, error) {
		ran = true
		return &testdata.Profile{Id: "u_1"}, nil
	})

	resp, err := core.Invoke(context.Background(), nil, testProcedure, testRequest())

	if err == nil {
		t.Fatal("Invoke accepted a call with no principal")
	}
	if resp != nil {
		t.Fatal("Invoke returned a response for a call with no principal")
	}
	if ran {
		t.Fatal("the resolver ran for a call with no principal")
	}
	if rec.count() != 1 {
		t.Fatalf("recorded %d events, want exactly 1", rec.count())
	}
	if d := rec.event().ErrorDetail; !strings.Contains(d, "no principal") {
		t.Errorf("ledger detail = %q, want it to name the missing principal", d)
	}
	// The specific regression: a step-1 refusal must not be ledgered as a
	// crash in step 6.
	if d := rec.event().ErrorDetail; strings.Contains(d, "panicked") {
		t.Errorf("a missing principal was ledgered as a panic: %q", d)
	}
}

// ---- steps 4, 5 and 7: the pluggable seams ----

// stubFGA is an FGAChecker whose two halves are whatever the test says. A nil
// func means "allow", so a case can exercise one half without the other.
type stubFGA struct {
	pre  func() error
	post func(proto.Message) (proto.Message, error)
}

func (s *stubFGA) Pre(_ context.Context, _ *toolplane.Principal, _ toolplane.ToolDef, _ proto.Message) error {
	if s.pre == nil {
		return nil
	}
	return s.pre()
}

func (s *stubFGA) Post(
	_ context.Context, _ *toolplane.Principal, _ toolplane.ToolDef, resp proto.Message,
) (proto.Message, error) {
	if s.post == nil {
		return resp, nil
	}
	return s.post(resp)
}

// stubGrants is a GrantVerifier that returns whatever the test says.
type stubGrants struct{ err error }

func (s *stubGrants) Verify(_ context.Context, _ *toolplane.Principal, _ toolplane.ToolDef) error {
	return s.err
}

// A seam that is DECLARED and refuses must close the call — and steps 4 and 5
// must close it before the resolver runs at all, because refusing after the
// effect has happened is not refusing.
//
// These are the branches a future edit could flip to fail-open with nothing
// else going red: the brief singles them out precisely because "nil means not
// declared" and "nil means the check failed and we carried on" are one
// keystroke apart.
func TestDeclaredSeamsFailClosed(t *testing.T) {
	refused := errors.New("no")

	for name, tc := range map[string]struct {
		opt coreOption
		// wantResolverRan is the load-bearing half: a pre-resolver step
		// that refuses AFTER the tool has run has governed nothing.
		wantResolverRan bool
		wantDetail      string
	}{
		"fga pre refuses": {
			opt:             withFGA(&stubFGA{pre: func() error { return refused }}),
			wantResolverRan: false,
			wantDetail:      "instance authorization (pre) refused",
		},
		"grant verification refuses": {
			opt:             withGrants(&stubGrants{err: refused}),
			wantResolverRan: false,
			wantDetail:      "grant verification refused",
		},
		"fga post refuses": {
			opt: withFGA(&stubFGA{post: func(proto.Message) (proto.Message, error) {
				return nil, refused
			}}),
			wantResolverRan: true,
			wantDetail:      "instance authorization (post) refused",
		},
		"fga post returns no message": {
			opt: withFGA(&stubFGA{post: func(proto.Message) (proto.Message, error) {
				return nil, nil
			}}),
			wantResolverRan: true,
			wantDetail:      "instance authorization (post) returned no message",
		},
		"fga post replaces the message": {
			// A Post that REPLACES rather than filters in place: the
			// connect adapter returns the object the handler produced, so
			// the replacement would be sanitized and then dropped while
			// the original, unfiltered message went out.
			opt: withFGA(&stubFGA{post: func(proto.Message) (proto.Message, error) {
				return &testdata.Profile{Id: "substituted"}, nil
			}}),
			wantResolverRan: true,
			wantDetail:      "instance authorization (post) replaced the message",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &countingRecorder{}
			ran := false
			core := testCore(t, rec, func(context.Context, proto.Message) (proto.Message, error) {
				ran = true
				return &testdata.Profile{Id: "u_1", NationalId: proto.String(sensitiveNatID)}, nil
			}, tc.opt)

			resp, err := core.Invoke(context.Background(),
				testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL),
				testProcedure, testRequest())

			if err == nil {
				t.Fatal("a declared seam refused and the call succeeded anyway")
			}
			if resp != nil {
				t.Fatal("a refused call returned a response; a filter that cannot " +
					"run must not return the unfiltered message")
			}
			if ran != tc.wantResolverRan {
				t.Errorf("resolver ran = %v, want %v", ran, tc.wantResolverRan)
			}
			if rec.count() != 1 {
				t.Fatalf("recorded %d events, want exactly 1", rec.count())
			}
			if d := rec.event().ErrorDetail; !strings.Contains(d, tc.wantDetail) {
				t.Errorf("ledger detail = %q, want it to name %q", d, tc.wantDetail)
			}
		})
	}
}

// The other direction, and the reason the nil check cannot simply be "deny":
// a nil seam means the step was NOT DECLARED, and a declared seam that allows
// must not be mistaken for one that refused. Both must let the call through.
func TestUndeclaredAndAllowingSeamsLetTheCallThrough(t *testing.T) {
	for name, opts := range map[string][]coreOption{
		"no seams declared at all": nil,
		"declared and allowing": {
			withFGA(&stubFGA{}),
			withGrants(&stubGrants{}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &countingRecorder{}
			core := testCore(t, rec, okResolver, opts...)

			resp, err := core.Invoke(context.Background(),
				testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL),
				testProcedure, testRequest())

			if err != nil {
				t.Fatalf("the call was refused with nothing declaring a refusal: %v", err)
			}
			if resp == nil {
				t.Fatal("the call succeeded with no response")
			}
			if got := rec.event().Outcome; got != ledger.OutcomeOK {
				t.Errorf("ledger outcome = %q, want %q", got, ledger.OutcomeOK)
			}
		})
	}
}

// TestAddToolsRefusesADifferingRedeclaration pins the rule AddTools did not
// have: a second, DIFFERENT declaration for the same FullMethod is refused,
// not applied.
//
// Before this, `c.tools[t.FullMethod] = t` overwrote silently. Declaring
// core_invoke at CLEARANCE_RESTRICTED and then declaring it again at
// CLEARANCE_PUBLIC left the PUBLIC policy in force, with no error at startup
// and no trace of the declaration that lost. Reachable in a real build by
// wiring one Core through both RegisterXService (which reaches AddTools via
// MountService) and toolindex.Mount — a combination Ruling 11 accepted.
//
// The weakening is what makes it a policy bug rather than a tidiness one, so
// the test asserts the POLICY, not just the error: a PUBLIC principal must
// still be denied afterwards.
func TestAddToolsRefusesADifferingRedeclaration(t *testing.T) {
	core := testCore(t, &countingRecorder{}, okResolver)

	restricted := coreToolDef()
	restricted.MinClearance = toolv1.Clearance_CLEARANCE_RESTRICTED
	if err := core.AddTools([]toolplane.ToolDef{restricted}); err == nil {
		t.Fatal("AddTools accepted a second declaration for the same method " +
			"with a different MinClearance; the last one in silently wins")
	}

	// The differing declaration must not have taken effect either. testCore
	// declared core_invoke at CLEARANCE_INTERNAL, so PUBLIC is below it.
	if _, err := core.Invoke(context.Background(),
		testPrincipal(toolv1.Clearance_CLEARANCE_PUBLIC),
		testProcedure, testRequest()); err == nil {
		t.Error("a CLEARANCE_PUBLIC principal invoked a CLEARANCE_INTERNAL tool; " +
			"the refused re-declaration was applied anyway")
	}

	// A differing declaration is refused wherever the difference is, not
	// only in the one field a naive check would compare.
	for name, mutate := range map[string]func(*toolplane.ToolDef){
		"Verb":         func(d *toolplane.ToolDef) { d.Verb = toolv1.Verb_VERB_WRITE },
		"Name":         func(d *toolplane.ToolDef) { d.Name = "core_invoke_v2" },
		"Sets":         func(d *toolplane.ToolDef) { d.Sets = []string{"support"} },
		"Title":        func(d *toolplane.ToolDef) { d.Title = "something else" },
		"Compartments": func(d *toolplane.ToolDef) { d.Compartments = []string{"pii-contact"} },
	} {
		t.Run(name, func(t *testing.T) {
			def := coreToolDef()
			mutate(&def)
			if err := core.AddTools([]toolplane.ToolDef{def}); err == nil {
				t.Errorf("AddTools accepted a re-declaration differing in %s", name)
			}
		})
	}
}

// TestAddToolsAcceptsAnIdenticalRedeclaration is the other half of the
// choice above, and it is deliberate rather than incidental.
//
// Core.Register refuses ANY duplicate because it cannot do otherwise: a
// ResolverFunc is a closure and closures are not comparable, so "is this the
// same resolver?" has no answer there. A ToolDef is data. The thing worth
// refusing is a declaration that DISAGREES with the one in force; an
// identical one changes no decision and loses nothing.
//
// It also arrives legitimately. Ruling 11 accepted that the generated Mount
// calls AddTools as well as RegisterXService, so one Core wired through both
// receives each package's declarations twice, byte for byte. Refusing that
// would turn a supported wiring into a startup failure and buy no safety.
func TestAddToolsAcceptsAnIdenticalRedeclaration(t *testing.T) {
	core := testCore(t, &countingRecorder{}, okResolver)

	// testCore already declared exactly this.
	if err := core.AddTools([]toolplane.ToolDef{coreToolDef()}); err != nil {
		t.Fatalf("AddTools refused an identical re-declaration: %v", err)
	}
	if _, err := core.Invoke(context.Background(),
		testPrincipal(toolv1.Clearance_CLEARANCE_CONFIDENTIAL),
		testProcedure, testRequest()); err != nil {
		t.Errorf("the tool stopped working after an identical re-declaration: %v", err)
	}
}

// Kind reaches the ledger, which is the only reason it exists. A field
// carried through authn and then dropped before the row is written would
// answer nothing.
func TestTheLedgerRecordsThePrincipalKind(t *testing.T) {
	rec := &record.Memory{}
	core := testCore(t, rec, func(_ context.Context, _ proto.Message) (proto.Message, error) {
		return &testdata.Profile{Id: "u_1"}, nil
	})

	p := testPrincipal(toolv1.Clearance_CLEARANCE_RESTRICTED)
	p.Kind = toolv1.PrincipalKind_PRINCIPAL_KIND_AGENT

	_, _ = core.Invoke(context.Background(), p, testProcedure, testRequest())

	events := rec.Events()
	if len(events) == 0 {
		t.Fatal("no ledger event")
	}
	if got := events[0].PrincipalKind; got != "PRINCIPAL_KIND_AGENT" {
		t.Errorf("PrincipalKind = %q, want PRINCIPAL_KIND_AGENT — the question this "+
			"field exists to answer is which rows were agents", got)
	}
}
