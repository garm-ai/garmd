package toolplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/policy/testdata"
	"github.com/garm-ai/garm/policy/testdata/testdatagarm"
	"google.golang.org/protobuf/proto"
)

// The refusal that stops a tool being served with less supervision than it
// claims.
//
// A schema author is forced into these declarations by the linter, so by the
// time one reaches here the only two outcomes are "this deployment refuses to
// start" and "the tool runs with none of the supervision its schema
// advertises". The first is a bad afternoon. The second is the incident, and
// it is worse than an undeclared tool because the declaration reads as
// protection to everyone who reviews it.

type stubGrants struct{}

func (stubGrants) Verify(context.Context, *Principal, ToolDef) error { return nil }

type stubFGA struct{}

func (stubFGA) Pre(context.Context, *Principal, ToolDef, proto.Message) error { return nil }
func (stubFGA) Post(_ context.Context, _ *Principal, _ ToolDef, resp proto.Message) (proto.Message, error) {
	return resp, nil
}

type stubNotifier struct{}

func (stubNotifier) Notify(context.Context, *Principal, ToolDef, ledger.Event) {}

func coreWith(t *testing.T, cfg CoreConfig) *Core {
	t.Helper()
	cfg.HashKey = []byte("a test hash key")
	// The fixture message declares pii-contact, and a compartment a plan
	// cannot resolve fails the mount before the governance check is reached.
	cfg.Compartments = testdatagarm.Compartments
	if cfg.Recorder == nil {
		cfg.Recorder = nopRecorder{}
	}
	c, err := NewCore(cfg)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	return c
}

type nopRecorder struct{}

func (nopRecorder) Record(context.Context, ledger.Event) {}

func declaring(f func(*ToolDef)) ToolDef {
	pd := (*testdata.Profile)(nil).ProtoReflect().Descriptor()
	d := ToolDef{
		FullMethod:   "/g.v1.S/Do",
		FQN:          "g.v1.do",
		Name:         "do",
		Verb:         toolv1.Verb_VERB_READ,
		MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		Input:        pd,
		Output:       pd,
	}
	f(&d)
	return d
}

func TestADeclarationThisDeploymentCannotHonourRefusesToMount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		def     ToolDef
		wantsay string
	}{
		{
			"a grant nobody can verify",
			declaring(func(d *ToolDef) { d.ApprovalMode = toolv1.Approval_MODE_GRANT }),
			"GrantVerifier",
		},
		{
			"an audit stream that does not exist",
			declaring(func(d *ToolDef) { d.AuditLevel = toolv1.Audit_LEVEL_AUDIT }),
			"no audit Sink",
		},
		{
			"instance authorization with no checker",
			declaring(func(d *ToolDef) { d.HasAuthorization = true }),
			"FGAChecker",
		},
		{
			"a notification nothing will send",
			declaring(func(d *ToolDef) { d.ApprovalMode = toolv1.Approval_MODE_NOTIFY }),
			"Notifier",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := coreWith(t, CoreConfig{})
			err := c.AddTools([]ToolDef{tc.def})
			if err == nil {
				t.Fatal("the tool mounted; it would now be served with none of the " +
					"supervision its schema declares")
			}
			if !strings.Contains(err.Error(), tc.wantsay) {
				t.Errorf("the refusal does not say what is missing, so nobody can act "+
					"on it: %v", err)
			}
			if !strings.Contains(err.Error(), "do") {
				t.Errorf("the refusal does not name the tool: %v", err)
			}
			if c.MountedTools() != 0 {
				t.Errorf("%d tool(s) mounted after a refusal; a partial mount is a "+
					"deployment that half-refused", c.MountedTools())
			}
		})
	}
}

// The other half, and the reason the check reads the Core rather than the
// build: configure the step and the same tool mounts.
//
// Without this, CoreConfig.Grants, .FGA and .Notifier are unreachable — a
// deployment could supply a GrantVerifier and still be told the build does
// not implement grants.
func TestConfiguringTheStepLetsTheSameToolMount(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  ToolDef
		cfg  CoreConfig
	}{
		{
			"a grant with a verifier",
			declaring(func(d *ToolDef) { d.ApprovalMode = toolv1.Approval_MODE_GRANT }),
			CoreConfig{Grants: stubGrants{}},
		},
		{
			"authorization with a checker",
			declaring(func(d *ToolDef) { d.HasAuthorization = true }),
			CoreConfig{FGA: stubFGA{}},
		},
		{
			"notify with a notifier",
			declaring(func(d *ToolDef) { d.ApprovalMode = toolv1.Approval_MODE_NOTIFY }),
			CoreConfig{Notifier: stubNotifier{}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := coreWith(t, tc.cfg)
			if err := c.AddTools([]ToolDef{tc.def}); err != nil {
				t.Fatalf("the step is configured and the tool still would not mount: %v", err)
			}
		})
	}
}

// An UNDECLARED tool mounts on a bare Core. The refusal must be about broken
// promises, not about supervision being mandatory — most tools declare
// nothing and must keep working.
func TestAToolThatDeclaresNothingMountsOnABareCore(t *testing.T) {
	c := coreWith(t, CoreConfig{})
	if err := c.AddTools([]ToolDef{declaring(func(*ToolDef) {})}); err != nil {
		t.Fatalf("a tool declaring no supervision was refused: %v", err)
	}
}

// An enum value this build has never seen is refused, not ignored.
//
// This is the whole reason the check is an allowlist. The enums are closed
// today; the moment either gains a member — MODE_MFA, LEVEL_FORENSIC — a
// denylist would mount it silently ungated, which is the exact failure the
// check exists to prevent. If someone "simplifies" this back to enumerating
// what is unsupported, this test is what fails.
func TestAnUnrecognisedDeclarationIsRefusedRatherThanIgnored(t *testing.T) {
	c := coreWith(t, CoreConfig{
		Grants: stubGrants{}, FGA: stubFGA{}, Notifier: stubNotifier{},
	})

	// A value beyond every member the enums currently define. Configuring
	// every step first means the refusal can only come from not recognising
	// the value itself.
	future := declaring(func(d *ToolDef) { d.ApprovalMode = toolv1.Approval_Mode(9999) })
	if err := c.AddTools([]ToolDef{future}); err == nil {
		t.Error("an unrecognised approval mode mounted; a future enum member must " +
			"refuse by construction, not be waved through because no case matched")
	}

	c2 := coreWith(t, CoreConfig{Grants: stubGrants{}, FGA: stubFGA{}, Notifier: stubNotifier{}})
	futureAudit := declaring(func(d *ToolDef) { d.AuditLevel = toolv1.Audit_Level(9999) })
	if err := c2.AddTools([]ToolDef{futureAudit}); err == nil {
		t.Error("an unrecognised audit level mounted")
	}
}

// Every missing step is named at once. A refusal that reports the first
// problem turns fixing a tool into as many deployments as it has
// declarations.
func TestTheRefusalNamesEveryMissingStepAtOnce(t *testing.T) {
	c := coreWith(t, CoreConfig{})
	everything := declaring(func(d *ToolDef) {
		d.ApprovalMode = toolv1.Approval_MODE_GRANT
		d.AuditLevel = toolv1.Audit_LEVEL_AUDIT
		d.HasAuthorization = true
	})

	err := c.AddTools([]ToolDef{everything})
	if err == nil {
		t.Fatal("a tool declaring grants, an audit stream and authorization mounted " +
			"on a Core with none of them")
	}
	for _, want := range []string{"GrantVerifier", "audit Sink", "FGAChecker"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so fixing this tool takes more "+
				"than one attempt: %v", want, err)
		}
	}
}

// The whole audit block is checked, not just its level.
//
// This is the hole the level-only check left. `audit` has five fields and
// only `level` reached the runtime, so a tool could ask for a blocking,
// seven-year, payload-recording audit trail and mount cleanly against a
// recorder that writes to stdout — simply by saying LEVEL_LEDGER instead of
// LEVEL_AUDIT. The declaration read as protection and bought nothing, which
// is precisely the failure this refusal exists to prevent.
func TestTheWholeAuditBlockIsCheckedNotJustItsLevel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		def     ToolDef
		wantsay string
	}{
		{
			"a blocking audit at the ordinary level",
			declaring(func(d *ToolDef) {
				d.AuditLevel = toolv1.Audit_LEVEL_LEDGER
				d.AuditFailClosed = true
			}),
			"fail_closed",
		},
		{
			"seven years of retention nobody provides",
			declaring(func(d *ToolDef) {
				d.AuditLevel = toolv1.Audit_LEVEL_LEDGER
				d.AuditRetainDays = 2555
			}),
			"retain_days",
		},
		{
			"recording a payload the Event cannot hold",
			declaring(func(d *ToolDef) {
				d.AuditLevel = toolv1.Audit_LEVEL_LEDGER
				d.AuditRecordRequest = true
			}),
			"record_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := coreWith(t, CoreConfig{
				Grants: stubGrants{}, FGA: stubFGA{}, Notifier: stubNotifier{},
			})
			err := c.AddTools([]ToolDef{tc.def})
			if err == nil {
				t.Fatalf("mounted; the tool asks for an audit guarantee nothing here " +
					"provides, and LEVEL_LEDGER must not be a way around the refusal")
			}
			if !strings.Contains(err.Error(), tc.wantsay) {
				t.Errorf("the refusal does not name %q: %v", tc.wantsay, err)
			}
		})
	}
}

// fail_closed cannot be satisfied by ANY Recorder, not merely by the ones
// written so far.
//
// The interface says Record "must not fail the call" and the annotation says
// the call must not proceed unless it was recorded. Those contradict, so this
// refusal cannot be lifted by writing a better sink — it needs a contract
// change. If someone lifts it anyway, this is what fails.
func TestFailClosedIsRefusedEvenWithEveryStepConfigured(t *testing.T) {
	c := coreWith(t, CoreConfig{
		Grants: stubGrants{}, FGA: stubFGA{}, Notifier: stubNotifier{},
	})
	def := declaring(func(d *ToolDef) { d.AuditFailClosed = true })

	if err := c.AddTools([]ToolDef{def}); err == nil {
		t.Fatal("a fail_closed tool mounted with every configurable step supplied; " +
			"the ledger contract still cannot refuse a call, so the guarantee is false")
	}
}

// fakeSink records what it was given and can be made to fail.
type fakeSink struct {
	mu        sync.Mutex
	written   []ledger.Outcome
	ids       []string
	err       error
	retention time.Duration
}

func (f *fakeSink) Write(_ context.Context, ev ledger.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.written = append(f.written, ev.Outcome)
	f.ids = append(f.ids, ev.ID)
	return nil
}

func (f *fakeSink) eventIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

func (f *fakeSink) Retention() time.Duration { return f.retention }

func (f *fakeSink) outcomes() []ledger.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ledger.Outcome(nil), f.written...)
}

func audited(failClosed bool) ToolDef {
	return declaring(func(d *ToolDef) {
		d.AuditLevel = toolv1.Audit_LEVEL_AUDIT
		d.AuditFailClosed = failClosed
	})
}

// A sink that keeps less than the tool promises is refused at mount.
//
// This is the only refusal here that fires against a fully configured
// deployment, and it is the one that catches a real operational mistake:
// everything is wired, the tool says seven years, the bucket says thirty
// days, and nobody finds out until someone goes looking for the row.
func TestASinkThatKeepsLessThanTheToolPromisesIsRefused(t *testing.T) {
	short := &fakeSink{retention: 30 * 24 * time.Hour}
	c := coreWith(t, CoreConfig{Audit: short})
	def := declaring(func(d *ToolDef) {
		d.AuditLevel = toolv1.Audit_LEVEL_AUDIT
		d.AuditRetainDays = 2555
	})

	err := c.AddTools([]ToolDef{def})
	if err == nil {
		t.Fatal("mounted; the tool promises seven years against a sink keeping thirty days")
	}
	if !strings.Contains(err.Error(), "2555") {
		t.Errorf("the refusal does not say what was promised: %v", err)
	}

	// Indefinite retention satisfies any request, which is what zero means.
	forever := &fakeSink{retention: 0}
	c2 := coreWith(t, CoreConfig{Audit: forever})
	if err := c2.AddTools([]ToolDef{def}); err != nil {
		t.Errorf("a sink keeping things indefinitely was refused: %v", err)
	}
}

// fail_closed at LEVEL_LEDGER is a contradiction, not a downgrade.
//
// Only the audit stream may refuse a call; the ledger is contractually
// forbidden from it. Quietly accepting the pairing would leave an author
// believing their call is gated on a record that can never gate it.
func TestFailClosedWithoutTheAuditLevelIsAContradiction(t *testing.T) {
	c := coreWith(t, CoreConfig{Audit: &fakeSink{}})
	def := declaring(func(d *ToolDef) {
		d.AuditLevel = toolv1.Audit_LEVEL_LEDGER
		d.AuditFailClosed = true
	})

	err := c.AddTools([]ToolDef{def})
	if err == nil {
		t.Fatal("fail_closed mounted at LEVEL_LEDGER; the ledger must never refuse a call")
	}
	if !strings.Contains(err.Error(), "LEVEL_AUDIT") {
		t.Errorf("the refusal does not point at the fix: %v", err)
	}
}

// The write-ahead, and the reason it is a write-AHEAD.
//
// A fail_closed tool whose audit record cannot be written must not run. Not
// "must return an error after running" — the side effect must never happen,
// because for anything irreversible a post-hoc refusal tells the caller the
// payment did not go out when it did.
func TestAFailClosedToolDoesNotRunWhenItsAuditRecordCannotBeWritten(t *testing.T) {
	broken := &fakeSink{err: errors.New("the audit store is unreachable")}
	c := coreWith(t, CoreConfig{Audit: broken})
	def := audited(true)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}

	var ran bool
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		ran = true
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}

	_, err := c.Invoke(context.Background(), auditPrincipal(), def.FullMethod, auditProfile())
	if err == nil {
		t.Fatal("the call succeeded with no audit record; fail_closed means the side " +
			"effect must not happen")
	}
	if ran {
		t.Error("the tool RAN despite the audit write failing. For an irreversible tool " +
			"this is the whole failure: the effect happened and the caller was told it " +
			"did not")
	}
	if CodeOfForTest(err) != "unavailable" {
		t.Errorf("code = %q, want unavailable: the audit store being down is an "+
			"operator's problem, not a bad request", CodeOfForTest(err))
	}
}

// The same tool, a working sink: it runs, and the stream holds intent then
// outcome in that order.
func TestAnAuditedCallWritesIntentThenOutcome(t *testing.T) {
	sink := &fakeSink{}
	c := coreWith(t, CoreConfig{Audit: sink})
	def := audited(true)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Invoke(context.Background(), auditPrincipal(), def.FullMethod, auditProfile()); err != nil {
		t.Fatalf("the call failed: %v", err)
	}

	got := sink.outcomes()
	want := []ledger.Outcome{ledger.OutcomeIntent, ledger.OutcomeOK}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("audit stream = %v, want %v. Intent must be written BEFORE the tool "+
			"runs and the outcome after, or an interrupted call is indistinguishable "+
			"from one that never started", got, want)
	}
}

// A tool that asked for an audit trail but NOT a blocking one gets the
// ordinary degrade. Refusing here would give every audited tool fail_closed
// semantics it did not ask for.
func TestAnAuditedButNotFailClosedCallProceedsWhenTheSinkIsDown(t *testing.T) {
	broken := &fakeSink{err: errors.New("the audit store is unreachable")}
	c := coreWith(t, CoreConfig{Audit: broken})
	def := audited(false)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}
	var ran bool
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		ran = true
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Invoke(context.Background(), auditPrincipal(), def.FullMethod, auditProfile()); err != nil {
		t.Fatalf("a non-fail_closed call was refused because the sink was down: %v", err)
	}
	if !ran {
		t.Error("the tool did not run; only fail_closed may stop a call")
	}
}

// A REFUSED call on an audited tool still reaches the stream.
//
// "Someone tried to move money and was turned away" is exactly the row an
// auditor goes looking for. It arrives as an outcome with no preceding
// intent, which is how a refusal reads in this stream.
func TestARefusedCallOnAnAuditedToolStillReachesTheStream(t *testing.T) {
	sink := &fakeSink{}
	c := coreWith(t, CoreConfig{Audit: sink})
	def := audited(false)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}

	// Below the tool's clearance: refused at step 2, long before the resolver.
	under := auditPrincipal()
	under.Clearance = toolv1.Clearance_CLEARANCE_PUBLIC

	if _, err := c.Invoke(context.Background(), under, def.FullMethod, auditProfile()); err == nil {
		t.Fatal("an under-cleared caller reached an audited tool")
	}

	got := sink.outcomes()
	if len(got) != 1 {
		t.Fatalf("audit stream = %v, want exactly one row: a refusal writes an outcome "+
			"and no intent, because the tool was never reached", got)
	}
	if got[0] == ledger.OutcomeIntent {
		t.Error("the refusal was written as an intent; nothing was intended, the call " +
			"was turned away")
	}
}

// auditProfile is the fixture message. helpers_test.go's fullProfile lives in
// the external test package; this file is internal, so it needs its own.
func auditProfile() *testdata.Profile { return &testdata.Profile{Id: "p1"} }

func auditPrincipal() *Principal {
	return &Principal{
		Subject:   "user:auditor",
		Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		Clearance: toolv1.Clearance_CLEARANCE_RESTRICTED,
		Verbs:     NewVerbSet(toolv1.Verb_VERB_READ),
	}
}

// The intent row and the outcome row are two writes of ONE call, and the
// event id is the only thing tying them together.
//
// Without it "started and never finished" — the signal an intent row exists to
// produce — cannot be answered at all: the stream holds an intent and an
// outcome with nothing saying they belong to the same call. The id is minted
// where the call is first observed, so both writes carry it.
func TestTheIntentAndTheOutcomeOfOneCallShareOneEventID(t *testing.T) {
	sink := &fakeSink{}
	c := coreWith(t, CoreConfig{Audit: sink})
	def := audited(true)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Invoke(context.Background(), auditPrincipal(), def.FullMethod, auditProfile()); err != nil {
		t.Fatalf("the call failed: %v", err)
	}

	ids := sink.eventIDs()
	if len(ids) != 2 {
		t.Fatalf("the sink saw %d writes, want 2", len(ids))
	}
	if ids[0] == "" {
		t.Fatal("the audit record carries no event id; delivery is at-least-once and " +
			"consumers dedupe on it, so an empty id makes every redelivery a new row")
	}
	if ids[0] != ids[1] {
		t.Errorf("the intent is %q and the outcome is %q; two writes of one call must "+
			"carry one id or they cannot be matched", ids[0], ids[1])
	}
}

// Two calls are two rows, and a shared id would merge them in any consumer
// that dedupes — which is every consumer, because delivery is at-least-once.
func TestTwoCallsDoNotShareAnEventID(t *testing.T) {
	sink := &fakeSink{}
	c := coreWith(t, CoreConfig{Audit: sink})
	def := audited(false)
	if err := c.AddTools([]ToolDef{def}); err != nil {
		t.Fatal(err)
	}
	resolver := func(context.Context, proto.Message) (proto.Message, error) {
		return auditProfile(), nil
	}
	if err := c.Register(def.FullMethod, func() proto.Message { return auditProfile() }, resolver); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Invoke(context.Background(), auditPrincipal(), def.FullMethod, auditProfile()); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}

	ids := sink.eventIDs()
	if len(ids) != 4 {
		t.Fatalf("the sink saw %d writes, want 4", len(ids))
	}
	if ids[0] == ids[2] {
		t.Errorf("both calls were recorded under id %q; a consumer deduping on the id "+
			"would keep one of them", ids[0])
	}
}
