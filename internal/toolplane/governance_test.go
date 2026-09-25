package toolplane

import (
	"context"
	"strings"
	"testing"

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
			"no audit stream exists",
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
	for _, want := range []string{"GrantVerifier", "audit stream", "FGAChecker"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so fixing this tool takes more "+
				"than one attempt: %v", want, err)
		}
	}
}
