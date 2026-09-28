package catalogue_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/garm-ai/garmd/internal/catalogue"
)

// garmd does not know about agents, and this is the test that keeps it true.
//
// An agent reaches this daemon as a proto service with two annotated methods.
// The garm.agent.v1.agent ServiceOption beside them is a namespace this binary
// has never heard of, and the whole design rests on that staying uninteresting:
// the loader's schema check is scoped to garm.tool.v1 for exactly this reason,
// and widening it would refuse an agent-bearing catalogue at boot — agent
// awareness acquired through an error message.
//
// The extension is DECLARED here in proto source rather than imported from
// garm's generated Go. Importing it would be this repository learning the
// agent annotation's type in order to prove it does not read it, which is
// self-defeating; declaring it means the loader meets extension 50101 the way
// it would in production — as bytes in a service's options that resolve to
// nothing here.

const agentProto = `syntax = "proto3";
package garm.agent.v1;
import "google/protobuf/descriptor.proto";
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/garm_agent_v1;x";

extend google.protobuf.ServiceOptions { AgentPolicy agent = 50101; }

enum Mode { MODE_UNSPECIFIED = 0; MODE_REACT = 1; }

message Principal { repeated string compartments = 1; }
message Model     { string alias = 1; }
message Bounds    { uint32 max_steps = 1; }
message Prompt    { string path = 1; string sha256 = 2; }
message ToolRef   { string fqn = 1; string guard = 2; }

message AgentPolicy {
  Mode mode = 1;
  Principal principal = 2;
  Model model = 3;
  Bounds bounds = 4;
  map<string, Prompt> prompts = 5;
  repeated ToolRef tools = 6;
}

// run_id is optional because the real RunRef declares it so: a singular scalar
// with on_deny omit needs presence (lint L6, program plan §7 item 2).
//
// The message-level default policy is there for the same reason every other
// mounted message carries one: these two cross the hop as a tool's request and
// response, and the chain refuses a field with neither its own policy nor a
// default. Nothing about that is agent-shaped — it is the tool plane's rule
// applied to an agent's messages. internal/serve/agentblind_test.go is where
// that bites, because that is where the catalogue is mounted.
message RunRef {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string run_id = 1;
}
message RunStatus {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string run_id = 1;
  optional string state = 2;
}
`

// bankAgentProto is the shape of spec §2.1: one agent service, two annotated
// methods, the manifest on the service itself.
const bankAgentProto = `syntax = "proto3";
package bank.agents.v1;
import "garm/agent/v1/agent.proto";
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/bank_agents_v1;x";

message SupportRequest {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string question = 1;
}

service SupportAssistant {
  option (garm.agent.v1.agent) = {
    mode: MODE_REACT
    principal: { compartments: ["financial", "pii-contact"] }
    model: { alias: "fast" }
    bounds: { max_steps: 12 }
    prompts: [{ key: "system" value: {
      path: "prompts/support-assistant.md"
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    }}]
    tools: [
      { fqn: "accounts.v1.get_customer" },
      { fqn: "payments.v1.initiate_payment" guard: "args.amount_minor_units <= 500000" }
    ]
  };

  rpc Invoke(SupportRequest) returns (garm.agent.v1.RunRef) {
    option (garm.tool.v1.tool) = {
      name: "support_assistant" verb: VERB_WRITE min_clearance: CLEARANCE_INTERNAL
      sets: ["support"]
    };
  }
  rpc GetRun(garm.agent.v1.RunRef) returns (garm.agent.v1.RunStatus) {
    option (garm.tool.v1.tool) = {
      name: "support_assistant_run" verb: VERB_READ min_clearance: CLEARANCE_INTERNAL
      sets: ["support"]
    };
  }
}
`

func agentCatalogue(t *testing.T) []byte {
	t.Helper()
	return assemble(t, map[string]string{
		"garm/agent/v1/agent.proto":              agentProto,
		"bank/agents/v1/support_assistant.proto": bankAgentProto,
	}, []string{"garm/agent/v1/agent.proto", "bank/agents/v1/support_assistant.proto"})
}

// Two tools, no agent. The annotation is not an error, not a third tool, and
// not a reason to refuse the artifact.
func TestAnAgentBearingCatalogueMountsItsTwoMethodsAsTools(t *testing.T) {
	cat, err := catalogue.Load(agentCatalogue(t), time.Now)
	if err != nil {
		t.Fatalf("a catalogue carrying an agent annotation was refused: %v", err)
	}

	var names []string
	for _, d := range cat.Defs {
		names = append(names, d.FQN)
	}
	if len(cat.Defs) != 2 {
		t.Fatalf("%d tools, want 2: %v", len(cat.Defs), names)
	}
	// Sorted by FQN at load, so this order is stable.
	if names[0] != "bank.agents.v1.support_assistant" ||
		names[1] != "bank.agents.v1.support_assistant_run" {
		t.Errorf("tools = %v, want the two annotated methods", names)
	}
	for _, d := range cat.Defs {
		if d.FullMethod != "/bank.agents.v1.SupportAssistant/Invoke" &&
			d.FullMethod != "/bank.agents.v1.SupportAssistant/GetRun" {
			t.Errorf("unexpected route %q", d.FullMethod)
		}
		if d.Input == nil || d.Output == nil {
			t.Errorf("%s has no descriptors, so nothing could be dispatched to it", d.FQN)
		}
	}
}

// A failure must never mention the namespace. The catalogue's schema check is
// scoped to garm.tool.v1; a check that read every extension namespace would
// refuse this artifact at boot with an error naming garm.agent.v1, which is
// agent-awareness arriving through a message.
func TestNothingInALoadMentionsTheAgentNamespace(t *testing.T) {
	body := agentCatalogue(t)
	if _, err := catalogue.Load(body, time.Now); err != nil {
		if strings.Contains(err.Error(), "garm.agent.v1") {
			t.Fatalf("the loader refused the artifact BY NAMESPACE: %v", err)
		}
		t.Fatalf("the artifact was refused: %v", err)
	}
}

// The annotation's bytes survive the load without being interpreted.
//
// This is the positive statement of the invariant: the option is still there,
// as an unresolvable extension, which is what it means for this binary to carry
// a declaration it does not read. A loader that had parsed it would have had to
// know the type; one that had stripped it would silently break whatever reads
// it downstream.
func TestTheAgentAnnotationSurvivesTheLoadUnread(t *testing.T) {
	cat, err := catalogue.Load(agentCatalogue(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	fd, err := cat.Files.FindFileByPath("bank/agents/v1/support_assistant.proto")
	if err != nil {
		t.Fatalf("the agent's file is not in the registry: %v", err)
	}
	svc := fd.Services().Get(0)
	if svc.FullName() != "bank.agents.v1.SupportAssistant" {
		t.Fatalf("service = %s", svc.FullName())
	}

	// Unknown to THIS binary's type registry, and present. Both halves matter.
	unknown := svc.Options().ProtoReflect().GetUnknown()
	var found bool
	proto.RangeExtensions(svc.Options(), func(xt protoreflect.ExtensionType, _ any) bool {
		if xt.TypeDescriptor().Number() == 50101 {
			found = true
		}
		return true
	})
	// Present AND unresolved. The day this process links garm's agent
	// package, the extension resolves, `found` flips true, and this test
	// fails — which is the point: garmd knowing about agents is the invariant
	// this file guards, not a feature it gains.
	if len(unknown) == 0 {
		t.Error("the agent annotation did not survive the load; a catalogue that " +
			"strips a namespace it does not understand breaks whatever does")
	}
	if found {
		t.Error("the agent annotation RESOLVED in this process: garmd has linked " +
			"the agent package and now knows about agents")
	}
}
