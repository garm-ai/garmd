package serve

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// The listing is where an agent-aware garmd would leak.
//
// internal/catalogue/agentblind_test.go proves the loader mounts an agent's
// two annotated methods as two ordinary tools. That is the mount half. This is
// the other half: the projection a caller actually reads. A model asks this
// endpoint what it may call, and what comes back must be two tools shaped like
// every other tool — approval mode, input schema, guidance — with nothing of
// the agent manifest in it. The manifest names a prompt digest, a step bound,
// a model alias and a compartment list, and every one of those is somebody
// else's business: a garmd that had learned to read the annotation would most
// plausibly show it here, helpfully, as extra metadata.
//
// The fixture protos are DUPLICATED from internal/catalogue rather than
// shared. Sharing them would need a non-test package holding an agent-shaped
// proto in this repository, which is the thing the invariant forbids; and
// there is no test-only import path between two packages' test binaries.

const agentProtoSrc = `syntax = "proto3";
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

const bankAgentProtoSrc = `syntax = "proto3";
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

// agentCatalogue loads the artifact through the real loader. Building a
// catalogue.Catalogue by hand, as the other tests in this package do, would
// skip the descriptors the annotation is attached to and prove nothing.
func agentCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()

	srcs := map[string]string{
		"garm/agent/v1/agent.proto":              agentProtoSrc,
		"bank/agents/v1/support_assistant.proto": bankAgentProtoSrc,
	}
	res := protocompile.WithStandardImports(protocompile.CompositeResolver{
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, protoregistry.NotFound
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}),
		&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(srcs)},
	})
	files, err := (&protocompile.Compiler{Resolver: res}).Compile(context.Background(),
		"garm/agent/v1/agent.proto", "bank/agents/v1/support_assistant.proto")
	if err != nil {
		t.Fatalf("compiling the agent fixture: %v", err)
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
	for _, f := range files {
		collect(f)
	}

	// The round trip the real producer does: protocompile leaves options as
	// dynamic messages, and the tool annotations have to resolve against the
	// linked extension types before the loader can read them. Extension 50101
	// resolves against nothing here, which is exactly its production state.
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
		Provenance:              &cataloguev1.Provenance{Producer: "serve_test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cat, err := catalogue.Load(body, time.Now)
	if err != nil {
		t.Fatalf("the agent-bearing catalogue would not load: %v", err)
	}
	return cat
}

// An agent's two methods list as two ordinary tools, and the manifest beside
// them is nowhere in the answer.
func TestTheListingShowsAnAgentAsTwoToolsAndNothingOfItsManifest(t *testing.T) {
	cat := agentCatalogue(t)
	h := chained(&Handler{
		Store:    &countingStore{c: cat},
		Invoker:  &fakeInvoker{fill: "x"},
		Log:      discardLogger(),
		Recorder: &record.Memory{},
		Principals: principalFunc(&toolplane.Principal{
			Subject:   "employee:jdoe",
			Kind:      toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
			Clearance: toolv1.Clearance_CLEARANCE_INTERNAL,
			Verbs: toolplane.NewVerbSet(toolv1.Verb_VERB_READ,
				toolv1.Verb_VERB_WRITE),
		}),
		Grants: refusingGrants{},
	})
	if err := h.Prepare(cat); err != nil {
		t.Fatalf("the agent-bearing catalogue would not mount: %v", err)
	}

	w, got := listTools(t, h)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	if len(got.Tools) != 2 {
		t.Fatalf("%d tools listed, want 2: %+v", len(got.Tools), got.Tools)
	}
	if got.Tools[0].FQN != "bank.agents.v1.support_assistant" ||
		got.Tools[1].FQN != "bank.agents.v1.support_assistant_run" {
		t.Fatalf("listed = %v, want the agent's two annotated methods",
			[]string{got.Tools[0].FQN, got.Tools[1].FQN})
	}

	// Shaped like every other tool. An agent-aware projection would have had
	// somewhere to put the manifest, and these are the fields it would have
	// grown a sibling to.
	for _, tl := range got.Tools {
		if tl.ApprovalMode != "MODE_UNSPECIFIED" {
			t.Errorf("%s: approval_mode = %q, want MODE_UNSPECIFIED", tl.FQN,
				tl.ApprovalMode)
		}
		if _, ok := tl.InputSchema["properties"]; !ok {
			t.Errorf("%s: input_schema has no properties: %v", tl.FQN, tl.InputSchema)
		}
		if s, _ := tl.InputSchema["$schema"].(string); s != jsonSchemaDraft {
			t.Errorf("%s: $schema = %q, want %q", tl.FQN, s, jsonSchemaDraft)
		}
	}
	if got.Tools[0].Method != "/bank.agents.v1.SupportAssistant/Invoke" ||
		got.Tools[1].Method != "/bank.agents.v1.SupportAssistant/GetRun" {
		t.Errorf("methods = %v; a caller dispatches on these", []string{
			got.Tools[0].Method, got.Tools[1].Method})
	}
	if got.Tools[0].Verb != "VERB_WRITE" || got.Tools[1].Verb != "VERB_READ" {
		t.Errorf("verbs = %v, want the ones the tool annotations declare",
			[]string{got.Tools[0].Verb, got.Tools[1].Verb})
	}

	// Nothing of the manifest, anywhere in the body. Each of these is a value
	// that exists only inside the agent annotation, so one appearing here
	// means this process read it.
	body := w.Body.String()
	for _, leak := range []string{
		"MODE_REACT",                   // the agent's mode
		"max_steps",                    // its bound
		"fast",                         // the model alias
		"prompts/",                     // the prompt path
		"0000000000",                   // the prompt digest
		"pii-contact",                  // the agent principal's compartments
		"accounts.v1.get_customer",     // a tool it may call
		"payments.v1.initiate_payment", // another
		"amount_minor_units",           // a guard expression
		"AgentPolicy",                  // the annotation's type
		"garm.agent.v1",                // the namespace
	} {
		// A literal that has left the fixture guards nothing; say so
		// rather than staying quietly green.
		if !strings.Contains(agentProtoSrc+bankAgentProtoSrc, leak) {
			t.Fatalf("leak literal %q is no longer in the fixture; this check covers nothing", leak)
		}
		if strings.Contains(body, leak) {
			t.Errorf("the listing carries %q; this process read the agent "+
				"annotation. Body: %s", leak, body)
		}
	}
}
