package serve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bufbuild/protocompile"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
)

// Constraints must survive the trip through the catalogue and fire on a
// message this binary has never seen.
//
// This is the step most likely to stop working without anything saying so.
// protovalidate reads buf.validate extensions off the descriptor, and every
// descriptor here arrives as bytes in an artifact, is parsed at boot, and is
// instantiated as dynamicpb. If the extensions did not survive that — a
// resolver that did not know buf.validate, a producer that stripped unknown
// options — protovalidate would find no constraints and report every message
// valid. Nothing would error. Every declared rule would simply stop being
// enforced, and the first sign would be a malformed request reaching a tool.
//
// So the assertion is not "validation works" in the abstract. It is that
// these exact declarations, carried the way this system carries them, still
// refuse.

const validatedProto = `syntax = "proto3";
package vld.v1;
import "buf/validate/validate.proto";
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/vld_v1;x";

message Pay {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };

  // A plain field constraint.
  optional string account = 1 [(buf.validate.field).string.pattern = "^acct_[a-z0-9]{4,32}$"];

  // A field-level CEL rule.
  optional string code = 2 [(buf.validate.field).cel = {
    id: "code.upper"
    message: "code must be upper case"
    expression: "this == this.upperAscii()"
  }];

  optional int64 amount = 3;
  optional string currency = 4;

  // The rule no single field can express, and the reason CEL earns its
  // weight: ISO 4217 gives JPY zero decimal places, so a value that is not a
  // whole multiple of 100 means the caller applied a two-decimal assumption
  // that does not hold. Both fields are individually valid; only their
  // relationship is wrong.
  option (buf.validate.message).cel = {
    id: "pay.jpy_has_no_minor_units"
    message: "JPY has no minor unit: amount must be a whole multiple of 100"
    expression: "this.currency != 'JPY' || this.amount % 100 == 0"
  };
}
`

var (
	vldOnce sync.Once
	vldMsg  protoreflect.MessageDescriptor
)

func validatedMessage(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	vldOnce.Do(func() {
		res := protocompile.WithStandardImports(protocompile.CompositeResolver{
			protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
				fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
				if err != nil {
					return protocompile.SearchResult{}, protoregistry.NotFound
				}
				return protocompile.SearchResult{Desc: fd}, nil
			}),
			&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(
				map[string]string{"vld/v1/p.proto": validatedProto})},
		})
		files, err := (&protocompile.Compiler{Resolver: res}).
			Compile(context.Background(), "vld/v1/p.proto")
		if err != nil {
			panic("compiling the validated fixture: " + err.Error())
		}
		// The same round trip the producer does. Verified by mutation to be
		// unnecessary for buf.validate specifically — protovalidate reads
		// options through a path that tolerates protocompile's dynamic form —
		// and kept because the fixture should travel the way a real catalogue
		// travels, and garm's OWN annotations do need it.
		fdp := protodesc.ToFileDescriptorProto(files[0])
		raw, err := proto.Marshal(fdp)
		if err != nil {
			panic(err)
		}
		fdp = &descriptorpb.FileDescriptorProto{}
		if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).
			Unmarshal(raw, fdp); err != nil {
			panic(err)
		}
		fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
		if err != nil {
			panic(err)
		}
		vldMsg = fd.Messages().ByName("Pay")
	})
	return vldMsg
}

func payCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()
	md := validatedMessage(t)
	return &catalogue.Catalogue{
		Digest: aDigest,
		Defs: []tool.Def{{
			FullMethod:   "/vld.v1.Payments/Pay",
			FQN:          "vld.v1.pay",
			Name:         "pay",
			Input:        md,
			Output:       md,
			Verb:         toolv1.Verb_VERB_READ,
			MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		}},
		DescriptorHashes: map[string]string{"vld.v1": good},
	}
}

func TestDeclaredConstraintsStillRefuseOnTheDynamicPath(t *testing.T) {
	md := validatedMessage(t)
	f := func(n string) protoreflect.FieldDescriptor { return md.Fields().ByName(protoreflect.Name(n)) }

	body := func(account, code, currency string, amount int64) string {
		m := dynamicpb.NewMessage(md)
		m.Set(f("account"), protoreflect.ValueOfString(account))
		m.Set(f("code"), protoreflect.ValueOfString(code))
		m.Set(f("currency"), protoreflect.ValueOfString(currency))
		m.Set(f("amount"), protoreflect.ValueOfInt64(amount))
		b, err := protojson.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	for _, tc := range []struct {
		name    string
		body    string
		refused bool
	}{
		{"a field constraint: the account pattern",
			body("nope", "USD", "USD", 100), true},
		{"a field-level CEL rule: the code must be upper case",
			body("acct_ab12", "usd", "USD", 100), true},
		{"a message-level CEL rule: JPY has no minor unit",
			body("acct_ab12", "USD", "JPY", 1050), true},
		{"a request that breaks none of them",
			body("acct_ab12", "USD", "JPY", 1000), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := &fakeInvoker{fill: "USD", field: "code"}
			h := chained(&Handler{
				Store:   &countingStore{c: payCatalogue(t)},
				Invoker: inv,
			})

			w := call(t, h, jsonReq("/vld.v1.Payments/Pay", tc.body))

			if tc.refused {
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400: the declaration was carried in the "+
						"catalogue and is no longer being enforced: %s", w.Code, w.Body.String())
				}
				// The reason validation sits before the resolver: a request
				// that can never succeed must cost no network round trip and
				// no side effect from a handler that was about to write.
				if n := inv.calls.Load(); n != 0 {
					t.Errorf("the tool was called %d times with a request that "+
						"violates its own contract", n)
				}
				// The violation text names the field and may name a field the
				// caller cannot read, so it belongs on the ledger, not the wire.
				if b := w.Body.String(); strings.Contains(b, "upperAscii") ||
					strings.Contains(b, "acct_") || strings.Contains(b, "JPY has no") {
					t.Errorf("the refusal quotes the constraint back to the caller: %s", b)
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: a valid request was refused: %s",
					w.Code, w.Body.String())
			}
		})
	}
}

func jsonReq(route, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
	r.Header.Set("Content-Type", contentJSON)
	return r
}
