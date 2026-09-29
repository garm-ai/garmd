package serve

import (
	"context"
	"encoding/json"
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

	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
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
				// The constraint is named — every field here is in this
				// caller's projection — but never the expression that
				// decides it, and never the values the caller sent.
				for _, leak := range []string{"upperAscii", "nope", "usd", "1050"} {
					if strings.Contains(w.Body.String(), leak) {
						t.Errorf("the refusal carries %q, which is not a constraint: %s",
							leak, w.Body.String())
					}
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

// The bank's initiate_payment, as it is declared in examples/bank, carried
// the way a real catalogue carries it. What is under test is the answer a
// model gets when it sends a malformed request: which field, which rule, and
// the constraint's own sentence — never its value, and never a field it was
// not shown.
const bankProto = `syntax = "proto3";
package bankfix.v1;
import "buf/validate/validate.proto";
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/bankfix_v1;x";

message InitiatePaymentRequest {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { mask: {} } };

  string source_account_id = 1 [(buf.validate.field).required = true,
                                (buf.validate.field).string.pattern = "^acct_[a-z0-9]{6,32}$"];
  string beneficiary_iban = 2 [(buf.validate.field).required = true,
                               (buf.validate.field).string.pattern = "^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$"];
  optional int64 amount_minor_units = 3 [
    (garm.tool.v1.field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } },
    (buf.validate.field).required = true,
    (buf.validate.field).int64 = { gt: 0, lte: 1000000000 }
  ];
  string currency_code = 4 [(buf.validate.field).required = true,
                            (buf.validate.field).string.pattern = "^[A-Z]{3}$"];
  optional string reference = 5 [(buf.validate.field).string.max_len = 140];
  string idempotency_key = 6 [(buf.validate.field).required = true,
                              (buf.validate.field).string.pattern = "^[A-Za-z0-9_-]{16,64}$"];

  option (buf.validate.message).cel = {
    id: "initiate_payment.jpy_has_no_minor_units"
    message: "JPY has no minor unit: amount_minor_units must be a whole multiple of 100"
    expression: "this.currency_code != 'JPY' || this.amount_minor_units % 100 == 0"
  };
}

// The withheld case: the amount is writable only at RESTRICTED, so an
// INTERNAL caller's projection does not carry it, and a rule that reads it
// names a field that caller was never shown.
message JpyPay {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { mask: {} } };

  string currency_code = 1 [(buf.validate.field).string.pattern = "^[A-Z]{3}$"];
  optional int64 amount_minor_units = 2 [(garm.tool.v1.field_policy) = {
    read: CLEARANCE_PUBLIC write: CLEARANCE_RESTRICTED on_deny: { omit: {} } }];

  option (buf.validate.message).cel = {
    id: "jpy.needs_an_amount"
    message: "a JPY payment needs an amount"
    expression: "this.currency_code != 'JPY' || this.amount_minor_units > 0"
  };
}

// A rule whose message is COMPUTED: the expression returns a sentence built
// from the value. Protovalidate reports that sentence; the wire must not.
message Echo {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { mask: {} } };

  string account = 1 [(buf.validate.field).cel = {
    id: "account.prefix"
    expression: "this.startsWith('acct_') ? '' : 'expected an account id, got ' + this"
  }];
}
`

var (
	bankOnce sync.Once
	bankFile protoreflect.FileDescriptor
)

func bankMessage(t *testing.T, name protoreflect.Name) protoreflect.MessageDescriptor {
	t.Helper()
	bankOnce.Do(func() { bankFile = compileFixture("bankfix/v1/b.proto", bankProto) })
	md := bankFile.Messages().ByName(name)
	if md == nil {
		t.Fatalf("the bank fixture has no message %s", name)
	}
	return md
}

// compileFixture is validatedMessage's compile-and-round-trip, for a second
// fixture file.
func compileFixture(path, src string) protoreflect.FileDescriptor {
	res := protocompile.WithStandardImports(protocompile.CompositeResolver{
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, protoregistry.NotFound
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}),
		&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(
			map[string]string{path: src})},
	})
	files, err := (&protocompile.Compiler{Resolver: res}).Compile(context.Background(), path)
	if err != nil {
		panic("compiling " + path + ": " + err.Error())
	}
	fdp := protodesc.ToFileDescriptorProto(files[0])
	raw, err := proto.Marshal(fdp)
	if err != nil {
		panic(err)
	}
	fdp = &descriptorpb.FileDescriptorProto{}
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(raw, fdp); err != nil {
		panic(err)
	}
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		panic(err)
	}
	return fd
}

const (
	initiatePaymentRoute = "/bankfix.v1.Payments/InitiatePayment"
	jpyPayRoute          = "/bankfix.v1.Payments/JpyPay"
	echoRoute            = "/bankfix.v1.Payments/Echo"
)

func bankCatalogue(t *testing.T) *catalogue.Catalogue {
	t.Helper()
	def := func(route, name string, md protoreflect.MessageDescriptor) tool.Def {
		return tool.Def{
			FullMethod:   route,
			FQN:          "bankfix.v1." + name,
			Name:         name,
			Input:        md,
			Output:       md,
			Verb:         toolv1.Verb_VERB_READ,
			MinClearance: toolv1.Clearance_CLEARANCE_INTERNAL,
		}
	}
	return &catalogue.Catalogue{
		Digest: aDigest,
		Defs: []tool.Def{
			def(initiatePaymentRoute, "initiate_payment", bankMessage(t, "InitiatePaymentRequest")),
			def(jpyPayRoute, "jpy_pay", bankMessage(t, "JpyPay")),
			def(echoRoute, "echo", bankMessage(t, "Echo")),
		},
		DescriptorHashes: map[string]string{"bankfix.v1": good},
	}
}

// violationsBody is the 400 the door writes for a request that broke its
// contract: Connect's shape plus the list.
type violationsBody struct {
	Code       string                `json:"code"`
	Message    string                `json:"message"`
	Violations []toolplane.Violation `json:"violations"`
}

func decodeViolations(t *testing.T, w *httptest.ResponseRecorder) violationsBody {
	t.Helper()
	var b violationsBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("the 400 body is not the violations shape: %v (%q)", err, w.Body.String())
	}
	if b.Violations == nil {
		t.Fatalf("violations is null, want an array: %s", w.Body.String())
	}
	return b
}

func bankCall(t *testing.T, principal *toolplane.Principal, route, body string) (
	*httptest.ResponseRecorder, *record.Memory,
) {
	t.Helper()
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:      &countingStore{c: bankCatalogue(t)},
		Invoker:    &fakeInvoker{fill: "x", field: "currency_code"},
		Recorder:   rec,
		Principals: principalFunc(principal),
	})
	return call(t, h, jsonReq(route, body)), rec
}

const badAccount = "not-an-account-7b2"

func TestAViolationOnAnAdmittedFieldNamesTheFieldAndTheRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want toolplane.Violation
	}{
		{
			"a field constraint: the source account pattern",
			`{"source_account_id":"` + badAccount + `","beneficiary_iban":"GB33BUKB20201555555555",` +
				`"amount_minor_units":"1000","currency_code":"GBP","idempotency_key":"run_01J9-dispatch-0004"}`,
			toolplane.Violation{Field: "source_account_id", Rule: "string.pattern",
				Message: "does not match regex pattern `^acct_[a-z0-9]{6,32}$`"},
		},
		{
			"a message-level rule whose every field is admitted",
			`{"source_account_id":"acct_ops001","beneficiary_iban":"GB33BUKB20201555555555",` +
				`"amount_minor_units":"1050","currency_code":"JPY","idempotency_key":"run_01J9-dispatch-0004"}`,
			toolplane.Violation{Field: "", Rule: "initiate_payment.jpy_has_no_minor_units",
				Message: "JPY has no minor unit: amount_minor_units must be a whole multiple of 100"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, rec := bankCall(t, admitted(), initiatePaymentRoute, tc.body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
			b := decodeViolations(t, w)
			if b.Code != "invalid_argument" {
				t.Errorf("code = %q, want invalid_argument", b.Code)
			}
			if len(b.Violations) != 1 || b.Violations[0] != tc.want {
				t.Errorf("violations = %+v, want exactly %+v", b.Violations, tc.want)
			}
			// The value the caller sent is the one thing a violation must not
			// carry: the caller has it, and an error path that quotes request
			// content is the habit that leaks somewhere else later.
			if strings.Contains(w.Body.String(), badAccount) || strings.Contains(w.Body.String(), "1050") {
				t.Errorf("the body echoes a value the caller sent: %s", w.Body.String())
			}

			// The ledger row is what it was before any of this: the full
			// protovalidate text, in the detail column and nowhere else.
			events := rec.Events()
			if len(events) != 1 {
				t.Fatalf("%d ledger rows, want 1", len(events))
			}
			ev := events[0]
			if ev.Outcome != ledger.OutcomeDenied {
				t.Errorf("outcome = %q, want denied", ev.Outcome)
			}
			wantDetail := "input validation refused: validation error: "
			if tc.want.Field != "" {
				wantDetail += tc.want.Field + ": "
			}
			wantDetail += tc.want.Message
			if ev.ErrorDetail != wantDetail {
				t.Errorf("error_detail = %q, want %q", ev.ErrorDetail, wantDetail)
			}
			assertEveryRowNamesThePlane(t, rec)
		})
	}
}

// A cross-field rule that reads a field this caller may not write is not
// listed, however admitted the field it is reported ON. The rule fires
// because the withheld field is absent — that is the whole point of a field
// the caller cannot set — and naming it would tell the caller a field exists
// that its own schema does not show.
func TestACrossFieldRuleNamingAWithheldFieldIsNotListed(t *testing.T) {
	w, rec := bankCall(t, admitted(), jpyPayRoute, `{"currency_code":"JPY"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	b := decodeViolations(t, w)
	if len(b.Violations) != 0 {
		t.Errorf("violations = %+v, want none: the rule reads amount_minor_units, which "+
			"this caller was never shown", b.Violations)
	}
	for _, leak := range []string{"amount_minor_units", "jpy.needs_an_amount", "needs an amount"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the body carries %q: %s", leak, w.Body.String())
		}
	}
	// On the row, as before.
	events := rec.Events()
	if len(events) != 1 || !strings.Contains(events[0].ErrorDetail, "a JPY payment needs an amount") {
		t.Errorf("the ledger row lost the detail: %+v", events)
	}

	// The control: a caller whose projection DOES carry the amount is told.
	restricted := admitted()
	restricted.Clearance = toolv1.Clearance_CLEARANCE_RESTRICTED
	w, _ = bankCall(t, restricted, jpyPayRoute, `{"currency_code":"JPY"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	want := toolplane.Violation{Rule: "jpy.needs_an_amount", Message: "a JPY payment needs an amount"}
	if b := decodeViolations(t, w); len(b.Violations) != 1 || b.Violations[0] != want {
		t.Errorf("violations = %+v, want exactly %+v", b.Violations, want)
	}
}

// A rule whose sentence is computed from the value is reported by its id
// alone. The sentence protovalidate produced is on the ledger row, where
// request content is allowed to be.
func TestAComputedRuleMessageNeverReachesTheWire(t *testing.T) {
	const secret = "SECRET-ACCOUNT-9f1"
	w, rec := bankCall(t, admitted(), echoRoute, `{"account":"`+secret+`"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	want := toolplane.Violation{Field: "account", Rule: "account.prefix"}
	if b := decodeViolations(t, w); len(b.Violations) != 1 || b.Violations[0] != want {
		t.Errorf("violations = %+v, want exactly %+v", b.Violations, want)
	}
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "expected an account id") {
		t.Errorf("the computed message reached the wire: %s", w.Body.String())
	}
	if events := rec.Events(); len(events) != 1 || !strings.Contains(events[0].ErrorDetail, secret) {
		t.Errorf("the ledger row does not carry the detail: %+v", events)
	}
}
