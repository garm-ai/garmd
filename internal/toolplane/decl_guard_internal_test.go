package toolplane

import (
	"reflect"
	"testing"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// sameDeclarationAs is hand-written: it compares ToolDef field by field, and
// the compiler does not notice when a new field is added and left out. That
// matters because AddTools uses it to decide whether a re-declaration is the
// SAME declaration (allowed — Mount and Register both declare) or a
// DIFFERENT one (refused). A field it forgets is a field a re-declaration can
// silently change, which is how a tool declared RESTRICTED becomes PUBLIC
// without anything saying so.
//
// This test does not check a list of field names, which would only have to be
// maintained in a second place. It sets each exported field to a value
// different from the zero one and asserts sameDeclarationAs NOTICES. A field
// added to ToolDef and not added to sameDeclarationAs fails here, named.
//
// DERIVED fields are exempt, and they now have to be named rather than
// hidden.
//
// The monorepo exempted `need` by keeping it unexported, which worked while
// ToolDef and this test were the same package. ToolDef is an alias to
// tool.Def now, in another package, so every field it carries is exported and
// "unexported means derived" stopped being a rule the compiler enforces.
//
// So the list below is explicit, and adding to it is a decision: a field that
// is part of what an AUTHOR DECLARED must be compared, and one computed at
// load must not be — comparing it would make a catalogue rebuild look like a
// changed declaration.
func TestSameDeclarationAsComparesEveryDeclaredField(t *testing.T) {
	// A distinct non-zero value per field type. A field whose type is not
	// here fails loudly below rather than being skipped silently.
	distinct := map[reflect.Type]any{
		reflect.TypeOf(""):                      "x",
		reflect.TypeOf(false):                   true,
		reflect.TypeOf([]string{}):              []string{"x"},
		reflect.TypeOf(map[string]string{}):     map[string]string{"a": "x"},
		reflect.TypeOf(toolv1.Verb(0)):          toolv1.Verb_VERB_DESTRUCTIVE,
		reflect.TypeOf(toolv1.Clearance(0)):     toolv1.Clearance_CLEARANCE_RESTRICTED,
		reflect.TypeOf(toolv1.Approval_Mode(0)): toolv1.Approval_MODE_GRANT,
		reflect.TypeOf(toolv1.Audit_Level(0)):   toolv1.Audit_Level(2),
		reflect.TypeOf(uint32(0)):               uint32(2555),
		reflect.TypeOf(toolv1.Reversibility(0)): toolv1.Reversibility_REVERSIBILITY_NONE,
		reflect.TypeOf((*protoreflect.MessageDescriptor)(nil)).Elem(): protoreflect.MessageDescriptor(
			(&timestamppb.Timestamp{}).ProtoReflect().Descriptor()),
	}

	// Computed at load, never written by an author. ClientName is assigned by
	// the catalogue loader and depends on what ELSE the catalogue contains —
	// the same tool gets a different one when another package collides with
	// its short name — so comparing it would report a declaration change that
	// no author made.
	derived := map[string]string{
		"ClientName": "assigned by the catalogue loader from collisions across the whole catalogue",
	}

	rt := reflect.TypeOf(ToolDef{})
	checked := 0
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		if why, ok := derived[f.Name]; ok {
			t.Logf("skipping ToolDef.%s: %s", f.Name, why)
			continue
		}
		want, ok := distinct[f.Type]
		if !ok {
			t.Fatalf("ToolDef.%s has type %s, which this test has no distinct "+
				"value for. Add one to `distinct` — and check that "+
				"sameDeclarationAs compares %s at all.", f.Name, f.Type, f.Name)
		}

		base := ToolDef{}
		mutated := ToolDef{}
		reflect.ValueOf(&mutated).Elem().Field(i).Set(reflect.ValueOf(want))

		if sameDeclarationAs(base, mutated) {
			t.Errorf("sameDeclarationAs says two ToolDefs are the same "+
				"declaration when they differ in %s. Add %s to "+
				"sameDeclarationAs (toolplane/server.go) — until then a "+
				"re-declaration can change it silently.", f.Name, f.Name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no exported ToolDef fields were checked; this test verifies nothing")
	}
}

// Input and Output are compared by full name, not descriptor identity: two
// descriptor values for the same message type declare the same tool. Pinned
// because it is the one place the comparison is deliberately loose, and a
// later tightening to == would invent conflicts that do not exist.
func TestSameDeclarationAsComparesMessagesByName(t *testing.T) {
	a := ToolDef{Input: (&emptypb.Empty{}).ProtoReflect().Descriptor()}
	b := ToolDef{Input: (&emptypb.Empty{}).ProtoReflect().Descriptor()}
	if !sameDeclarationAs(a, b) {
		t.Error("two descriptors for the same message type were treated as different declarations")
	}
	c := ToolDef{Input: (&timestamppb.Timestamp{}).ProtoReflect().Descriptor()}
	if sameDeclarationAs(a, c) {
		t.Error("different message types were treated as the same declaration")
	}
}
