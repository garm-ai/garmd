package toolplane

import (
	"reflect"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
)

// The reference reader is the whole of the disclosure decision for a CEL
// rule, so each shape it has to refuse is pinned separately from the ones it
// reads.
func TestCELFieldRefsReadsEverySelectionOffThisAndRefusesWhatItCannotAccountFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
		refs [][]string
		ok   bool
	}{
		{"a cross-field rule",
			"this.currency_code != 'JPY' || this.amount_minor_units % 100 == 0",
			[][]string{{"currency_code"}, {"amount_minor_units"}}, true},
		{"a nested selection names the whole path and its prefix",
			"this.destination.iban != ''",
			[][]string{{"destination", "iban"}, {"destination"}}, true},
		{"a has() macro is a selection",
			"has(this.reference)", [][]string{{"reference"}}, true},
		{"a function over a field still names the field",
			"size(this.name) > 3", [][]string{{"name"}}, true},
		{"the rule's own values are not fields",
			"this.amount <= rules.lte && this.amount > rule", [][]string{{"amount"}, {"amount"}}, true},
		{"a field-level rule over a scalar names nothing",
			"this == this.upperAscii()", nil, true},
		{"a comprehension is refused: its variable aliases an element",
			"this.items.all(i, i.amount > 0)", nil, false},
		{"an identifier this does not bind is refused",
			"this.kind == PaymentKind.WIRE", nil, false},
		{"a selection off an index is refused",
			"this.items[0].iban != ''", nil, false},
		{"an expression that does not parse is refused",
			"this.a ==", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs, ok := celFieldRefs(tc.expr)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (refs %v)", ok, tc.ok, refs)
			}
			if !tc.ok {
				return
			}
			if !reflect.DeepEqual(refs, tc.refs) {
				t.Errorf("refs = %v, want %v", refs, tc.refs)
			}
		})
	}
}

func TestAdmittedPathWalksTheProjectionAndLooksThroughCollections(t *testing.T) {
	s := Schema{
		"type": "object",
		"properties": map[string]any{
			"currency": map[string]any{"type": "string"},
			"lines": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":       "object",
					"properties": map[string]any{"amount": map[string]any{"type": "integer"}},
				},
			},
			"tags": map[string]any{
				"type": "object",
				"additionalProperties": map[string]any{
					"type":       "object",
					"properties": map[string]any{"v": map[string]any{"type": "string"}},
				},
			},
			"self": map[string]any{"type": "object"}, // a cycle: rendered without properties
		},
	}
	for _, tc := range []struct {
		path []string
		want bool
	}{
		{nil, true},
		{[]string{"currency"}, true},
		{[]string{"amount"}, false},
		{[]string{"lines"}, true},
		{[]string{"lines", "amount"}, true},
		{[]string{"lines", "iban"}, false},
		{[]string{"tags", "v"}, true},
		{[]string{"self", "anything"}, false},
	} {
		if got := admittedPath(s, tc.path); got != tc.want {
			t.Errorf("admittedPath(%v) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// A string map key is request content, and request content does not go on
// the wire. Indices and scalar keys are positions, not values.
func TestPathStringElidesStringKeys(t *testing.T) {
	path := []*validate.FieldPathElement{
		validate.FieldPathElement_builder{FieldName: ptr("lines"), Index: ptr(uint64(2))}.Build(),
		validate.FieldPathElement_builder{FieldName: ptr("tags"), StringKey: ptr("ada@corp.com")}.Build(),
		validate.FieldPathElement_builder{FieldName: ptr("by_id"), IntKey: ptr(int64(7))}.Build(),
	}
	if got, want := pathString(path), "lines[2].tags[*].by_id[7]"; got != want {
		t.Errorf("pathString = %q, want %q", got, want)
	}
}

func ptr[T any](v T) *T { return &v }
