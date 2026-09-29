package toolplane

import (
	"strconv"
	"strings"
	"sync"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"buf.build/go/protovalidate"
	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Violation is one constraint a request broke, in the form the caller may
// see: the field, the rule, and the rule's own sentence.
//
// It is what a caller needs to repair a request and nothing else. The value
// it sent is not here — it already has that — and a field it may not send is
// never named, because a violation that names a field is a schema disclosure
// and the schema this caller was shown is the projected one.
type Violation struct {
	// Field is the dotted proto-name path the violation is on, spelled the
	// way the caller's input schema spells it. Empty for a message-level
	// rule on the request itself.
	Field string `json:"field"`

	// Rule is protovalidate's rule id — "string.pattern", "required" — or,
	// for a CEL rule, the id its author gave it.
	Rule string `json:"rule"`

	// Message is the constraint's own sentence, and it is absent when the
	// sentence could carry a value: a CEL rule whose message is computed
	// rather than declared, or a standard message that happens to contain
	// the value it was checking.
	Message string `json:"message,omitempty"`
}

// ValidationRefusal is step 3's refusal carrying the violations this caller
// may see. It IS errInvalidArgument — codeFor, ScrubError and every surface
// that asks errors.Is see the same sentinel they saw before — with one
// addition a surface may read.
//
// Violations is never nil on a refusal the chain built, so a surface that
// marshals it sends `[]` rather than `null` for a request whose only broken
// rules name fields this caller may not see.
type ValidationRefusal struct {
	Violations []Violation
}

func (e *ValidationRefusal) Error() string { return errInvalidArgument.Error() }
func (e *ValidationRefusal) Unwrap() error { return errInvalidArgument }

// Protovalidate spells a field rule's position in buf.validate.FieldRules,
// and a CEL rule there is `cel[i]` — field 23. A MESSAGE-level CEL rule has
// no rule path at all: it is identified by the id its author gave it, and by
// nothing else.
const fieldRulesCel = 23

// admittedViolations keeps the violations whose every named field the
// caller's own request projection admits.
//
// The projection is the one ListTools showed this caller — SchemaFor at the
// caller's shape, from the same cache — so "may this caller see this field"
// has exactly one answer here and in the listing. A field-level rule names
// its field path; a CEL rule names, in addition, every field its expression
// selects off `this`, and it is admitted only when all of them are. A rule
// that cannot be read back from the descriptor, or whose expression cannot be
// resolved to a set of paths, is left out: the ledger row has it, and an
// unlisted violation costs a retry where a listed one could cost a
// disclosure.
//
// A tool with no projection — a non-tool sibling, a ToolDef with no
// descriptors — lists nothing.
func (c *Core) admittedViolations(t ToolDef, p *Principal, verr *protovalidate.ValidationError) []Violation {
	out := []Violation{}
	in, _, err := c.SchemaFor(t, p)
	if err != nil {
		return out
	}
	for _, v := range verr.Violations {
		if v == nil || v.Proto == nil {
			continue
		}
		field := v.Proto.GetField().GetElements()
		if !admittedPath(in, namesOf(field)) {
			continue
		}
		msg := v.Proto.GetMessage()
		if rule, isCEL := celRuleFor(t.Input, v); isCEL {
			if rule == nil {
				continue
			}
			refs, ok := celFieldRefs(rule.GetExpression())
			if !ok || !allAdmitted(in, namesOf(field), refs) {
				continue
			}
			// The DECLARED message, and only when it is what protovalidate
			// reported. An expression that returns a string computes its
			// message from the value it was checking, and a rule with no
			// message is reported as its expression, which is the rule
			// author's text but not something this caller was shown.
			msg = ""
			if declared := rule.GetMessage(); declared != "" && declared == v.Proto.GetMessage() {
				msg = declared
			}
		} else if echoesValue(v, msg) {
			msg = ""
		}
		out = append(out, Violation{
			Field:   pathString(field),
			Rule:    v.Proto.GetRuleId(),
			Message: msg,
		})
	}
	return out
}

// celRuleFor reports whether v came from a CEL rule and, if so, the rule as
// declared on the descriptor — nil when the declaration cannot be found,
// which the caller treats as "do not list".
//
// A message-level rule is reported with no rule path, so it is found by id
// among the message's own rules; an id declared twice is ambiguous and is
// not found. A field-level rule is `cel[i]` under the field's rules, and its
// id must agree with the one at that index.
func celRuleFor(root protoreflect.MessageDescriptor, v *protovalidate.Violation) (*validate.Rule, bool) {
	field := v.Proto.GetField().GetElements()
	elems := v.Proto.GetRule().GetElements()

	if len(elems) == 0 {
		md := descriptorAt(root, field)
		if md == nil {
			return nil, true
		}
		mr, err := protovalidate.ResolveMessageRules(md)
		if err != nil {
			return nil, true
		}
		var found *validate.Rule
		for _, r := range mr.GetCel() {
			if r.GetId() != v.Proto.GetRuleId() {
				continue
			}
			if found != nil {
				return nil, true
			}
			found = r
		}
		return found, true
	}

	last := elems[len(elems)-1]
	if last.GetFieldName() != "cel" || last.GetFieldNumber() != fieldRulesCel ||
		last.WhichSubscript() != validate.FieldPathElement_Index_case {
		return nil, false
	}
	fd := fieldAt(root, field)
	if fd == nil {
		return nil, true
	}
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil {
		return nil, true
	}
	rules := fr.GetCel()
	idx := int(last.GetIndex())
	if idx < 0 || idx >= len(rules) || rules[idx].GetId() != v.Proto.GetRuleId() {
		return nil, true
	}
	return rules[idx], true
}

// descriptorAt walks root along a violation's field path and returns the
// message at its end: root itself for an empty path, the nested message for
// a path ending on a message-typed field, nil for anything else.
func descriptorAt(root protoreflect.MessageDescriptor, path []*validate.FieldPathElement) protoreflect.MessageDescriptor {
	if root == nil {
		return nil
	}
	md := root
	for _, el := range path {
		fd := md.Fields().ByName(protoreflect.Name(el.GetFieldName()))
		if fd == nil {
			return nil
		}
		if fd.IsMap() {
			fd = fd.MapValue()
		}
		if fd.Message() == nil {
			return nil
		}
		md = fd.Message()
	}
	return md
}

// fieldAt is the field a violation's path ends on, or nil.
func fieldAt(root protoreflect.MessageDescriptor, path []*validate.FieldPathElement) protoreflect.FieldDescriptor {
	if len(path) == 0 {
		return nil
	}
	md := descriptorAt(root, path[:len(path)-1])
	if md == nil {
		return nil
	}
	return md.Fields().ByName(protoreflect.Name(path[len(path)-1].GetFieldName()))
}

// admittedPath reports whether every name along path is in the projected
// schema. A list or map along the way is looked through — the element schema
// is the field's, whichever element a violation happened to be on — and a
// message the projection rendered without properties (a cycle) admits
// nothing beneath it.
func admittedPath(s Schema, path []string) bool {
	cur := asMap(s)
	for _, name := range path {
		next := asMap(asMap(cur["properties"])[name])
		if next == nil {
			return false
		}
		cur = lookThrough(next)
	}
	return true
}

// lookThrough descends from a collection's schema to its element's.
func lookThrough(s map[string]any) map[string]any {
	for {
		switch {
		case s["items"] != nil:
			s = asMap(s["items"])
		case s["additionalProperties"] != nil:
			s = asMap(s["additionalProperties"])
		default:
			return s
		}
		if s == nil {
			return map[string]any{}
		}
	}
}

// asMap reads a schema node whichever of the two spellings the projection
// stored it under: the root is a Schema, everything beneath a plain map.
func asMap(v any) map[string]any {
	switch m := v.(type) {
	case Schema:
		return m
	case map[string]any:
		return m
	}
	return nil
}

func allAdmitted(s Schema, prefix []string, refs [][]string) bool {
	for _, ref := range refs {
		full := append(append([]string(nil), prefix...), ref...)
		if !admittedPath(s, full) {
			return false
		}
	}
	return true
}

func namesOf(path []*validate.FieldPathElement) []string {
	out := make([]string, 0, len(path))
	for _, el := range path {
		out = append(out, el.GetFieldName())
	}
	return out
}

// pathString spells a field path for the caller: names joined by dots, list
// indices and scalar map keys as subscripts, a string map key as `[*]` — the
// key is request content, and request content does not go on the wire.
func pathString(path []*validate.FieldPathElement) string {
	var b strings.Builder
	for i, el := range path {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(el.GetFieldName())
		switch el.WhichSubscript() {
		case validate.FieldPathElement_Index_case:
			b.WriteString("[" + strconv.FormatUint(el.GetIndex(), 10) + "]")
		case validate.FieldPathElement_BoolKey_case:
			b.WriteString("[" + strconv.FormatBool(el.GetBoolKey()) + "]")
		case validate.FieldPathElement_IntKey_case:
			b.WriteString("[" + strconv.FormatInt(el.GetIntKey(), 10) + "]")
		case validate.FieldPathElement_UintKey_case:
			b.WriteString("[" + strconv.FormatUint(el.GetUintKey(), 10) + "]")
		case validate.FieldPathElement_StringKey_case:
			b.WriteString("[*]")
		}
	}
	return b.String()
}

// echoesValue reports whether a standard rule's message contains the text of
// the value it refused.
//
// Protovalidate's standard messages describe the constraint — "value does
// not match regex pattern `…`", "value length must be at most 16" — and
// interpolate the rule's value, never the field's. This is the guard for the
// day one does: a string or bytes value found inside the sentence drops the
// sentence, and the rule id carries the refusal alone. Numbers and enums are
// not checked, because "must be greater than 0" contains the refused 0 by
// coincidence of the constraint, not by disclosure.
func echoesValue(v *protovalidate.Violation, msg string) bool {
	if msg == "" || !v.FieldValue.IsValid() {
		return false
	}
	switch val := v.FieldValue.Interface().(type) {
	case string:
		return val != "" && strings.Contains(msg, val)
	case []byte:
		return len(val) > 0 && strings.Contains(msg, string(val))
	}
	return false
}

// celEnv parses rule expressions. Parsing only — no type check, no program —
// so the environment declares nothing beyond the names protovalidate binds.
var celEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("this", cel.DynType),
		cel.Variable("rules", cel.DynType),
		cel.Variable("rule", cel.DynType),
		cel.Variable("now", cel.TimestampType),
	)
})

// celFieldRefs is every field path an expression selects off `this`.
//
// It is conservative on purpose, and reports !ok for any expression it cannot
// account for completely: a comprehension (its iteration variable aliases an
// element of some field, and which field is not a question worth answering
// here), an identifier that is not one protovalidate binds, or a selection
// whose operand is not itself a chain of selections back to an identifier —
// `this.items[0].iban` selects off an index expression, and the field under
// the element is exactly what the caller might not be shown. A rule this
// cannot read is a rule the caller is not told about.
func celFieldRefs(expression string) (refs [][]string, ok bool) {
	env, err := celEnv()
	if err != nil {
		return nil, false
	}
	parsed, iss := env.Parse(expression)
	if iss != nil && iss.Err() != nil {
		return nil, false
	}
	ok = true
	celast.PreOrderVisit(parsed.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.ComprehensionKind:
			ok = false
		case celast.IdentKind:
			switch e.AsIdent() {
			case "this", "rules", "rule", "now":
			default:
				ok = false
			}
		case celast.SelectKind:
			chain, root := selectChain(e)
			switch root {
			case "this":
				refs = append(refs, chain)
			case "rules", "rule", "now":
			default:
				ok = false
			}
		}
	}))
	return refs, ok
}

// selectChain unwinds a.b.c to (["a","b","c"], root) when every operand is a
// selection and the innermost is an identifier, and ("", nil) otherwise.
func selectChain(e celast.Expr) ([]string, string) {
	var names []string
	for e.Kind() == celast.SelectKind {
		sel := e.AsSelect()
		names = append([]string{sel.FieldName()}, names...)
		e = sel.Operand()
	}
	if e.Kind() != celast.IdentKind {
		return nil, ""
	}
	return names, e.AsIdent()
}
