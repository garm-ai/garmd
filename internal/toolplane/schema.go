package toolplane

import (
	"sort"

	"google.golang.org/protobuf/reflect/protoreflect"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"

	"github.com/garm-ai/garm/policy"
)

// Schema is a JSON Schema document (draft 2020-12), as MCP's inputSchema and
// the tool catalogue both want it.
type Schema map[string]any

// ProjectInput builds the schema advertised to a principal of this shape.
//
// A field the principal may not WRITE is ABSENT, not present-and-rejected.
// That is the whole rule (spec §5.3), and it is about the reader: a model
// attempts every field it is shown, a field it cannot write produces a
// step-3 rejection naming a path it cannot interpret, and it retries
// identically. An unprojected schema teaches the model to fail.
//
// It takes a Plan and a Shape rather than a policy.Resolved, and that is
// a correctness requirement rather than a preference. Resolved.Deny is
// computed against Action.Read — a field that is readable but NOT writable
// does not appear in it. Projecting input from Deny would therefore advertise
// exactly the fields this function exists to hide.
func ProjectInput(plan *policy.Plan, s policy.Shape, docs map[string]string) Schema {
	return project(plan, s, docs, func(a policy.Action) toolv1.Clearance { return a.Write })
}

// ProjectOutput builds the schema of what a principal of this shape will
// actually receive — the same walk, decided on READ.
//
// It has to exist alongside the input projection rather than being derived
// from it: read and write clearances differ per field, so a field can be
// writable and unreadable or the reverse.
func ProjectOutput(plan *policy.Plan, s policy.Shape, docs map[string]string) Schema {
	return project(plan, s, docs, func(a policy.Action) toolv1.Clearance { return a.Read })
}

// project walks the message once, keeping fields this shape clears under the
// supplied dimension.
//
// The denial set is built from the plan's actions rather than from the
// descriptor, because the plan is what knows the inherited policy — a field
// with no annotation of its own still carries its message's default.
func project(
	plan *policy.Plan,
	s policy.Shape,
	docs map[string]string,
	need func(policy.Action) toolv1.Clearance,
) Schema {
	denied := map[string]bool{}
	var deniedSubtrees []string
	for _, a := range plan.Actions {
		if policy.Allows(s.Clearance, need(a)) && s.Compartments.Covers(a.Need) {
			continue
		}
		denied[a.Name] = true
		if a.IsSubtree {
			deniedSubtrees = append(deniedSubtrees, a.Name)
		}
	}
	return schemaFor(plan.Desc, "", denied, deniedSubtrees, docs, map[protoreflect.FullName]bool{})
}

// schemaFor renders one message.
//
// seen breaks recursion: a message may reference itself directly or through a
// cycle and protos permit it. Without the guard a self-referential schema
// would not terminate.
func schemaFor(
	md protoreflect.MessageDescriptor,
	path string,
	denied map[string]bool,
	deniedSubtrees []string,
	docs map[string]string,
	seen map[protoreflect.FullName]bool,
) Schema {
	out := Schema{"type": "object"}
	if seen[md.FullName()] {
		// A cycle. Describing it as an untyped object is honest: the shape
		// is the message we are already inside.
		return out
	}
	seen[md.FullName()] = true
	defer delete(seen, md.FullName())

	properties := map[string]any{}
	var required []string

	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		full := name
		if path != "" {
			full = path + "." + name
		}
		if denied[full] || underDeniedSubtree(full, deniedSubtrees) {
			continue
		}

		properties[name] = fieldSchema(fd, full, denied, deniedSubtrees, docs, seen)

		// proto3 explicit presence means the field is genuinely optional;
		// a bare scalar always has a value on the wire, so describing it as
		// required is what a client expects.
		if !fd.HasPresence() && !fd.IsList() && !fd.IsMap() {
			required = append(required, name)
		}
	}

	out["properties"] = properties
	if len(required) > 0 {
		// Sorted: map iteration order is random, and an unsorted slice would
		// make every projection differ from the last one.
		sort.Strings(required)
		out["required"] = required
	}
	return out
}

func underDeniedSubtree(name string, subtrees []string) bool {
	for _, s := range subtrees {
		if len(name) > len(s) && name[:len(s)] == s && name[len(s)] == '.' {
			return true
		}
	}
	return false
}

// fieldSchema renders one field, recursing into message types.
func fieldSchema(
	fd protoreflect.FieldDescriptor,
	full string,
	denied map[string]bool,
	deniedSubtrees []string,
	docs map[string]string,
	seen map[protoreflect.FullName]bool,
) map[string]any {
	var s map[string]any

	switch {
	case fd.IsMap():
		s = map[string]any{
			"type": "object",
			"additionalProperties": scalarOrMessage(
				fd.MapValue(), full, denied, deniedSubtrees, docs, seen),
		}
	case fd.IsList():
		s = map[string]any{
			"type":  "array",
			"items": scalarOrMessage(fd, full, denied, deniedSubtrees, docs, seen),
		}
	default:
		s = scalarOrMessage(fd, full, denied, deniedSubtrees, docs, seen)
	}

	if doc := docs[string(fd.FullName())]; doc != "" {
		s["description"] = doc
	}
	return s
}

func scalarOrMessage(
	fd protoreflect.FieldDescriptor,
	full string,
	denied map[string]bool,
	deniedSubtrees []string,
	docs map[string]string,
	seen map[protoreflect.FullName]bool,
) map[string]any {
	if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
		md := fd.Message()
		// google.protobuf.Timestamp is JSON-encoded as an RFC 3339 string by
		// protojson, so describing its internal seconds/nanos fields would
		// describe a shape no caller ever sees.
		if md.FullName() == "google.protobuf.Timestamp" {
			return map[string]any{"type": "string", "format": "date-time"}
		}
		return schemaFor(md, full, denied, deniedSubtrees, docs, seen)
	}
	return scalarSchema(fd)
}

// scalarSchema maps a proto kind to a JSON Schema type.
//
// The 64-bit integers are "string", not "integer", and that is not a quirk:
// protojson encodes them as strings precisely because a JSON number is a
// float64 and loses precision above 2^53. Describing them as integers would
// document a shape that disagrees with the bytes on the wire.
func scalarSchema(fd protoreflect.FieldDescriptor) map[string]any {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return map[string]any{"type": "boolean"}

	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return map[string]any{"type": "integer"}

	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return map[string]any{"type": "string", "format": "int64"}

	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return map[string]any{"type": "number"}

	case protoreflect.StringKind:
		return map[string]any{"type": "string"}

	case protoreflect.BytesKind:
		return map[string]any{"type": "string", "contentEncoding": "base64"}

	case protoreflect.EnumKind:
		// VALUE NAMES, not numbers: protojson emits the name, and a model
		// shown 0,1,2 would send integers the server does not accept.
		values := fd.Enum().Values()
		names := make([]string, 0, values.Len())
		for i := 0; i < values.Len(); i++ {
			names = append(names, string(values.Get(i).Name()))
		}
		return map[string]any{"type": "string", "enum": names}
	}
	return map[string]any{"type": "string"}
}
