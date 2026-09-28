// Package grants verifies that a human approved this call.
//
// Step 5. A tool declaring MODE_GRANT does not run until a grant token says
// somebody senior enough agreed, recently enough, to these values — and until
// that grant has not been spent before.
//
// Extraction lives here rather than in the shared contract because only this
// side has the descriptors. The caller sends the values it is about to use to
// the issuer, the issuer shows them to a human and digests what it was given,
// and this side re-extracts from the ACTUAL request and compares. A caller
// that showed the human one thing and sent another gets a mismatch, so the
// issuer never needs a catalogue and the lie is still caught.
package grants

import (
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/garm-ai/garm/contracts/grant"
)

// Materialise reads the values a grant binds to.
//
// The linter has already refused any path that does not resolve to a scalar
// leaf, so a failure here means the catalogue and the request disagree about
// the message's shape — which the descriptor hash should have caught first,
// and which must refuse rather than skip the field.
func Materialise(msg protoreflect.Message, paths []string) (map[string]string, error) {
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		v, err := valueAt(msg, strings.Split(p, "."))
		if err != nil {
			return nil, fmt.Errorf("material field %q: %w", p, err)
		}
		out[p] = v
	}
	return out, nil
}

// valueAt walks a dotted path to a scalar.
//
// An absent field anywhere on the path yields Unset for the whole path rather
// than an error: a request that omits `payment` has omitted `payment.amount`
// too, and both a human approving that and this side checking it should agree
// on what "absent" means.
func valueAt(msg protoreflect.Message, segs []string) (string, error) {
	if msg == nil || !msg.IsValid() {
		return grant.Unset, nil
	}
	fd := msg.Descriptor().Fields().ByName(protoreflect.Name(segs[0]))
	if fd == nil {
		return "", fmt.Errorf("%s has no field %q", msg.Descriptor().FullName(), segs[0])
	}
	if len(segs) > 1 {
		if fd.Kind() != protoreflect.MessageKind {
			return "", fmt.Errorf("%q is not a message", segs[0])
		}
		if !msg.Has(fd) {
			return grant.Unset, nil
		}
		return valueAt(msg.Get(fd).Message(), segs[1:])
	}
	// Presence, where the field has it. A proto3 scalar without `optional` is
	// always present and reads as its zero, which is why the linter treats
	// such a field as required rather than optional — there is no absence to
	// distinguish.
	if fd.HasPresence() && !msg.Has(fd) {
		return grant.Unset, nil
	}
	return scalarText(fd, msg.Get(fd))
}

// scalarText is the canonical text form used in the digest.
//
// Chosen so every language writes the same string without a specification to
// consult: decimal integers, 'true'/'false', the enum's NAME rather than its
// number, and the string itself. An enum by number would digest differently
// after somebody renumbered a proto, which is a change the wire format says
// is breaking anyway but the digest should not be the thing that discovers it.
func scalarText(fd protoreflect.FieldDescriptor, v protoreflect.Value) (string, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return v.String(), nil
	case protoreflect.BoolKind:
		return strconv.FormatBool(v.Bool()), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return strconv.FormatInt(v.Int(), 10), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return strconv.FormatUint(v.Uint(), 10), nil
	case protoreflect.EnumKind:
		ed := fd.Enum().Values().ByNumber(v.Enum())
		if ed == nil {
			// A number the catalogue's enum does not define. Refusing beats
			// digesting the integer: the approver was shown a name, and there
			// is no name for this.
			return "", fmt.Errorf("enum value %d is not declared", v.Enum())
		}
		return string(ed.Name()), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		// Refused rather than formatted. Every language rounds and prints
		// floats slightly differently, and a grant that matched on one
		// runtime and not another would be a fault nobody could reproduce.
		// The linter should never let one through; this is the backstop.
		return "", fmt.Errorf("a floating-point field cannot be material: its text " +
			"form differs between runtimes, so a grant would match in one and not " +
			"another")
	case protoreflect.BytesKind:
		return "", fmt.Errorf("a bytes field cannot be material: a human cannot read " +
			"it, so they cannot approve it")
	default:
		return "", fmt.Errorf("kind %s cannot be material", fd.Kind())
	}
}
