package catalogue

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"

	"github.com/garm-ai/garmd/internal/tool"
)

// Reading a tool's audience out of a catalogue this binary is older than.
//
// A tool declares what it is FOR — PERSON, AGENT, RUNNER (cards-and-tasks
// design §2.5) — on `garm.tool.v1.ToolPolicy`. The garm this binary links
// does not have that field yet; Track G adds it. Widening the go.mod and
// waiting would be the obvious move and it is the wrong one, for the reason
// this whole repository exists: **a catalogue is data.** Its descriptor set
// carries the `tool.proto` it was built with, so the catalogue knows the
// field even when the binary does not, and reading it from there is the same
// inversion that lets a tool be added without a release.
//
// So the number is found by NAME, in the catalogue's own descriptors, and the
// VALUE is then read off the annotation — from the linked type's field when a
// later garm gives it one, and from the unknown bytes the annotation carried
// through the load when it does not. Track G may pick any field number it
// likes; nothing here depends on the choice.
//
// The same read covers the two shapes the design leaves open: a plain field
// on ToolPolicy, and an extension of it. Both are a field number on the same
// message, and both land in the same bytes.

const (
	toolPolicyName  protoreflect.FullName = "garm.tool.v1.ToolPolicy"
	audienceField   protoreflect.Name     = "audience"
	unknownAudience                       = ""
)

// audienceReader is one catalogue generation's answer to "where is audience".
// Built once per load; the zero value reads nothing, which is the honest
// answer for a catalogue whose tool.proto has no such field.
type audienceReader struct {
	num   protoreflect.FieldNumber
	enum  protoreflect.EnumDescriptor
	found bool
}

func newAudienceReader(files *protoregistry.Files) audienceReader {
	d, err := files.FindDescriptorByName(toolPolicyName)
	if err != nil {
		return audienceReader{}
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	if !ok {
		return audienceReader{}
	}
	if fd := md.Fields().ByName(audienceField); fd != nil {
		return readerFor(fd)
	}
	// Not a field: an extension of ToolPolicy, which is how §2.5 writes it.
	var found audienceReader
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		rangeExtensions(fd, func(xd protoreflect.ExtensionDescriptor) bool {
			if xd.Name() != audienceField ||
				xd.ContainingMessage() == nil ||
				xd.ContainingMessage().FullName() != toolPolicyName {
				return true
			}
			found = readerFor(xd)
			return !found.found
		})
		return !found.found
	})
	return found
}

func readerFor(fd protoreflect.FieldDescriptor) audienceReader {
	if fd.Kind() != protoreflect.EnumKind || fd.IsMap() || fd.Enum() == nil {
		// A shape this build cannot read is read as ABSENT, which reads as
		// AGENT — exactly what every catalogue predating audiences gets. It
		// is not a hole: an audience narrows a LISTING, so failing to read
		// one costs Studio a tool it would have been offered and gives a
		// model nothing it did not already have.
		return audienceReader{}
	}
	return audienceReader{num: fd.Number(), enum: fd.Enum(), found: true}
}

// rangeExtensions visits a file's extensions, including the ones declared
// inside a message.
func rangeExtensions(fd protoreflect.FileDescriptor, fn func(protoreflect.ExtensionDescriptor) bool) {
	exts := fd.Extensions()
	for i := 0; i < exts.Len(); i++ {
		if !fn(exts.Get(i)) {
			return
		}
	}
	var walk func(protoreflect.MessageDescriptors) bool
	walk = func(mds protoreflect.MessageDescriptors) bool {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			es := md.Extensions()
			for j := 0; j < es.Len(); j++ {
				if !fn(es.Get(j)) {
					return false
				}
			}
			if !walk(md.Messages()) {
				return false
			}
		}
		return true
	}
	walk(fd.Messages())
}

// read returns the audiences a tool declares, normalised to the names in
// internal/tool, in declaration order and without duplicates.
func (r audienceReader) read(p *toolv1.ToolPolicy) []string {
	if !r.found || p == nil {
		return nil
	}
	var numbers []protoreflect.EnumNumber

	m := p.ProtoReflect()
	if fd := m.Descriptor().Fields().ByName(audienceField); fd != nil &&
		fd.Number() == r.num && fd.Kind() == protoreflect.EnumKind {
		// A later garm gave the LINKED type the field. Read it properly.
		switch {
		case fd.IsList():
			list := m.Get(fd).List()
			for i := 0; i < list.Len(); i++ {
				numbers = append(numbers, list.Get(i).Enum())
			}
		case m.Has(fd):
			numbers = append(numbers, m.Get(fd).Enum())
		}
	} else {
		numbers = enumsFromUnknown(m.GetUnknown(), r.num)
	}

	var out []string
	for _, n := range numbers {
		v := r.enum.Values().ByNumber(n)
		if v == nil {
			continue
		}
		name, ok := tool.NormaliseAudience(string(v.Name()))
		if !ok || name == tool.AudienceUnspecified {
			// UNSPECIFIED is the declared zero and it reads as AGENT. It is
			// dropped rather than recorded, so that "declared nothing" and
			// "declared the zero" are one state downstream instead of two
			// that behave alike and read differently.
			continue
		}
		if !containsString(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// enumsFromUnknown reads a repeated (or singular) enum field out of the bytes
// an annotation carried through a load unread.
//
// This is where the inversion pays: the linked ToolPolicy has no `audience`,
// so protobuf-go preserved it verbatim in the message's unknown fields, and
// the catalogue's own descriptor said which number to look for. Packed and
// unpacked are both handled because proto3 packs a repeated enum by default
// and a hand-rolled encoder may not.
//
// Anything malformed yields NOTHING rather than a partial list: a half-read
// audience would be a tool offered to an audience nobody declared.
func enumsFromUnknown(raw protoreflect.RawFields, want protoreflect.FieldNumber) []protoreflect.EnumNumber {
	var out []protoreflect.EnumNumber
	b := []byte(raw)
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil
		}
		b = b[n:]
		if num != want {
			if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
				return nil
			}
			b = b[n:]
			continue
		}
		switch typ {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return nil
			}
			out = append(out, protoreflect.EnumNumber(v))
			b = b[m:]
		case protowire.BytesType:
			packed, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil
			}
			b = b[m:]
			for len(packed) > 0 {
				v, k := protowire.ConsumeVarint(packed)
				if k < 0 {
					return nil
				}
				out = append(out, protoreflect.EnumNumber(v))
				packed = packed[k:]
			}
		default:
			// A wire type an enum cannot have. The field is not what this
			// build thinks it is, so nothing is read from it.
			return nil
		}
	}
	return out
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
