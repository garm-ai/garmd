// Package tool is the in-memory form of a tool declaration.
//
// A Def is what a .proto said about a tool, projected out of a catalogue at
// load. It is inert: nothing here decides whether a call may proceed. The
// chain reads these; the loader produces them.
//
// It lives in the daemon rather than in the contract language because the
// daemon is its only consumer. The generator emits no Defs — a catalogue does
// — and a tool service registers against a Registrar, not a Def.
package tool

import (
	"strings"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Def is one tool, as its declaration describes it.
//
// Derived state does NOT live here. The compartment set a tool resolves to is
// computed by whoever mounts it and kept beside the declaration, because it
// is not declared — it is derived, and a struct that mixes the two invites
// code to trust a field the author never wrote.
type Def struct {
	// FullMethod is the route: "/pkg.Service/Method".
	FullMethod string

	// FQN is the globally unique identity: proto package + tool name. Parse
	// by splitting at the LAST dot — tool names cannot contain one, so the
	// final segment is the name and everything before it is the package.
	FQN string

	// Name is the author's declared short name, and the last segment of the
	// FQN.
	Name string

	// ClientName is what a caller sees and dispatches on — the short name
	// when it is unique in this catalogue, a package-prefixed form when it is
	// not. Assigned at load, never authored.
	//
	// It is a label, not an identity. Manifests pin by FQN and the ledger
	// records the FQN, so this may differ between two catalogues containing
	// the same tool without anything downstream noticing.
	ClientName string

	Title       string
	Description string

	Verb         toolv1.Verb
	MinClearance toolv1.Clearance
	Compartments []string
	Sets         []string

	Input  protoreflect.MessageDescriptor
	Output protoreflect.MessageDescriptor

	// Governance the tool DECLARES. Carried so that mounting can REFUSE: a
	// declaration the runtime silently ignores is worse than no declaration,
	// because it reads as protection in review.
	ApprovalMode     toolv1.Approval_Mode
	AuditLevel       toolv1.Audit_Level
	HasAuthorization bool

	Idempotent    bool
	Reversibility toolv1.Reversibility
	External      bool

	// Prose for the model rather than for a human reading the proto.
	// WhenNotToUse is consistently worth more than a longer description:
	// wrong-tool selection beats wrong-argument construction as a source of
	// agent error.
	WhenNotToUse string
	OnError      string

	// FieldDocs is the prose for this tool's fields, keyed by each field's
	// full proto name.
	//
	// It is here rather than read from the catalogue on demand because a
	// projected schema is assembled per principal and per shape, and going
	// back to the catalogue for every field would make the cache pointless.
	//
	// The map is SHARED with the catalogue that produced it and with every
	// other Def from that catalogue — read-only, never written after load.
	// Copying it per tool would multiply the one part of a catalogue that is
	// already the largest.
	FieldDocs map[string]string
}

// Service is the proto service this tool belongs to, which is also the queue
// group a NATS deployment balances over.
func (d Def) Service() string {
	i := strings.Index(d.FullMethod[1:], "/")
	if i < 0 {
		return ""
	}
	return d.FullMethod[1 : i+1]
}
