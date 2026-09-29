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
	"time"

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

	// Audience is what this tool is FOR: PERSON, AGENT, RUNNER (design
	// §2.5). Empty means the contract said nothing, which READS as AGENT —
	// person-facing is always an explicit choice, so a catalogue built
	// before audiences existed lists to a model unchanged and lists nothing
	// to Studio.
	//
	// A []string of NAMES rather than a generated enum, because the enum
	// does not exist in the garm this binary links: it is read out of the
	// CATALOGUE's own descriptors (internal/catalogue/audience.go), by field
	// name, so Track G's number choice cannot break the read. Names survive
	// that; a Go enum would not.
	//
	// It is not a fourth gate. Nothing in the chain reads it — visibility is
	// still verb, clearance, compartments and set — and the only thing that
	// does is the LISTING, which is what decides what a caller is offered.
	Audience []string

	Input  protoreflect.MessageDescriptor
	Output protoreflect.MessageDescriptor

	// Governance the tool DECLARES. Carried so that mounting can REFUSE: a
	// declaration the runtime silently ignores is worse than no declaration,
	// because it reads as protection in review.
	ApprovalMode toolv1.Approval_Mode

	// The rest of the approval block. Only Mode used to reach here, which
	// left MODE_GRANT meaning no more than "some grant existed" — a verifier
	// could not check that the approver was senior enough, held the right
	// compartments, or approved recently. Those three ARE the approval
	// policy; without them the declaration names a gate and describes none of
	// it.
	//
	// Same omission the audit block had, found the same way: by needing one.
	ApproverMinClearance toolv1.Clearance
	ApproverCompartments []string
	MaxGrantAge          time.Duration

	// MaterialFields are the dotted paths whose values a grant binds to —
	// what the human actually saw. Empty means the grant binds only tool,
	// subject and time, which for anything irreversible is close to no
	// binding at all.
	MaterialFields []string
	AuditLevel     toolv1.Audit_Level

	// The rest of the audit block, carried because a declaration the runtime
	// silently drops is worse than no declaration.
	//
	// Only Level used to reach here, so `audit: { level: LEVEL_LEDGER,
	// fail_closed: true, retain_days: 2555 }` mounted cleanly and honoured
	// none of it — a tool could ask for a blocking, seven-year audit trail
	// and be served against a recorder that writes to stdout, simply by not
	// saying LEVEL_AUDIT. These are here so the mount refusal can see them.
	AuditRecordRequest  bool
	AuditRecordResponse bool
	AuditRetainDays     uint32
	AuditFailClosed     bool

	HasAuthorization bool

	Idempotent    bool
	Reversibility toolv1.Reversibility
	External      bool

	// Prose for the model rather than for a human reading the proto.
	// WhenNotToUse is consistently worth more than a longer description:
	// wrong-tool selection beats wrong-argument construction as a source of
	// agent error.
	//
	// All three are carried because all three are published: a projection that
	// dropped one would make an author's declaration disappear between the
	// .proto and the model, with nothing failing.
	WhenToUse    string
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
//
// Anything that is not "/service/method" yields nothing rather than a guess.
// Half of a malformed route would still end up in a subject, and a call that
// goes somewhere nobody meant is worse than one that visibly has nowhere to
// go. A Def is a value type other packages construct directly, so this has to
// hold for the zero value too, which the earlier form panicked on.
func (d Def) Service() string {
	rest, ok := strings.CutPrefix(d.FullMethod, "/")
	if !ok {
		return ""
	}
	i := strings.Index(rest, "/")
	if i < 0 {
		return ""
	}
	return rest[:i]
}

// The audiences a tool may declare (cards-and-tasks design §2.5), as the
// names a caller asks with and a listing answers with.
//
// They are strings rather than a generated enum for the same reason
// Def.Audience is: the enum is Track G's to add to garm.tool.v1, and this
// daemon reads whatever the CATALOGUE's descriptors declare rather than
// whatever this binary happens to link. A name is what survives that.
const (
	AudiencePerson = "PERSON"
	AudienceAgent  = "AGENT"
	AudienceRunner = "RUNNER"

	// AudienceUnspecified is the declared zero, and it READS as AGENT:
	// person-facing is always an explicit choice in the contract.
	AudienceUnspecified = "UNSPECIFIED"
)

// NormaliseAudience turns what a caller or a contract wrote into one of the
// names above, and reports whether it is one at all.
//
// It accepts the buf-prefixed spelling (AUDIENCE_PERSON) and the bare one
// (PERSON) because garm.card.v1 already spells its enums bare and Track G has
// not said which garm.tool.v1.Audience will be. Case-insensitive because a
// caller types this into a JSON body.
func NormaliseAudience(s string) (string, bool) {
	name := strings.ToUpper(strings.TrimSpace(s))
	if rest, cut := strings.CutPrefix(name, "AUDIENCE_"); cut && rest != "" {
		name = rest
	}
	switch name {
	case AudiencePerson, AudienceAgent, AudienceRunner:
		return name, true
	case "", AudienceUnspecified:
		return AudienceUnspecified, true
	default:
		return "", false
	}
}

// AudienceAdmits reports whether a tool declaring `declared` may be OFFERED
// to a caller asking for `want`.
//
// An empty or absent declaration reads as AGENT — "person-facing is always an
// explicit choice" — so a catalogue built before audiences existed lists to a
// model exactly as it did, and lists nothing at all to Studio until its tools
// say they are for people.
//
// This is half of the rule. The other half is the caller's own claims, and it
// is unchanged: Core.Catalog intersects this with the SAME visibility
// predicate step 2 denies with. An audience is what a tool is FOR; a set is
// who HOLDS it; clearance is what a caller may reach. Three questions, and
// this one answers only the first.
func AudienceAdmits(declared []string, want string) bool {
	if want == "" || want == AudienceUnspecified {
		want = AudienceAgent
	}
	if len(declared) == 0 {
		return want == AudienceAgent
	}
	for _, d := range declared {
		if d == want {
			return true
		}
		if d == AudienceUnspecified && want == AudienceAgent {
			return true
		}
	}
	return false
}
