package toolplane

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/garm-ai/garmd/internal/tool"
)

// ToolDef is the declaration the chain reads, and it is an alias rather than
// a type of its own.
//
// Being an alias, it carries no methods of its own — so what were methods on
// the monorepo's struct are functions here. That is the honest shape anyway:
// both ask enforcement questions ("can this build honour what this declares",
// "do these two declarations agree") rather than describing the declaration,
// and a declaration that could answer them would be deciding something.
//
// The chain talks about ToolDefs throughout, and so do a hundred and forty
// nine commits of design record. An alias keeps that vocabulary while there
// is exactly ONE definition — a second struct with the same fields is how two
// halves of a system start disagreeing about what a tool is.
type ToolDef = tool.Def

// AvailabilitySource reports whether a tool's service can serve a call now.
//
// A seam, not an implementation. It is deliberately separate from
// visibility: a tool the caller may not see and a tool nothing is serving are
// different answers to different questions, and folding them together would
// let an outage leak the existence of tools a caller is not cleared for.
//
// The reconciler satisfies this — it already knows what is reachable and why.
type AvailabilitySource interface {
	// Availability reports whether fqn can serve a call right now and, when
	// it cannot, a reason naming what an operator would need to act on.
	Availability(fqn string) (available bool, reason string)
}

// unimplementedGovernance reports the declared governance this Server cannot
// honour, if any.
//
// Plan A implements the field-classification half of the design: clearance,
// compartments, redaction, the input write check. It implements NONE of the
// supervision half — there is no grant verification (spec §8), no audit
// stream separate from the ledger (§10), and no instance authorization
// (§7). A tool that declares any of them and is served anyway is executing
// ungated while its schema says otherwise.
//
// Refusing at mount is deliberately louder than a warning. The schema
// author has already been forced into these declarations by L14 and L21;
// the only remaining failure modes are "the server refuses to start" and
// "the tool runs with none of the supervision it claims". The first is a
// bad afternoon, the second is the incident.
//
// This is deliberately an allowlist of the values this Core can honour, not
// a denylist of the ones it cannot. A denylist only refuses the values it was
// written against; the enums it checks are closed today, but the moment
// either gains a new member (MODE_MFA, LEVEL_FORENSIC, ...) a denylist mounts
// it silently ungated — the exact failure this exists to prevent,
// reintroduced. An allowlist refuses anything it does not recognise by
// construction, including values that do not exist yet, so do not "simplify"
// this back to enumerating what is unsupported.
//
// It asks what THIS Core was given, not what this build contains. Grants, FGA
// and notify are CoreConfig fields precisely so a deployment can supply them,
// and a check phrased as "the build does not implement grants" would refuse a
// MODE_GRANT tool even on a Core that had just been handed a GrantVerifier —
// making those fields unreachable, and this refusal permanent rather than
// conditional.
func (c *Core) unimplementedGovernance(t ToolDef) error {
	var missing []string

	switch t.ApprovalMode {
	case toolv1.Approval_MODE_UNSPECIFIED, toolv1.Approval_MODE_NONE:
		// Nothing declared. Nothing to honour.
	case toolv1.Approval_MODE_NOTIFY:
		// Step 10 DEGRADES — a notifier that fails cannot fail the call — but
		// degrading is not the same as absent. With no notifier at all the
		// notification never happens for any call, which makes the
		// declaration false rather than best-effort.
		if c.notifier == nil {
			missing = append(missing, "approval.mode MODE_NOTIFY, and this deployment "+
				"has no Notifier (step 10)")
		}
	case toolv1.Approval_MODE_GRANT:
		if c.grants == nil {
			missing = append(missing, "approval.mode MODE_GRANT, and this deployment "+
				"has no GrantVerifier (step 5)")
		}
	default:
		missing = append(missing, fmt.Sprintf(
			"approval.mode %d, which is not a mode this build knows how to enforce "+
				"(step 5)", t.ApprovalMode))
	}

	switch t.AuditLevel {
	case toolv1.Audit_LEVEL_UNSPECIFIED, toolv1.Audit_LEVEL_LEDGER:
		// NewCore refuses to build without a Recorder, so the ledger is
		// always there.
	case toolv1.Audit_LEVEL_AUDIT:
		// Deliberately unconditional, unlike the three above. LEVEL_AUDIT
		// asks for a durable, separately retained audit stream, and there is
		// no CoreConfig field to supply one because nothing in this
		// repository implements it yet. When the sink lands this becomes a
		// nil check like the others; until then a tool asking for seven years
		// of retention must not mount against a Recorder that writes to
		// stdout.
		missing = append(missing, "audit.level LEVEL_AUDIT, and no audit stream exists "+
			"yet — the ledger is not one (step 9 vs step 10)")
	default:
		missing = append(missing, fmt.Sprintf(
			"audit.level %d, which is not a level this build knows how to emit", t.AuditLevel))
	}

	if t.HasAuthorization && c.fga == nil {
		missing = append(missing, "an authorization block, and this deployment has no "+
			"FGAChecker (steps 4 and 7)")
	}

	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("tool %q declares %s. Serving it would run the tool ungated while "+
		"its schema says it is supervised, so this catalogue will not mount: either "+
		"configure the missing step, or remove the declaration from the tool that is "+
		"not getting it. See KNOWN-GAPS.md",
		t.Name, strings.Join(missing, ", "))
}

// sameDeclarationAs reports whether o declares exactly what t declares.
//
// Every field of the declaration is compared, not the one or two a duplicate
// is most likely to differ in: the point is to let an identical
// re-declaration through (see Core.AddTools) without letting anything else
// through with it, and a partial comparison would silently accept a
// declaration that disagrees in a field the comparison forgot. A field added
// to ToolDef must be added here; the compiler will not say so, which is why
// this sits next to the struct.
//
// need is deliberately not compared: it is not declared, it is DERIVED from
// Compartments by the registry, and Compartments is compared directly. It is
// also not yet resolved at the point AddTools calls this.
//
// Input and Output are compared by full name rather than by descriptor
// identity. The declaration names a message type; two descriptor values for
// the same message type (a dynamic one built from a descriptor set and the
// generated one, say) declare the same tool, and refusing that pair would be
// this check inventing a conflict that does not exist.
func sameDeclarationAs(t, o ToolDef) bool {
	md := func(d protoreflect.MessageDescriptor) protoreflect.FullName {
		if d == nil {
			return ""
		}
		return d.FullName()
	}
	return t.FullMethod == o.FullMethod &&
		t.Name == o.Name &&
		t.FQN == o.FQN &&
		t.Title == o.Title &&
		t.Description == o.Description &&
		t.Verb == o.Verb &&
		t.MinClearance == o.MinClearance &&
		slices.Equal(t.Compartments, o.Compartments) &&
		slices.Equal(t.Sets, o.Sets) &&
		md(t.Input) == md(o.Input) &&
		md(t.Output) == md(o.Output) &&
		t.ApprovalMode == o.ApprovalMode &&
		t.AuditLevel == o.AuditLevel &&
		t.HasAuthorization == o.HasAuthorization &&
		t.Idempotent == o.Idempotent &&
		t.Reversibility == o.Reversibility &&
		t.External == o.External &&
		t.WhenNotToUse == o.WhenNotToUse &&
		t.OnError == o.OnError &&
		maps.Equal(t.FieldDocs, o.FieldDocs)
}

// Service returns the proto service name, for the generated per-service filter.
