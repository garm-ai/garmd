package toolplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"buf.build/go/protovalidate"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/garm-ai/garm/contracts/audit"
	"github.com/garm-ai/garm/contracts/callctx"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garm/policy/redact"
)

// Core is the governance chain, with no transport in it.
//
// Connect, MCP and the catalogue are adapters: build a Principal, build a
// message, call Invoke. The chain that decides whether and in what form a
// call may proceed lives here, once, so that a second front door cannot
// arrive with a second interpretation of the policy (spec §1).
//
// Core owns the resolvers as well as the rules. That is what makes the
// guarantee structural rather than conventional: an adapter holds a *Core
// and can only call Invoke, because there is nothing else to hold.
type Core struct {
	hashKey  []byte
	reg      *policy.Registry
	cache    *policy.Cache
	recorder ledger.Recorder
	audit    audit.Sink

	// The pluggable steps. Nil means the step is NOT DECLARED and returns
	// nil; it never means "the check failed and we carried on". See fgaPre.
	fga      FGAChecker
	grants   GrantVerifier
	notifier Notifier

	mu sync.RWMutex
	// plans is keyed by descriptor identity, not full name: two distinct
	// descriptors (a dynamicpb message beside a generated type, or a second
	// copy of a schema loaded from a runtime FileDescriptorSet) can share a
	// full name, and policy.Sanitize compares descriptor identity, not
	// name. Keying this map on protoreflect.FullName (a string) would let
	// unrelated descriptors share a compiled plan; protoreflect.MessageDescriptor
	// is an interface backed by a pointer for every real implementation, so
	// it is safe and cheap to use as a map key directly.
	plans map[protoreflect.MessageDescriptor]*policy.Plan

	// need is the compartment set each tool resolves to, keyed by route.
	//
	// Derived at mount, never declared — the registry turns declared
	// compartment NAMES into a bitset, and which bit a name gets depends on
	// the whole catalogue. It lives here rather than on ToolDef because a
	// declaration should carry only what its author wrote: a field mixing
	// the two invites code to trust a value nobody declared.
	need      map[string]policy.CompartmentSet
	tools     map[string]ToolDef      // keyed by FullMethod
	resolvers map[string]registration // keyed by procedure; see resolver.go

	// validator evaluates (buf.validate.*) constraints. Always non-nil on a
	// Core built by NewCore; see validate.go.
	validator protovalidate.Validator

	// schemas memoizes projected schemas per (descriptor, shape, dimension).
	schemas *schemaCache

	// availability is step 6's own question — is this tool's SERVICE
	// reachable right now — and it is deliberately a SEPARATE field from
	// everything above: reg/cache/plans/tools all answer "may this
	// principal use this tool", and availability must never be folded into
	// that predicate (see checkAvailability's own doc comment). Nil means
	// no AvailabilitySource is wired (every Core before SetAvailability is
	// called, and every Core whose tools never leave process): the check is
	// skipped, not failed closed, because a Core with no NATS-backed tool
	// has nothing to ask.
	availability AvailabilitySource
}

// FGAChecker is instance authorization: may this principal touch THIS object
// (spec §3 steps 4 and 7). Nil on a Core means no instance authz is declared.
//
// Both halves fail CLOSED, including when the FGA service is unreachable: a
// post-filter that cannot run must not return the unfiltered list.
//
// Post may filter the message it is given — it must do so IN PLACE and
// return that same message. The connect adapter returns the response object
// the handler produced, so a Post that returns a DIFFERENT message would be
// sanitized and then dropped, and the unfiltered one would go out. This is
// not left to the reader: fgaPost REFUSES a replacement. When a replacing
// Post is needed, the adapters change first, and that guard second.
type FGAChecker interface {
	Pre(ctx context.Context, p *Principal, t ToolDef, req proto.Message) error
	Post(ctx context.Context, p *Principal, t ToolDef, resp proto.Message) (proto.Message, error)
}

// GrantVerifier is step 5: an approval-gated tool verifies a grant token
// before it runs.
//
// Nil on a Core means no verifier is configured, which is safe only because
// AddTools then REFUSES to mount a MODE_GRANT tool at all — see
// Core.unimplementedGovernance, which reads this field to decide. The two are
// a pair: relaxing that refusal without making this seam mandatory for those
// tools would serve an approval-gated tool with no approval.
type GrantVerifier interface {
	Verify(ctx context.Context, p *Principal, t ToolDef) error
}

// Notifier is step 10: HOTL fan-out, after the response has left. It
// DEGRADES — it runs from the same defer as the ledger, cannot fail the
// call, and cannot delay what the caller already received.
type Notifier interface {
	Notify(ctx context.Context, p *Principal, t ToolDef, ev ledger.Event)
}

// CoreConfig configures a Core.
//
// There is no PrincipalFunc here on purpose: step 1 (authn) belongs to the
// surface, because what a principal is derived FROM differs per front door —
// a JWT on connect, a session on MCP. Invoke receives the Principal already
// built.
type CoreConfig struct {
	HashKey      []byte
	Compartments []*toolv1.Decl
	Recorder     ledger.Recorder

	// Audit is the durable, separately-retained stream — the half of the
	// record that MAY refuse a call. Nil means no audit stream, which is safe
	// only because AddTools then refuses to mount any tool that declares one.
	Audit audit.Sink

	// FGA, Grants and Notifier are the steps whose IMPLEMENTATION may vary
	// (spec §2). What is not variable is whether they run: that is the fixed
	// order in Invoke, which is code, not data.
	FGA      FGAChecker
	Grants   GrantVerifier
	Notifier Notifier
}

func NewCore(cfg CoreConfig) (*Core, error) {
	if len(cfg.HashKey) == 0 {
		return nil, fmt.Errorf("toolplane: HashKey is required for hash redactions")
	}
	if cfg.Recorder == nil {
		return nil, fmt.Errorf("toolplane: Recorder is required to ledger tool calls")
	}
	reg, err := policy.NewRegistry(cfg.Compartments)
	if err != nil {
		return nil, err
	}
	// Fail closed at startup: a Core that could not build its validator must
	// not exist, because the alternative is a Core that silently stops
	// validating.
	validator, err := newValidator()
	if err != nil {
		return nil, err
	}
	return &Core{
		validator: validator,
		schemas:   newSchemaCache(),
		hashKey:   cfg.HashKey,
		reg:       reg,
		cache:     policy.NewCache(),
		recorder:  cfg.Recorder,
		audit:     cfg.Audit,
		fga:       cfg.FGA,
		grants:    cfg.Grants,
		notifier:  cfg.Notifier,
		plans:     map[protoreflect.MessageDescriptor]*policy.Plan{},
		need:      map[string]policy.CompartmentSet{},
		tools:     map[string]ToolDef{},
		resolvers: map[string]registration{},
	}, nil
}

// AddTools registers tool declarations and compiles a plan for every message
// they name.
//
// Plans are compiled here rather than lazily so that a message with a missing
// or undeclared policy fails at startup, when someone is watching, rather than
// on the first call that happens to touch it.
//
// Declarations go IN; nothing comes back out but an error. A tool declaring
// governance this build does not implement is refused here rather than served
// ungated — see ToolDef.unimplementedGovernance.
//
// # Duplicates
//
// A second declaration for a FullMethod that already has one is refused if it
// DIFFERS from the one in force, and accepted if it is identical.
//
// Refusing the differing one is the same rule Register holds for resolvers,
// and for the same reason: a silent overwrite is how a build ends up serving
// a policy nobody chose, with the losing declaration leaving no trace. Here
// the stakes are higher than a wiring mistake — declaring a method
// RESTRICTED and then declaring it again PUBLIC used to leave PUBLIC in
// force, and the clearance gate is one of the things this package exists to
// hold.
//
// Accepting the identical one is where this deliberately parts company with
// Register. Register refuses EVERY duplicate because it cannot do otherwise:
// a ResolverFunc is a closure and closures are not comparable, so "is this
// the same resolver?" has no answer there. A ToolDef is data, so the question
// has an answer, and the answer is what matters — an identical declaration
// changes no decision and discards nothing. It also arrives legitimately:
// Ruling 11 accepted that the generated Mount calls AddTools as well as
// RegisterXService, so a Core wired through both receives each package's
// declarations twice, unchanged. Refusing that would turn a supported wiring
// into a startup failure and buy no safety.
func (c *Core) AddTools(tools []ToolDef) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range tools {
		t := tools[i]
		if err := c.unimplementedGovernance(t); err != nil {
			return err
		}
		// Before any work: a conflicting declaration is a wiring bug, and
		// the diagnostic is clearer than whatever a compartment or plan
		// failure downstream would say about it.
		if prev, dup := c.tools[t.FullMethod]; dup && !sameDeclarationAs(prev, t) {
			return fmt.Errorf("tool %q: %s is already declared as %q, with a "+
				"different declaration; refusing to replace it. One method has "+
				"one policy — declaring it twice differently means two wirings "+
				"disagree about what it is, and whichever ran last would win "+
				"silently", t.Name, t.FullMethod, prev.Name)
		}
		for _, md := range []protoreflect.MessageDescriptor{t.Input, t.Output} {
			if md == nil {
				return fmt.Errorf("tool %q: nil descriptor", t.Name)
			}
			if _, ok := c.plans[md]; ok {
				continue
			}
			plan, err := policy.Compile(md, c.reg)
			if err != nil {
				return fmt.Errorf("tool %q: %w", t.Name, err)
			}
			c.plans[md] = plan
		}
		need, err := c.reg.Set(t.Compartments)
		if err != nil {
			return fmt.Errorf("tool %q: %w", t.Name, err)
		}
		c.need[t.FullMethod] = need
		c.tools[t.FullMethod] = t
	}
	return nil
}

// SetAvailability wires step 6's AvailabilitySource (svcwatch.go's
// ServiceWatcher, in production). It is a separate call from NewCore rather
// than a CoreConfig field because it is optional in exactly the way FGA and
// Grants are not: a Core with no NATS-backed tool has nothing to ask, and
// every Core built before this task existed worked correctly with the
// check simply absent (see checkAvailability's nil case).
//
// Calling it more than once REPLACES the source. There is no refusal on a
// second call the way Register refuses a second resolver for one
// procedure: unlike a resolver, a wrong AvailabilitySource does not open a
// path around the chain, it only changes an answer — a build that
// re-wires it deliberately (a test swapping in a fake mid-run, say) is not
// the failure mode Register's refusal exists to catch.
func (c *Core) SetAvailability(src AvailabilitySource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.availability = src
}

// PlanFor returns the compiled plan for a message type.
func (c *Core) PlanFor(md protoreflect.MessageDescriptor) (*policy.Plan, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.plans[md]
	if !ok {
		return nil, fmt.Errorf("no plan for %s; was it registered?", md.FullName())
	}
	return p, nil
}

func (c *Core) lookup(procedure string) (ToolDef, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.tools[procedure]
	return t, ok
}

// Visible is step 2, and the whole of it: verb ∧ clearance ∧ compartments.
//
// The catalogue lists what this returns true for and the chain denies what it
// returns false for, so discovery and enforcement cannot disagree — there is
// only one rule to disagree with (spec §4).
// MountedTools reports how many tool declarations this Core holds.
//
// A count, not a catalogue: it exists so a startup line can say what was
// actually mounted instead of carrying a number someone typed. Enumerating
// the tools is a different question with a different answer — it is
// per-principal, and Visible is how it is asked.
func (c *Core) MountedTools() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.tools)
}

// kindName renders a PrincipalKind for the ledger, empty for UNSPECIFIED so
// a token that did not say produces an absent field rather than a row
// asserting the principal was of an unspecified kind.
func kindName(k toolv1.PrincipalKind) string {
	if k == toolv1.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED {
		return ""
	}
	return k.String()
}

func (c *Core) Visible(p *Principal, t ToolDef) bool {
	return c.visibleLocked(p, t)
}

// visibleLocked is Visible's body, callable by a holder of c.mu.
//
// It reads nothing from c — visibility is a function of the principal and the
// declaration — so it is safe under either lock state. It exists so the
// catalogue can decide visibility while holding the read lock without
// re-entering Visible, and so that there remains exactly ONE expression of
// the rule: if this is ever changed, step 2 and the catalogue change together
// because both call it.
func (c *Core) visibleLocked(p *Principal, t ToolDef) bool {
	if p == nil {
		return false
	}
	return p.Verbs.Has(t.Verb) &&
		policy.Allows(p.Clearance, t.MinClearance) &&
		p.Compartments.Covers(c.need[t.FullMethod]) &&
		inScope(p.ToolSets, t.Sets)
}

// inScope applies the session's tool-set scope.
//
// It lives here, inside the visibility predicate, rather than as a filter on
// the catalogue — which means a scoped session cannot reach an out-of-scope
// tool by NAMING it either. A scope enforced only at listing time would be a
// suggestion, and step 2 is what makes it a rule.
//
// nil scope means unscoped: everything this principal is otherwise entitled
// to. A non-nil scope means only tools declaring membership of one of its
// sets — including a tool that declares NO sets, which is deliberately out of
// scope for every scoped session. An unclassified tool appearing in every
// scoped session would defeat the point of scoping.
//
// An undeclared set name in a token needs no special handling: it matches no
// tool, so it costs that caller reach and nothing else. That is the same
// stance SetLenient takes on an unknown compartment — an IdP-side typo should
// cost access, not availability — and here it is self-enforcing rather than
// something a check has to remember.
func inScope(scope, toolSets []string) bool {
	if scope == nil {
		return true
	}
	for _, s := range scope {
		for _, ts := range toolSets {
			if s == ts {
				return true
			}
		}
	}
	return false
}

// Invoke runs the chain for procedure, resolving it with the resolver
// registered for that procedure.
//
// Every error it returns is transport-neutral: the surface maps it to
// whatever its callers understand (see codeFor). The detailed reason went to
// the ledger and nowhere else.
func (c *Core) Invoke(
	ctx context.Context, p *Principal, procedure string, req proto.Message,
) (proto.Message, error) {
	return c.invoke(ctx, p, procedure, req, c.resolverFor(procedure))
}

// invoke is the chain of spec §5.1 steps 2-10. fn is the resolver for this
// call: Invoke supplies the registered one, and the connect adapter supplies
// the connect handler it is wrapping. The generated Mount now registers a
// typed resolver for every tool, so the registry is no longer empty — why
// the connect adapter still cannot use it (connect.AnyResponse is a sealed
// interface, so an interceptor holding only a proto.Message has no way to
// build a response) is set out in full on WrapUnary in interceptor.go.
//
// fn never crosses the package boundary in either direction, so the
// structural guarantee is unchanged: outside this package the only way to
// reach an implementation is still Invoke.
//
// Every error return sets ev.ErrorDetail to the text a human needs to
// understand the refusal — the field path that failed the write check, the
// gate the principal missed, the resolver's own error message. None of that
// text reaches the wire: the caller gets a code and a static message (see
// ScrubError and errStatic). The detail is the ledger's, and only the
// ledger's.
func (c *Core) invoke(
	ctx context.Context,
	p *Principal,
	procedure string,
	req proto.Message,
	fn ResolverFunc,
) (resp proto.Message, err error) {
	// Spec §5.1 step 9: emit EXACTLY ONE event, on every terminal path.
	//
	// The event is built here and filled in as the chain learns things, so
	// there is exactly one Record call and no `return` below can skip it.
	// That is not a refactoring preference: an earlier shape recorded only
	// after a successful sanitize, so unauthenticated calls, invisible-tool
	// NOT_FOUNDs, checkInput PERMISSION_DENIEDs and resolver errors all
	// returned before the Recorder and left NO ROW AT ALL. For a policy
	// product the denied calls are the rows anyone actually queries.
	//
	// Outcome starts at denied, not ok: every path that returns early is a
	// refusal, and the one that succeeds says so explicitly. An event that
	// escapes with an unset outcome should read as "blocked", never as
	// "fine".
	ev := c.newEvent(p, procedure)
	var (
		tool  ToolDef
		abort any
	)

	defer func() {
		if r := recover(); r != nil {
			ev.Outcome = ledger.OutcomeError
			if r == http.ErrAbortHandler { //nolint:errorlint // net/http compares with ==, so we do too
				// Not a failure to convert. ErrAbortHandler is a
				// deliberate "drop this connection, write nothing", and
				// net/http (and connect's own recover, recover.go:38)
				// re-raise it for exactly that reason. Answering the
				// caller anyway would be this package inventing a
				// response the handler decided not to give. Re-raised
				// below, after the ledger row.
				ev.ErrorDetail = "handler aborted the connection (http.ErrAbortHandler)"
				abort = r
			} else {
				// A panicking resolver must not take the process down,
				// and must not look like a successful call. It is an
				// internal error, ledgered as one, with the panic value
				// kept for the ledger and scrubbed off the wire like any
				// other detail.
				resp = nil
				err = fmt.Errorf("%w: resolver panicked: %v", errInternal, r)
				ev.ErrorDetail = fmt.Sprintf("resolver panicked: %v", r)
			}
		}
		// Exactly one event, whatever happened above — including the
		// abort, which is a terminal path like any other. Degrades: a
		// ledger that cannot publish must never turn a successful call
		// into a failed one.
		c.record(ctx, p, tool, ev)
		// Every terminal path, refusals included. An audited tool's REFUSALS
		// are audit-worthy too — "someone tried to move money and was turned
		// away" is a row an auditor wants. So an outcome with no preceding
		// intent means refused before the tool was reached, and an intent
		// with no outcome means started and never accounted for. Both are
		// legible, and neither is a gap.
		c.auditOutcome(ctx, tool, ev)
		if abort != nil {
			panic(abort)
		}
	}()

	// A surface that reaches here with no Principal has skipped step 1, and
	// every step below dereferences p — the denial detail two blocks down
	// reads p.Verbs, checkInputWrites reads p.Clearance, sanitize takes
	// p.Shape(). Without this, a nil principal panics, the defer converts
	// the panic to errInternal, and the ledger row reads "resolver panicked:
	// invalid memory address" for a call that never reached a resolver: a
	// refusal disguised as a crash, and a NotFound quietly promoted to
	// Internal.
	//
	// The refusal is returned directly rather than through Unauthenticated:
	// that helper records its own row, and this path already has a defer that
	// will record one. Two rows for one call would break the invariant this
	// whole shape exists to hold.
	if p == nil {
		ev.ErrorDetail = "no principal for " + procedure +
			": the surface called Invoke without completing step 1"
		return nil, errUnauthenticated
	}

	var known bool
	tool, known = c.lookup(procedure)
	if known {
		ev.Tool = tool.Name
		// Step 2. A tool the principal cannot use is reported as absent,
		// matching what its tools/list would have shown. Existence is
		// itself information: an under-cleared caller must not be able to
		// distinguish "no such tool" from "that tool exists but you may
		// not call it" by error code alone. The ledger, which is not the
		// caller, records which gate actually failed.
		if !c.Visible(p, tool) {
			ev.ErrorDetail = fmt.Sprintf(
				"tool %q invisible to principal: verb_ok=%v clearance_ok=%v compartments_ok=%v",
				tool.Name, p.Verbs.Has(tool.Verb),
				policy.Allows(p.Clearance, tool.MinClearance),
				p.Compartments.Covers(c.need[tool.FullMethod]))
			return nil, errNotFound
		}
	}

	// A surface that could not turn its wire payload into a proto message
	// passes nil. There is nothing to classify and therefore nothing to
	// enforce, so the call is refused rather than served.
	if req == nil {
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = "request payload is not a proto message"
		return nil, errInternal
	}

	// An unknown procedure is NOT a passthrough.
	//
	// MountService mounts a WHOLE connect service, while the tool registry
	// holds only annotated, non-excluded methods. An earlier shape answered
	// an unknown procedure with `return next(ctx, req)` and the comment
	// "not a tool; nothing to enforce" — which was false: classification
	// lives on the MESSAGE, so an unannotated or exclude: true sibling
	// returns exactly the same classified fields its tool siblings do, and
	// it got the full response with no input check, no sanitization, no
	// ScrubError and no ledger event.
	//
	// The default is inverted. A sibling whose messages this Core has
	// classified (a plan was compiled for them at AddTools) runs the same
	// field-level chain as a tool: checkInputWrites, sanitize, ledger. What
	// it does NOT get is the tool-level visibility gate (verb /
	// min_clearance / compartments), because a non-tool method declares
	// none — field policy is the whole of what the schema says about it,
	// and enforcing it is strictly better than enforcing nothing.
	//
	// A sibling whose request type has no plan at all is refused outright,
	// BEFORE the resolver runs: with no classification we cannot know what
	// is safe to accept or return, and refusing after the fact would still
	// have executed whatever effect the method has. Unimplemented is the
	// honest answer — on this Core, that procedure is not something we can
	// serve. L27 makes the omission a build error, so reaching this at
	// runtime means the service was assembled outside the generated path.
	if !known {
		if _, perr := c.PlanFor(req.ProtoReflect().Descriptor()); perr != nil {
			ev.ErrorDetail = "no compiled plan for the request type of " +
				procedure + ": " + perr.Error()
			return nil, errUnimplemented
		}
	}

	if err := c.checkInputWrites(p, req, &ev); err != nil {
		return nil, err
	}
	if err := c.validateInput(req, &ev); err != nil {
		return nil, err
	}
	if err := c.fgaPre(ctx, p, tool, req, &ev); err != nil {
		return nil, err
	}
	if err := c.verifyGrant(ctx, p, tool, &ev); err != nil {
		return nil, err
	}
	if known {
		if err := c.checkAvailability(tool, &ev); err != nil {
			return nil, err
		}
	}

	// The resolver — an out-of-process one, over NATS, above all — gets
	// the principal's own assertions on ctx, never a reachable *Principal
	// itself: see withInvocationContext's own doc comment for why this is
	// a value on a context the chain already owns, not a new path out of
	// it.
	// The audit write-ahead, and the LAST point at which refusing is still
	// free. After the next line the tool has run.
	//
	// Write-ahead rather than write-after because the alternative does not
	// work for anything irreversible: recording afterwards and failing the
	// response would tell the caller the payment did not happen, when it did.
	// Recording the intent first and refusing means the side effect never
	// occurs, which is the only thing "fail closed" can mean for a tool whose
	// effects cannot be undone.
	if err := c.auditIntent(ctx, tool, ev); err != nil {
		ev.Outcome = ledger.OutcomeDenied
		ev.ErrorDetail = "audit write-ahead failed: " + err.Error()
		return nil, fmt.Errorf("%w: the audit record could not be written", errUnavailable)
	}

	ctx = c.withInvocationContext(ctx, p)

	resp, err = c.resolve(ctx, procedure, req, fn)
	if err != nil {
		// The single most likely leak in this design: a resolver error
		// routinely interpolates the value it was protecting (e.g. "user
		// with email ada@corp.com not found"), and policy.Sanitize
		// never sees it — it only ever operates on successful response
		// messages. The surface scrubs every error that reaches it, not
		// just the happy path, and the original text is kept for the
		// ledger so that scrubbing it off the wire does not mean
		// destroying it.
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = err.Error()
		return nil, err
	}

	// A resolver that produced no message produced nothing to sanitize.
	// The call succeeded; what the surface sends is the surface's business.
	if resp == nil {
		ev.Outcome = ledger.OutcomeOK
		return nil, nil
	}

	if resp, err = c.fgaPost(ctx, p, tool, resp, &ev); err != nil {
		return nil, err
	}
	if err := c.sanitize(ctx, p, resp, &ev); err != nil {
		return nil, err
	}
	ev.Outcome = ledger.OutcomeOK
	return resp, nil
}

// auditIntent writes the intent row for a tool that declared an audit stream.
//
// Nil sink and no declaration are both "nothing to do" — and the pairing is
// what makes that safe: AddTools refuses to mount a tool declaring an audit
// level when no Sink is configured, so reaching here with a declaration and
// no sink is not a state a mounted Core can be in.
//
// Only fail_closed turns a write error into a refusal. A tool that asked for
// an audit trail but not a blocking one gets the ordinary degrade: the error
// is recorded and the call proceeds, because that is what it asked for.
func (c *Core) auditIntent(ctx context.Context, t ToolDef, ev ledger.Event) error {
	if c.audit == nil || t.AuditLevel != toolv1.Audit_LEVEL_AUDIT {
		return nil
	}
	ev.Outcome = ledger.OutcomeIntent
	err := c.audit.Write(ctx, ev)
	if err == nil {
		return nil
	}
	if t.AuditFailClosed {
		return err
	}
	return nil
}

// auditOutcome writes what actually happened, and CANNOT refuse.
//
// By the time this runs the tool has run. Failing the call here would report a
// side effect that did happen as one that did not, which is worse than the
// missing row. It must still be loud: an intent with no matching outcome says
// a call was authorised, started, and never accounted for.
func (c *Core) auditOutcome(ctx context.Context, t ToolDef, ev ledger.Event) {
	if c.audit == nil || t.AuditLevel != toolv1.Audit_LEVEL_AUDIT {
		return
	}
	if err := c.audit.Write(ctx, ev); err != nil {
		slog.Error("toolplane: the audit outcome could not be written; the stream now "+
			"holds an intent with no outcome for this call",
			"tool", t.FQN, "subject", ev.PrincipalSubject, "err", err)
	}
}

// newEvent opens the one ledger row this call will produce.
//
// Attribution is recorded for every outcome, not just successful ones —
// "who was denied" is the question a denial row exists to answer.
// Compartments are recorded by NAME via Registry.Names, never as the
// bitset: CompartmentSet bit assignment is stable only within a build,
// and a persisted bitmask would silently reinterpret every older ledger
// row after a rebuild (spec §9).
func (c *Core) newEvent(p *Principal, procedure string) ledger.Event {
	ev := ledger.Event{
		// The id belongs to the CALL and is minted here, where the call is
		// first observed, because everything downstream dedupes on it.
		// Delivery to the lake is at-least-once, so a redelivered event has
		// to carry the id it carried the first time; a publisher minting ids
		// while sending would give every retry a fresh one and make
		// duplicates indistinguishable from distinct calls.
		//
		// It is also the only thing tying an audited call's intent row to its
		// outcome row. Two writes, one id — without it the two halves of a
		// fail_closed call cannot be matched at all, and "started and never
		// finished" stops being answerable.
		ID:      ledger.NewEventID(),
		Time:    time.Now(),
		Tool:    procedure,
		Outcome: ledger.OutcomeDenied,
	}
	if p == nil {
		return ev
	}
	ev.Tenant = p.Tenant
	ev.PrincipalSubject = p.Subject
	ev.PrincipalKind = kindName(p.Kind)
	ev.PrincipalActor = p.Actor
	ev.ChainDepth = len(p.Chain)
	ev.ClearanceEffective = p.Clearance.String()
	ev.CompartmentsEffective = c.reg.Names(p.Compartments)
	return ev
}

// Unauthenticated is step 1's failure, ledgered.
//
// Building the Principal belongs to the surface, so its failure returns
// before Invoke is ever called — but the row still belongs to the same
// ledger as every other terminal path. Without this, the one outcome nobody
// authenticated for is the one outcome the ledger cannot see.
//
// Exported for that reason and that reason only: the surface is the one
// caller, because the surface is where step 1 happens.
func (c *Core) Unauthenticated(ctx context.Context, procedure string, cause error) error {
	ev := c.newEvent(nil, procedure)
	ev.ErrorDetail = "no principal for " + procedure
	if cause != nil {
		ev.ErrorDetail += ": " + cause.Error()
	}
	c.record(ctx, nil, ToolDef{}, ev)
	return errUnauthenticated
}

// record is steps 9 and 10, the two that DEGRADE.
//
// Neither may fail a call and neither may panic out of the defer that runs
// them: the recover in invoke has already fired by then, so a panic here
// would escape past the chain's own safety net. A recorder that misbehaves
// costs a log line, not the response.
func (c *Core) record(ctx context.Context, p *Principal, tool ToolDef, ev ledger.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("toolplane: ledger panicked; the call is unaffected",
				"tool", ev.Tool, "panic", r)
		}
	}()
	ctx = context.WithoutCancel(ctx)
	c.recorder.Record(ctx, ev)
	if c.notifier != nil {
		c.notifier.Notify(ctx, p, tool, ev)
	}
}

// checkInputWrites is step 3: reject a request that sets any field the
// principal may not write.
//
// Strict rejection rather than silent stripping: the field is absent from this
// principal's advertised schema, so its presence means either a stale client or
// a deliberate attempt, and both deserve an error.
// The ledger detail names the field path and the clearance it required, while
// the caller is told "permission denied" and nothing else. Which field was
// refused is precisely what an operator needs and precisely what an attacker
// must not learn.
func (c *Core) checkInputWrites(p *Principal, req proto.Message, ev *ledger.Event) error {
	// Same amendment as the response path: the plan is looked up by req's own
	// live descriptor, never by tool.Input.
	plan, err := c.PlanFor(req.ProtoReflect().Descriptor())
	if err != nil {
		ev.ErrorDetail = "no compiled plan for the request type: " + err.Error()
		return errInternal
	}
	root := req.ProtoReflect()
	for _, a := range plan.Actions {
		if policy.Allows(p.Clearance, a.Write) && p.Compartments.Covers(a.Need) {
			continue
		}
		if fieldIsSet(root, a.Path) {
			ev.ErrorDetail = fmt.Sprintf(
				"input sets %q, which requires write clearance %v; principal holds %v",
				a.Name, a.Write, p.Clearance)
			return errPermissionDenied
		}
	}
	return nil
}

// fgaPre is step 4: may this principal touch THIS object.
//
// A nil FGAChecker means no instance authorization was DECLARED, and the step
// returns nil. It never means "the check failed and we let it through": an FGA
// service that is unreachable is a closed failure, which is the checker's own
// error to return.
func (c *Core) fgaPre(
	ctx context.Context, p *Principal, tool ToolDef, req proto.Message, ev *ledger.Event,
) error {
	if c.fga == nil {
		return nil
	}
	if err := c.fga.Pre(ctx, p, tool, req); err != nil {
		ev.ErrorDetail = "instance authorization (pre) refused: " + err.Error()
		return errPermissionDenied
	}
	return nil
}

// verifyGrant is step 5: an approval-gated tool verifies its grant token.
//
// A nil GrantVerifier means no verifier is configured, which today is safe
// only because mount refuses to serve a MODE_GRANT tool at all. Nil is "not
// declared", never "checked and shrugged".
func (c *Core) verifyGrant(
	ctx context.Context, p *Principal, tool ToolDef, ev *ledger.Event,
) error {
	if c.grants == nil {
		return nil
	}
	if err := c.grants.Verify(ctx, p, tool); err != nil {
		ev.ErrorDetail = "grant verification refused: " + err.Error()
		return errPermissionDenied
	}
	return nil
}

// checkAvailability is step 6's own gate, run immediately before the
// resolver: is tool's service reachable right now. It is a DIFFERENT
// question from Visible (step 2, above) and must stay different — Visible
// answers "may this principal use this tool" and never changes based on
// whether a service happens to be up; checkAvailability answers "is it up"
// and never changes based on who is asking. Folding the two together would
// mean a tool a principal MAY use starts returning NotFound the moment its
// service blinks, which is exactly the confusion §5.8 exists to prevent
// (design spec's stack B): NotFound is reserved for a principal who may not
// use a tool, because existence is information, and a tool that silently
// vanishes reads to an agent as one that never existed.
//
// A nil c.availability (no AvailabilitySource wired — see SetAvailability)
// skips the check entirely, exactly like every other optional step in this
// chain: nil means "not declared," never "checked and refused."
func (c *Core) checkAvailability(t ToolDef, ev *ledger.Event) error {
	c.mu.RLock()
	src := c.availability
	c.mu.RUnlock()
	if src == nil {
		return nil
	}
	if ok, reason := src.Availability(t.FQN); !ok {
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = fmt.Sprintf("tool %q unavailable: %s", t.Name, reason)
		return errUnavailable
	}
	return nil
}

// withInvocationContext puts the part of design spec §4.1's
// InvocationContext that Core itself owns — the principal's own assertions
// and the ledger's own attribution — onto ctx, via contracts/callctx's
// existing seam (callctx.NewContext/FromContext), so an out-of-process
// resolver (a NATS-backed one, above all — toolplane/natsresolver.Call)
// can read them back without Core handing out anything reachable.
//
// This is deliberately NOT a new parameter on ResolverFunc. ResolverFunc's
// signature is the thing that makes Core.Invoke the only reachable path to
// an implementation (resolver.go's own doc comment); widening it to carry
// *Principal would be a decision about that guarantee, not about this
// value, and is not this function's call to make. Putting the value on ctx
// instead costs nothing structural: ctx already crosses this boundary on
// every call, an in-process resolver that never looks for it is unaffected,
// and nothing about reading a value off a context hands out a path INTO
// Core the way returning a resolver would.
//
// What is deliberately NOT carried, even here: clearance and compartments
// (spec §4.4 — the tool returns the full object and garm redacts; a tool
// that can see clearance is a tool that will eventually filter, the second
// unreviewed policy copy every design doc in this tree refuses), and the
// caller's own credential (the token itself never crosses this boundary in
// any form — see natsresolver.Call's own doc comment on headers carrying
// assertions, never credentials).
//
// causation_id is also left unset — empty because this build has no front
// door that threads in the immediate parent call's own id (the LLM
// generation that decided to call this tool, in design spec §4.2's
// diagram), not because it was forgotten. Core.Invoke's own signature has
// nothing to carry it from today; setting it requires a decision about
// THAT signature, which is not this function's to make.
//
// call_id, the deadline and trace context are deliberately NOT set here:
// those are per-HOP, minted by whichever resolver actually crosses the
// wire (natsresolver.Call mints its own), not per-INVOKE. A resolver that
// finds an InvocationContext already on ctx must fill those in itself
// rather than trust ones set this far upstream, or two resolvers reusing
// one ctx.Value(...) instance across retries would collide on one call_id.
func (c *Core) withInvocationContext(ctx context.Context, p *Principal) context.Context {
	// Prefer a correlation_id already on ctx: nothing upstream sets one
	// today, so this is inert in this build, but the day a front door
	// decodes an inbound callctx.Header (a delegated call, say) and puts it
	// on ctx before calling Invoke, overwriting it here would silently
	// sever that caller's own trace — the same reasoning
	// natsresolver.Call already applies to the rest of the message when it
	// clones an existing InvocationContext instead of building from
	// nothing.
	correlationID := newCorrelationID()
	if existing := callctx.FromContext(ctx).GetAttribution().GetCorrelationId(); existing != "" {
		correlationID = existing
	}
	ic := &toolv1.InvocationContext{
		Attribution: &toolv1.CallContext{
			Tenant:        p.Tenant,
			CorrelationId: correlationID,
		},
		Principal: &toolv1.InvocationPrincipal{
			Subject: p.Subject,
			Kind:    p.Kind,
		},
	}
	return callctx.NewContext(ctx, ic)
}

// newCorrelationID mints a fresh correlation id for a call that arrived
// with no transaction-level one already established (design spec §4.2:
// "correlation_id originates with the app OR garm" — either is legitimate,
// and nothing upstream of Core.Invoke threads one in today). Each Invoke
// call mints its own: that is conservative rather than wrong — it never
// MERGES two unrelated calls under one id — and stops short of inventing
// session-level correlation this package has no way to verify. Threading a
// caller-supplied correlation_id through ctx, so a whole MCP session or
// connect request chain shares one, is future work.
func newCorrelationID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("corr_%d", time.Now().UnixNano())
	}
	return "corr_" + hex.EncodeToString(b)
}

// resolve is step 6.
func (c *Core) resolve(
	ctx context.Context, procedure string, req proto.Message, fn ResolverFunc,
) (proto.Message, error) {
	if fn == nil {
		// Nothing is registered to serve this procedure. Refusing is the
		// honest answer, and it fails closed: an unresolvable procedure must
		// never look like a successful empty call.
		return nil, fmt.Errorf("%w: no resolver registered for %s", errUnimplemented, procedure)
	}
	return fn(ctx, req)
}

// fgaPost is step 7: the post-check, or the collection filter.
//
// Nil means not declared. A filter that CANNOT RUN must not return the
// unfiltered list, so an error here refuses the whole response rather than
// passing it through.
func (c *Core) fgaPost(
	ctx context.Context, p *Principal, tool ToolDef, resp proto.Message, ev *ledger.Event,
) (proto.Message, error) {
	if c.fga == nil {
		return resp, nil
	}
	out, err := c.fga.Post(ctx, p, tool, resp)
	if err != nil {
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = "instance authorization (post) refused: " + err.Error()
		return nil, errPermissionDenied
	}
	if out == nil {
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = "instance authorization (post) returned no message"
		return nil, errInternal
	}
	// A Post that REPLACES the message rather than filtering it in place is
	// refused, not accommodated. The connect adapter returns the response
	// object the handler produced, so a replacement would be sanitized and
	// then dropped while the original, unfiltered message went out — the
	// exact failure step 7 exists to prevent, arriving silently.
	//
	// Held structurally rather than by the doc comment on FGAChecker.Post,
	// because every other invariant in this package is: MountService builds
	// its own handler, Register only takes resolvers in. Whoever implements
	// step 7 gets a loud refusal instead of a contract they have to have
	// read. Supporting a replacing Post means changing the adapters first,
	// and then this guard, in that order.
	if out != resp {
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = "instance authorization (post) replaced the message"
		return nil, errInternal
	}
	return out, nil
}

// sanitize is step 8: apply the resolved plan to the response.
func (c *Core) sanitize(
	ctx context.Context, p *Principal, resp proto.Message, ev *ledger.Event,
) error {
	// Amendment: the plan is looked up by the LIVE response descriptor —
	// ProtoReflect().Descriptor() on the actual object the resolver returned
	// — never by tool.Output as recorded on the ToolDef at mount time. With
	// generated Go types the two happen to be the same descriptor, so
	// looking it up from tool.Output would pass every test in this package;
	// the two diverge for a dynamicpb message, and using tool.Output there
	// would resolve (and sanitize) against the wrong plan silently, rather
	// than failing loudly.
	plan, perr := c.PlanFor(resp.ProtoReflect().Descriptor())
	if perr != nil {
		// Fail closed: an unregistered response type has no plan, so we
		// cannot know what is safe to return.
		ev.Outcome = ledger.OutcomeError
		ev.ErrorDetail = "no compiled plan for the response type: " + perr.Error()
		return errInternal
	}
	resolved := c.cache.Resolve(plan, p.Shape())

	// No wrapper: policy.Sanitize enforces the descriptor pairing itself
	// now (it panics on a mismatch), so the guard lives with the primitive
	// instead of with this one caller. resolved is derived from resp's own
	// live descriptor five lines up, so the pairing holds by construction.
	paths := policy.Sanitize(resp, resolved, redact.Ctx{Key: c.hashKey, Tenant: p.Tenant})
	setRedactions(ctx, Redactions{Paths: paths, PlanHash: resolved.Hash})

	// Ledger attribution (tools spec §9). Paths and the plan hash only — a
	// redacted VALUE must never reach the ledger, which is the property this
	// whole design protects. DisclosedCount is the §10.5 counterpart:
	// how many audit_on_read fields this caller DID see.
	ev.RedactionPlan = resolved.Hash
	ev.RedactionCount = len(paths)
	ev.DisclosedCount = len(resolved.Disclosed)
	return nil
}

// fieldIsSet reports whether the field at the end of path is set on m, or on
// ANY element reached by path when it crosses a repeated or map field.
//
// This mirrors toolpolicy/sanitize.go's applyAction: a path element denotes
// one field number at every level of nesting, not one message instance, so
// a path through a repeated or map field fans out to every element the same
// way applyAction does when it applies a redaction. Checking only the first
// element (or bailing out at the first list/map crossing, as an earlier
// version of this function did) would let a caller smuggle a restricted
// value past checkInput by nesting it inside a repeated message or a map
// value — exactly the shape of collection the response side is careful to
// walk in full.
func fieldIsSet(m protoreflect.Message, path []protoreflect.FieldNumber) bool {
	if len(path) == 0 {
		return false
	}
	targets := []protoreflect.Message{m}

	// Walk every path element but the last, expanding across collections —
	// same shape as applyAction's first loop.
	for _, num := range path[:len(path)-1] {
		var next []protoreflect.Message
		for _, t := range targets {
			fd := t.Descriptor().Fields().ByNumber(num)
			if fd == nil || !t.Has(fd) {
				continue
			}
			v := t.Get(fd)
			switch {
			case fd.IsList():
				l := v.List()
				for i := 0; i < l.Len(); i++ {
					next = append(next, l.Get(i).Message())
				}
			case fd.IsMap():
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					if fd.MapValue().Kind() == protoreflect.MessageKind {
						next = append(next, mv.Message())
					}
					return true
				})
			default:
				next = append(next, v.Message())
			}
		}
		targets = next
		if len(targets) == 0 {
			return false
		}
	}

	last := path[len(path)-1]
	for _, t := range targets {
		fd := t.Descriptor().Fields().ByNumber(last)
		if fd != nil && t.Has(fd) {
			return true
		}
	}
	return false
}
