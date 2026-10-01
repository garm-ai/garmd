// Package grants is step 5: a tool declaring MODE_GRANT does not run until a
// grant token says somebody senior enough agreed, recently enough, to these
// values — and until that grant has not been spent before.
//
// What is HERE is spending one. What a grant IS — its claims, the canonical
// text of the values it binds, and the comparisons that follow from the
// token's format — is [github.com/garm-ai/contracts/grants], because three
// processes have to agree about it: the STS that mints a grant, this daemon
// that spends it at the gate, and the tasks service that must refuse a
// decision whose grant names another task. Two of them cannot import this
// package, and the one credential in the system that authorises an
// irreversible act is the last place to let two readers drift apart.
//
// So this package keeps what is a DEPLOYMENT's rather than a token's: which
// issuers are trusted and what this daemon calls itself, the replay cache
// that makes a grant single-use, and the three sentinels below — which exist
// so a surface can answer the right code and an operator is paged for the
// right thing. The shared package has one kind of error; the difference
// between "the caller's approval is bad", "the caller has no approval yet"
// and "this deployment could not check" is three different next moves, and
// deciding between them is a daemon's job.
//
// It also does not check the task claim, and that is the design. See
// [grants.Claims.Task] and TestTheClaimsGarmdChecksAreUnchanged.
package grants

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/grants"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/replay"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// ErrGrantRequired means no grant was presented for a tool that needs one.
//
// Distinct from every other refusal because it is the only one with a next
// move: the caller can obtain an approval and come back. A wrong grant, an
// expired one or a spent one are all denials, and telling them apart on the
// wire would say which of several things an attacker got right.
var ErrGrantRequired = errors.New("a human grant is required")

// ErrRefused means an approval WAS presented, was CHECKED, and is not good
// for this call: not a well-formed token, signed by a key the issuer does not
// publish, wrong issuer, wrong audience, wrong tool, wrong subject, carrying a
// delegation chain, too old, already spent, or minted against material that
// differs from what is being sent.
//
// Every one of them is the CALLER's fault. One sentinel for all of them,
// deliberately: distinguishing them on the wire would tell an attacker which
// of several things they got right, and every one is the same answer — stop.
// It is separate from ErrGrantRequired because that one is the opposite answer
// — go and get an approval — and a caller told to fetch one when it had just
// presented a tampered one would do exactly that, forever.
//
// It is separate from ErrUnavailable because that one is not the caller's
// fault at all, and the two must be distinguishable by anything that decides
// whether to wake an operator. What they share is the answer on the wire.
//
// It exists so a surface can answer PERMISSION_DENIED. Without it these
// refusals reach the surface carrying no code at all and are answered
// "internal", which pages an operator for a caller's own mistake.
var ErrRefused = errors.New("the approval presented is not valid for this call")

// ErrUnavailable means the approval could not be CHECKED.
//
// Three shapes, and none of them is the caller's fault: this verifier is
// half-configured, the key set that signs approvals could not be fetched, or
// the replay cache could not answer whether the grant was already spent.
//
// It still refuses, and it still answers PERMISSION_DENIED on the wire. Not
// because the grant was bad — nobody knows — but because the alternative is
// running an approval-gated tool on an approval nobody verified, and because a
// caller cannot act differently on "denied" than on "we could not check": both
// mean stop, and saying which would tell a prober when this deployment's
// dependencies are down.
//
// What it changes is the OPERATOR's view. Wrapped separately so the surface
// can log exactly these at error level and leave the caller's own bad
// approvals unlogged — otherwise an IdP outage looks like a spike of people
// presenting tampered grants, and the one person who can fix it is the one
// person not told.
var ErrUnavailable = errors.New("the approval could not be checked")

// Verifier is step 5.
type Verifier struct {
	// Keys verifies the grant's signature. The same JWKS the subject token is
	// verified against when the issuer is the same service, and a separate one
	// when approvals are issued elsewhere.
	Keys *authn.KeySet

	// Issuers is the allowlist. An approval from an issuer nobody named is
	// somebody else's approval.
	Issuers []string

	// Audience is this daemon's identifier. A grant minted for another
	// deployment is a valid grant and must not be spendable here.
	Audience string

	// Spent records single-use. Required: a grant that can be replayed is one
	// approval authorising every call the window allows.
	Spent replay.Cache

	Skew time.Duration
	Now  func() time.Time
}

// grantFromContext is how the surface hands a presented grant to the chain.
type ctxKey struct{}

// WithGrant puts a presented grant token on the context.
//
// Unexported key, so nothing outside this package can inject one — a caller
// able to put a grant on a context could approve its own call.
func WithGrant(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKey{}, token)
}

// GrantFromContextForTest exposes what the surface put on the context, so a
// test outside this package can assert the header was lifted without making
// the accessor available to anything that might act on it.
func GrantFromContextForTest(ctx context.Context) string { return grantFrom(ctx) }

func grantFrom(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}

// Verify implements toolplane.GrantVerifier.
//
// Every refusal that is the CALLER's fault is wrapped in ErrRefused, so the
// surface can classify it without knowing anything about grants, and the
// original sentence survives underneath for the ledger. ErrGrantRequired and
// ErrUnavailable are already the answer they need to be and pass through: the
// first is the one refusal with a next move, the second is this deployment's
// own failure and is the one the operator has to be told about.
func (v *Verifier) Verify(
	ctx context.Context, p *toolplane.Principal, t toolplane.ToolDef, req proto.Message,
) error {
	err := v.verify(ctx, p, t, req)
	if err == nil || errors.Is(err, ErrGrantRequired) || errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrRefused, err)
}

// verify is every check, each returning the sentence that says which one
// failed. Verify above is what turns those into a code a surface can act on.
func (v *Verifier) verify(
	ctx context.Context, p *toolplane.Principal, t toolplane.ToolDef, req proto.Message,
) error {
	if t.ApprovalMode != toolv1.Approval_MODE_GRANT {
		return nil
	}
	if v == nil || v.Keys == nil || v.Spent == nil || len(v.Issuers) == 0 || v.Audience == "" {
		// Refusing rather than passing. A half-configured verifier that let
		// grant-gated tools through would be the single worst failure in this
		// package, and AddTools only mounted the tool because something
		// claimed this seam existed.
		return fmt.Errorf("%w: the grant verifier is not configured", ErrUnavailable)
	}

	raw := grantFrom(ctx)
	if raw == "" {
		return ErrGrantRequired
	}

	cl, err := v.parse(ctx, raw)
	if err != nil {
		return err
	}
	// Recorded BEFORE the checks, so a refused grant's binding reaches the
	// ledger too. Nothing here reads it — see grants.Claims.Task, whose own
	// comment says the daemon deliberately ignores it — and nothing
	// downstream may: it is attribution, and a claim that could deny a call
	// would be a second place to look when one is refused. The tasks service
	// is what checks a grant against the task it was given on, with
	// CheckTask, which this verifier must never start calling.
	toolplane.NoteGrantBinding(ctx, toolplane.GrantBinding{TaskID: cl.Task})

	if err := v.checkShape(cl, p, t); err != nil {
		return err
	}
	if err := v.checkMaterial(cl, t, req); err != nil {
		return err
	}

	// Spending LAST, after every other check has passed.
	//
	// Order matters: spending first would let a malformed or mis-targeted
	// grant burn a legitimate approval, so an attacker could invalidate
	// somebody else's pending payment by replaying their grant at the wrong
	// tool. Nothing is consumed until the grant is known good.
	if err := v.Spent.Spend(ctx, cl.ID); err != nil {
		if errors.Is(err, replay.ErrAlreadySpent) {
			return fmt.Errorf("this grant has already been used; an approval " +
				"authorises one call")
		}
		// Could not find out. Refuses, because a replay cache that fails open
		// during an outage is one an attacker only has to wait for — and says
		// so as ErrUnavailable, because the caller did nothing wrong and the
		// broker being down is nobody's problem but the operator's.
		return fmt.Errorf("%w: the grant could not be checked for reuse: %w",
			ErrUnavailable, err)
	}
	return nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) parse(ctx context.Context, raw string) (*grants.Claims, error) {
	sig, err := jose.ParseSigned(raw, authn.PermittedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("the grant is not a well-formed token: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("the grant carries %d signatures, want 1", len(sig.Signatures))
	}
	kid := sig.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, fmt.Errorf("the grant has no kid")
	}
	key, err := v.Keys.Key(ctx, kid)
	if err != nil {
		// A kid the issuer does not publish is a grant we can judge: bad. Any
		// other failure of Key means the key set could not be read at all, so
		// nothing has been judged and the operator is the one who needs to
		// know — the first grant to arrive while the STS is down lands here.
		if errors.Is(err, authn.ErrNoSuchKey) {
			return nil, fmt.Errorf("the grant's key: %w", err)
		}
		return nil, fmt.Errorf("%w: the keys that sign approvals: %w", ErrUnavailable, err)
	}
	payload, err := sig.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("the grant's signature: %w", err)
	}
	return grants.ParseClaims(payload)
}
