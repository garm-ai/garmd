package grants

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
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

// ErrRefused means an approval WAS presented and is not good for this call:
// wrong tool, wrong subject, too old, already spent, or minted against
// material that differs from what is being sent.
//
// One sentinel for all of them, deliberately. Distinguishing them on the wire
// would tell an attacker which of several things they got right, and every one
// of them is the same answer to the caller: stop. It is separate from
// ErrGrantRequired because that one is the opposite answer — go and get an
// approval — and a caller told to fetch one when it had just presented a
// tampered one would do exactly that, forever.
//
// It exists so a surface can answer PERMISSION_DENIED. Without it these
// refusals reach the surface carrying no code at all and are answered
// "internal", which pages an operator for a caller's own mistake.
var ErrRefused = errors.New("the approval presented is not valid for this call")

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
// Every refusal except ErrGrantRequired is wrapped in ErrRefused, so the
// surface can classify it without knowing anything about grants, and the
// original sentence survives underneath for the ledger.
func (v *Verifier) Verify(
	ctx context.Context, p *toolplane.Principal, t toolplane.ToolDef, req proto.Message,
) error {
	err := v.verify(ctx, p, t, req)
	if err == nil || errors.Is(err, ErrGrantRequired) {
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
		return fmt.Errorf("the grant verifier is not configured")
	}

	raw := grantFrom(ctx)
	if raw == "" {
		return ErrGrantRequired
	}

	cl, err := v.parse(ctx, raw)
	if err != nil {
		return err
	}
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
		// during an outage is one an attacker only has to wait for.
		return fmt.Errorf("the grant could not be checked for reuse: %w", err)
	}
	return nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) parse(ctx context.Context, raw string) (*grantClaims, error) {
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
		return nil, fmt.Errorf("the grant's key: %w", err)
	}
	payload, err := sig.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("the grant's signature: %w", err)
	}
	return parseGrantClaims(payload)
}
