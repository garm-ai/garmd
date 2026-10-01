package grants

import (
	"fmt"

	"github.com/garm-ai/contracts/grants"
	"google.golang.org/protobuf/proto"

	"github.com/garm-ai/garmd/internal/toolplane"
)

// What this daemon REQUIRES of an approval, as opposed to what an approval IS.
//
// The reading of a grant — its claims, the canonical text of the values it
// binds, and the comparisons that follow from the token's format — is
// [github.com/garm-ai/contracts/grants], because three processes have to
// agree about it and one of them cannot import this package. What is left
// here is the part that is this deployment's: which issuers it trusts, what it
// calls itself, that a grant must carry a jti because THIS process makes it
// single-use, and that a tool's declaration is the ceiling.
//
// The line is drawn at "would another process reading the same token reach the
// same conclusion". Whether the grant approves this tool, this caller, these
// values: yes, and those delegate. Whether the issuer is one this deployment
// named: no, and that stays.

// checkShape is everything that does not need the request.
func (v *Verifier) checkShape(c *grants.Claims, p *toolplane.Principal, t toolplane.ToolDef) error {
	// A delegated identity cannot approve. This is what structurally prevents
	// an agent approving the destructive action it is about to take — not a
	// policy anybody configures, a shape the token cannot have.
	if err := c.CheckNoAct(); err != nil {
		return err
	}
	if !contains(v.Issuers, c.Issuer) {
		return fmt.Errorf("the grant's issuer %q is not trusted here", c.Issuer)
	}
	if !contains(c.Audience, v.Audience) {
		return fmt.Errorf("the grant was minted for %v, not for this deployment", c.Audience)
	}
	if c.ID == "" {
		return fmt.Errorf("the grant has no jti, so it cannot be made single-use")
	}
	if err := c.CheckTool(t.FQN); err != nil {
		return err
	}
	// Whose call was approved. An approval for one subject spent on another's
	// call is the confused deputy this check exists for. The nil guard is
	// this side's: CheckSubject refuses an empty subject, and a chain that
	// reached step 5 with no principal at all is a different fault.
	if p == nil {
		return fmt.Errorf("the grant approves a call by %q, and this call has no caller", c.Subject)
	}
	if err := c.CheckSubject(p.Subject); err != nil {
		return err
	}
	// Expiry, and the tool's own ceiling on top of it. MaxGrantAge zero means
	// the tool declared none — `serve` refuses to mount a MODE_GRANT tool in
	// that state, so reaching here with a zero is not a silent skip.
	if err := c.CheckFresh(v.now(), v.Skew, t.MaxGrantAge); err != nil {
		return err
	}
	// How senior the approver had to be. The tool says; the grant records who
	// it was.
	return c.CheckApprover(t.ApproverMinClearance, t.ApproverCompartments)
}

// checkMaterial compares what the human saw with what is being sent.
//
// The extraction needs the DESCRIPTORS, which only a side holding the
// catalogue has; the comparison needs only the digest, which every side has.
// So this reads the values off the actual request and hands them to the
// shared check: the issuer showed a human some values and digested them, and
// a caller that showed one thing and sent another gets a mismatch without the
// issuer ever needing a catalogue.
func (v *Verifier) checkMaterial(c *grants.Claims, t toolplane.ToolDef, req proto.Message) error {
	if len(t.MaterialFields) == 0 {
		// Nothing declared, so nothing bound. The grant covers the tool for a
		// window — weak for anything irreversible, which is why L14 pushes
		// destructive tools toward declaring material fields, but it is the
		// author's declaration and not this code's to override.
		return nil
	}
	if req == nil {
		return fmt.Errorf("this tool binds a grant to %d material field(s) and there "+
			"is no request to read them from", len(t.MaterialFields))
	}
	values, err := grants.Materialise(req.ProtoReflect(), t.MaterialFields)
	if err != nil {
		return err
	}
	return c.CheckMaterial(values)
}
