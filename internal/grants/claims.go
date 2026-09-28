package grants

import (
	"encoding/json"
	"fmt"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/grant"
	"github.com/garm-ai/garmd/internal/toolplane"
	"google.golang.org/protobuf/proto"
)

// grantClaims is an approval, on the wire.
type grantClaims struct {
	Issuer   string
	Audience []string
	ID       string // jti — what makes it single-use
	IssuedAt time.Time
	Expires  time.Time

	// Tool is the FQN this approval is for. Without it an approval for
	// get_balance is spendable on initiate_payment.
	Tool string

	// Subject is whose call was approved. Without it, Alice's approval
	// authorises Bob's payment.
	Subject string

	// Material is the digest over the values the human saw.
	Material string

	// Approver is who clicked, and what authority they held. Checked against
	// the tool's approver_min_clearance and approver_compartments — the tool
	// says how senior an approver must be, and the grant says how senior this
	// one was.
	Approver             string
	ApproverClearance    string
	ApproverCompartments []string

	// HasAct records whether the token carried a delegation chain. A
	// delegated identity may not approve: it is what structurally stops an
	// agent approving its own destructive action.
	HasAct bool
}

func parseGrantClaims(payload []byte) (*grantClaims, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("the grant's body is not JSON: %w", err)
	}
	g, _ := raw["garm_grant"].(map[string]any)
	if g == nil {
		return nil, fmt.Errorf("the token carries no garm_grant claim, so it is not " +
			"an approval — a delegation token is not a grant and must not be " +
			"spendable as one")
	}
	_, hasAct := raw["act"]

	c := &grantClaims{
		Issuer:               str(raw, "iss"),
		Audience:             strSlice(raw, "aud"),
		ID:                   str(raw, "jti"),
		IssuedAt:             unix(raw, "iat"),
		Expires:              unix(raw, "exp"),
		Tool:                 str(g, "tool"),
		Subject:              str(g, "subject"),
		Material:             str(g, "material"),
		Approver:             str(g, "approver"),
		ApproverClearance:    str(g, "approver_clearance"),
		ApproverCompartments: strSlice(g, "approver_compartments"),
		HasAct:               hasAct,
	}
	return c, nil
}

// checkShape is everything that does not need the request.
func (v *Verifier) checkShape(c *grantClaims, p *toolplane.Principal, t toolplane.ToolDef) error {
	// A delegated identity cannot approve. This is what structurally prevents
	// an agent approving the destructive action it is about to take — not a
	// policy anybody configures, a shape the token cannot have.
	if c.HasAct {
		return fmt.Errorf("the grant carries a delegation chain; an approval must be " +
			"given by a person acting as themselves, or an agent could approve its " +
			"own irreversible call")
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
	if c.Tool != t.FQN {
		return fmt.Errorf("the grant approves %q and this call is %q", c.Tool, t.FQN)
	}
	// Whose call was approved. An approval for one subject spent on another's
	// call is the confused deputy this check exists for.
	if p == nil || c.Subject != p.Subject {
		return fmt.Errorf("the grant approves a call by %q, not by this caller", c.Subject)
	}

	now := v.now()
	if !c.Expires.IsZero() && now.After(c.Expires.Add(v.Skew)) {
		return fmt.Errorf("the grant expired at %s", c.Expires.UTC().Format(time.RFC3339))
	}
	// The tool's declaration is a CEILING the issuer cannot raise. An issuer
	// minting a day-long approval for a tool that asked for fifteen minutes
	// gets fifteen minutes, because the tool is the thing that knows how stale
	// an approval may be for what it does.
	if t.MaxGrantAge > 0 {
		if c.IssuedAt.IsZero() {
			return fmt.Errorf("the grant has no iat, so its age cannot be checked " +
				"against the tool's maximum")
		}
		if age := now.Sub(c.IssuedAt); age > t.MaxGrantAge+v.Skew {
			return fmt.Errorf("the grant is %s old and this tool accepts approvals "+
				"up to %s", age.Truncate(time.Second), t.MaxGrantAge)
		}
	}

	// How senior the approver had to be. The tool says; the grant records who
	// it was.
	if t.ApproverMinClearance != toolv1.Clearance_CLEARANCE_UNSPECIFIED {
		got, ok := toolv1.Clearance_value[normaliseClearance(c.ApproverClearance)]
		if !ok || toolv1.Clearance(got) < t.ApproverMinClearance {
			return fmt.Errorf("the approver held %q and this tool requires at least %s",
				c.ApproverClearance, t.ApproverMinClearance)
		}
	}
	for _, need := range t.ApproverCompartments {
		if !contains(c.ApproverCompartments, need) {
			return fmt.Errorf("the approver does not hold the %q compartment this "+
				"tool requires of an approver", need)
		}
	}
	return nil
}

// checkMaterial compares what the human saw with what is being sent.
func (v *Verifier) checkMaterial(c *grantClaims, t toolplane.ToolDef, req proto.Message) error {
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
	values, err := Materialise(req.ProtoReflect(), t.MaterialFields)
	if err != nil {
		return err
	}
	want := grant.Digest(values)
	if c.Material == "" {
		return fmt.Errorf("this tool binds a grant to its material fields and the " +
			"grant carries no digest, so it approves the tool rather than the call")
	}
	if c.Material != want {
		// Deliberately does not say which field differs. The caller sent the
		// request and knows its values; naming the difference would only help
		// somebody probing what an approval covered.
		return fmt.Errorf("the request does not match what was approved")
	}
	return nil
}
