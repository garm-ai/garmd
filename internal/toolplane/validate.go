package toolplane

import (
	"errors"
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	"github.com/garm-ai/contracts/ledger"
)

// Input validation is a step of the chain, and it lives in the Core for the
// same reason every other step does.
//
// protovalidate ships as a connect interceptor. Used that way, the connect
// surface would validate and MCP and the NATS binding would not — a front
// door that skips a step, which is the exact failure the Core extraction
// exists to prevent. One implementation, every surface.
//
// It sits AFTER step 3 and before step 4, and both halves of that placement
// are deliberate:
//
//   - after step 2, or an error leaks existence. "reference: value length
//     must be at most 16" tells a caller who may not call this tool at all
//     that the tool exists, that the field exists, and what shape it takes.
//     Step 2 answers NotFound precisely so none of that is learnable.
//
//   - after step 3, so a governance verdict wins. If a caller sets a field
//     they may not write AND it is malformed, the refusal they should see is
//     that they may not set it — not a shape complaint about a field they
//     were never allowed to send.
//
//   - before step 4 and the resolver, which is the reason this is worth its
//     binary cost: garm is the hop before the tool, so a request that can
//     never succeed costs no FGA lookup, no NATS round-trip, and no side
//     effect from a handler that was about to write something.
//
// The full detail goes to the ledger, as every other refusal's does. What
// goes on the wire is the sentinel AND the violations this caller may see —
// see violations.go for the rule. The disclosure analysis that decides which
// those are: a violation names a field, a rule and a sentence, and the only
// one of the three that can say something this caller was not already shown
// is the field. So a violation is listed when its field path is in the
// caller's own input projection (SchemaFor at the caller's shape, the same
// object ListTools sent them), a CEL rule when every field its expression
// selects is; the sentence is protovalidate's own, which describes the
// constraint rather than the value, and is dropped in favour of the rule id
// alone wherever it could not be (a computed CEL message, a standard message
// that happens to contain the refused string). The caller's own values never
// appear: it sent them.
func (c *Core) validateInput(p *Principal, t ToolDef, req proto.Message, ev *ledger.Event) error {
	if c.validator == nil {
		// Unreachable: NewCore refuses to build a Core without one, so that
		// a validator that failed to construct is a startup failure rather
		// than a step that silently stops running.
		ev.ErrorDetail = "no validator on this core"
		return errInternal
	}
	if err := c.validator.Validate(req); err != nil {
		ev.ErrorDetail = "input validation refused: " + err.Error()
		var verr *protovalidate.ValidationError
		if !errors.As(err, &verr) {
			// Not a violation — a rule that could not be compiled or
			// evaluated. Nothing to list, and the same answer as before.
			return errInvalidArgument
		}
		return &ValidationRefusal{Violations: c.admittedViolations(t, p, verr)}
	}
	return nil
}

// newValidator builds the shared validator.
//
// protovalidate compiles each message's constraints once and caches them, so
// this is constructed per Core and never per call.
func newValidator() (protovalidate.Validator, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("toolplane: building the input validator: %w", err)
	}
	return v, nil
}
