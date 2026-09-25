package toolplane

import (
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	"github.com/garm-ai/garm/contracts/ledger"
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
// The detail goes to the ledger and the sentinel goes on the wire, the same
// split every other refusal uses (see errors.go). Surfacing the violations
// to callers is a separate decision with its own disclosure analysis: a
// cross-field CEL rule can name a field the caller may not read, so "the
// caller sent it, so they may see it" is not true in general.
func (c *Core) validateInput(req proto.Message, ev *ledger.Event) error {
	if c.validator == nil {
		// Unreachable: NewCore refuses to build a Core without one, so that
		// a validator that failed to construct is a startup failure rather
		// than a step that silently stops running.
		ev.ErrorDetail = "no validator on this core"
		return errInternal
	}
	if err := c.validator.Validate(req); err != nil {
		ev.ErrorDetail = "input validation refused: " + err.Error()
		return errInvalidArgument
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
