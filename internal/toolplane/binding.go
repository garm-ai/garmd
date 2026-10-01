package toolplane

import "context"

// What a grant was bound to, carried out of step 5 for the ledger.
//
// An approval binds to a tool, a subject, the material a person saw — and,
// once the STS mints one for a task, to that task (cards-and-tasks design §7:
// two tasks with the same material, the same payment asked twice, cannot
// share a grant). The chain does not CHECK the task id: the thing that knows
// which task is being decided is the caller that opened it, and a verifier
// comparing a claim against nothing would be a check in name only. What the
// chain owes it is the RECORD — "this call was authorised under task X" is a
// question asked of the ledger, afterwards, and it is unanswerable unless
// somebody writes it down.
//
// It travels on the context for the same reason the redaction record does:
// GrantVerifier.Verify returns an error and nothing else, and widening that
// signature to carry a diagnostic value would be a change to the seam rather
// than to this value. The direction is one way and write-only — the chain
// supplies the destination and step 5 fills it — so nothing a verifier
// receives lets it decide anything it could not already decide.
type grantBindingKey struct{}

// GrantBinding is what step 5 learned about what the approval covered.
type GrantBinding struct {
	// TaskID is the grant's `task` claim, empty when it carried none. Every
	// grant minted before the STS learned about tasks carries none, which is
	// why an absent one is an ordinary state and not a refusal.
	TaskID string
}

// NoteGrantBinding records what a grant was bound to.
//
// Exported because the verifier is a separate package by design — the chain
// holds a seam, not an implementation — and a no-op when nothing seeded the
// context, which is the ordinary case for a verifier called directly in a
// test.
func NoteGrantBinding(ctx context.Context, b GrantBinding) {
	if dst, ok := ctx.Value(grantBindingKey{}).(*GrantBinding); ok && dst != nil {
		*dst = b
	}
}

// withGrantBinding seeds a destination for the call about to be verified.
func withGrantBinding(ctx context.Context, dst *GrantBinding) context.Context {
	return context.WithValue(ctx, grantBindingKey{}, dst)
}

// LedgerTagTaskID is the ledger tag a bound grant's task lands under.
//
// A tag rather than a column: `ledger.Event` has no slot for it, the tags map
// already reaches the lake through `ToProto`, and adding a column to a
// contract shared with every other plane for one plane's claim is a change
// that should be asked for by a second caller. If the tasks work makes this a
// question people ask of every row, promote it then.
const LedgerTagTaskID = "task_id"

// WithGrantBindingForTest exposes the destination the chain seeds, so a test
// outside this package can assert that step 5 reports what a grant was bound
// to without making the seam available to anything that might act on it.
//
// It survives the unexported setter for the same reason
// Redactions/WithRedactions do: the two answer different questions. The chain
// needs a slot it owns; a test needs to read what landed in one.
func WithGrantBindingForTest(ctx context.Context, dst *GrantBinding) context.Context {
	if dst == nil {
		return ctx
	}
	return withGrantBinding(ctx, dst)
}
