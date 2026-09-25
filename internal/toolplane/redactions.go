package toolplane

import "context"

// The record of what the sanitizer withheld, carried on the request context.
//
// Lifted out of the connect interceptor the monorepo kept it in: what the
// chain needs is the RECORD, so that step 9 can report which field paths were
// withheld without the values. The middleware that seeded it belonged to a
// transport this daemon does not use.

// Redactions records what the sanitizer did, for the ledger. Paths only —
// never values, which have no business leaving the field where they live.
type Redactions struct {
	Paths    []string
	PlanHash string
}

type redactionsKey struct{}

// WithRedactions seeds a context so the chain can record what it withheld.
//
// The connect surface gets this from its own middleware. A surface that calls
// Core.Invoke directly — MCP does — has to seed it, and without this it would
// silently report nothing withheld on every call: the setter writes through a
// pointer that would not be there, so the loss would be invisible rather than
// an error. Exported so that a second surface cannot get this subtly wrong.
func WithRedactions(ctx context.Context) context.Context {
	if _, ok := ctx.Value(redactionsKey{}).(*Redactions); ok {
		return ctx
	}
	return context.WithValue(ctx, redactionsKey{}, &Redactions{})
}

// RedactionsFrom retrieves what was redacted on this call.
//
// It never returns nil. When the HTTP middleware that seeds the context
// (see withRedactionsContext in server.go) has not run — a handler invoked
// directly in a test, for instance — it returns a detached zero value rather
// than forcing every caller to nil-check a pointer that "should" always be
// there.
func RedactionsFrom(ctx context.Context) *Redactions {
	if r, ok := ctx.Value(redactionsKey{}).(*Redactions); ok && r != nil {
		return r
	}
	return &Redactions{}
}

// setRedactions records a sanitiser's findings on the context, if one is
// carrying a record.
//
// A no-op when nothing seeded the context, which is deliberate: a handler
// invoked outside a served request is not a bug, and panicking there would
// make the chain untestable in isolation.
func setRedactions(ctx context.Context, r Redactions) {
	if cur, ok := ctx.Value(redactionsKey{}).(*Redactions); ok {
		*cur = r
	}
}
