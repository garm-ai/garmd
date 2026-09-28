package toolplane

import "context"

// The ledger event id of a call, handed back to whatever surface made it.
//
// It goes out on ctx rather than through Invoke's signature for the same
// reason the invocation context does (withInvocationContext's doc comment):
// ResolverFunc's shape is what makes Core.Invoke the only reachable path to an
// implementation, and Invoke's own signature is the surface's contract with
// the chain. Widening either to carry a diagnostic identifier would be a
// decision about that guarantee rather than about this value.
//
// The direction is deliberately one-way and write-only. A surface supplies a
// destination; the chain fills it. Nothing here lets a caller CHOOSE an id —
// the id belongs to the call, is minted where the call is first observed, and
// everything downstream dedupes on it, so a surface able to set one would be a
// second author of the ledger's join key.
type eventIDKey struct{}

// WithEventID arranges for the id of the one ledger row a call made under ctx
// produces to be written to dst.
//
// dst is written exactly once, from the goroutine that called Invoke or
// Unauthenticated and before either returns, so an ordinary *string needs no
// synchronisation — the surface reads it after the call it made.
func WithEventID(ctx context.Context, dst *string) context.Context {
	if dst == nil {
		return ctx
	}
	return context.WithValue(ctx, eventIDKey{}, dst)
}

// noteEventID records the id of the row this call will produce. A ctx with no
// destination is the ordinary case — an in-process caller that never asked —
// and costs one type assertion.
func noteEventID(ctx context.Context, id string) {
	if dst, ok := ctx.Value(eventIDKey{}).(*string); ok && dst != nil {
		*dst = id
	}
}
