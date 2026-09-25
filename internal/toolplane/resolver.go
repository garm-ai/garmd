package toolplane

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// ResolverFunc executes one tool: it receives the request message the chain
// has already checked and returns the response the chain will sanitize.
//
// It is step 6 of the chain and nothing else. Everything a resolver used to
// be trusted to do — check the caller, refuse a field, redact a response —
// happens around it, in Core.Invoke, whether the resolver remembers to or
// not.
//
// A resolver that returns (nil, nil) has produced nothing to sanitize, and
// the surface decides what to send. The one resolver in this build never
// does: serve wraps the NATS hop, and a hop that fails returns an error
// rather than an empty success — a payload the chain cannot classify is one
// it cannot make safe.
//
// The case is handled anyway because ResolverFunc is exported and the next
// surface will write its own.
type ResolverFunc func(ctx context.Context, req proto.Message) (proto.Message, error)

// registration is one procedure's resolver, plus the factory for its request
// message.
//
// newReq exists for the surfaces that have to BUILD a request rather than
// receive one already typed: MCP arrives as JSON against a procedure name,
// and the docs surface needs an empty message to project a schema from.
// Requiring it at registration means such a surface cannot be wired up
// against a procedure that has no way to make its request — the failure
// lands at startup instead of at the first call.
type registration struct {
	newReq func() proto.Message
	fn     ResolverFunc
}

// NewRequestFor returns a fresh, empty request message for a procedure, and
// whether one is registered.
//
// This is NOT the accessor the registry deliberately lacks. What it hands out
// is an empty MESSAGE, not the factory and not the resolver: a caller gets
// something to unmarshal into, and no way to reach an implementation. The
// line from spec §1 is that resolvers go in and none comes out, and a zero
// value of a request type is not a resolver.
//
// It exists because a surface that receives JSON against a procedure NAME —
// MCP is the one that forced it — has nothing to unmarshal into otherwise.
// Its only alternative would be a dynamicpb message built from the
// descriptor, which would work and would also mean MCP requests were a
// different Go type from every other surface's, for no benefit.
func (c *Core) NewRequestFor(procedure string) (proto.Message, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	reg, ok := c.resolvers[procedure]
	if !ok || reg.newReq == nil {
		return nil, false
	}
	return reg.newReq(), true
}

// Register binds a resolver to a procedure.
//
// This is the only exported thing that touches the resolver registry, and it
// only takes resolvers IN. There is deliberately no accessor: nothing outside
// this package can retrieve or enumerate a resolver, so the only way to reach
// a tool implementation is Invoke, which is the chain. A generated Mount hands
// closures in; it never gets one back.
//
// Handing a closure in creates no path around the chain. Handing one out
// would, and that is the line this package holds (spec §1, "there is no
// reachable path to a tool implementation that skips the chain").
func (c *Core) Register(procedure string, newReq func() proto.Message, fn ResolverFunc) error {
	if procedure == "" {
		return fmt.Errorf("toolplane: a resolver needs a procedure")
	}
	if newReq == nil {
		return fmt.Errorf("toolplane: resolver for %q has no request factory", procedure)
	}
	if fn == nil {
		return fmt.Errorf("toolplane: resolver for %q is nil", procedure)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.resolvers[procedure]; dup {
		// Refuse rather than replace. A silent overwrite is how one build
		// ends up serving a procedure with a resolver nobody meant to
		// register, and the losing registration leaves no trace.
		return fmt.Errorf("toolplane: procedure %q already has a resolver", procedure)
	}
	c.resolvers[procedure] = registration{newReq: newReq, fn: fn}
	return nil
}

// resolverFor returns the registered resolver, or nil. Unexported, and the
// only reader of c.resolvers besides Register.
func (c *Core) resolverFor(procedure string) ResolverFunc {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolvers[procedure].fn
}
