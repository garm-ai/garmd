// Package transport is how garmd reaches the services that implement tools.
//
// Two ports, because they are two problems and only one of them is easy.
//
// Invocation is transport in the ordinary sense: send a request, get a reply.
// Any protocol does it.
//
// Discovery is not. It answers which services are actually reachable, at which
// contract version, advertising which identity — and it answers from the
// running process rather than from configuration. That distinction is the
// whole reason garmd can say a tool is "declared but unreachable" instead of
// assuming a catalogue entry means a service exists.
//
// NATS implements both natively. A hypothetical HTTP adapter implements
// invocation in an afternoon and discovery not at all, which is why the second
// adapter waits for a named trigger — an enterprise that cannot run NATS —
// rather than for a sense that abstraction is tidy. See the design record's
// decisions/2026-09-25-transport-is-a-port.md.
package transport

import (
	"context"

	"google.golang.org/protobuf/proto"
)

// Invoker executes one tool call.
//
// The signature takes and returns proto.Message rather than a generated type
// on purpose: garmd builds its requests as dynamic messages from catalogue
// descriptors, and the wire bytes are identical either way.
type Invoker interface {
	Invoke(ctx context.Context, procedure string, req proto.Message) (proto.Message, error)
}

// Discoverer reports what is reachable.
type Discoverer interface {
	// Services returns every reachable instance, once.
	Services(ctx context.Context) ([]Service, error)

	// Watch streams changes until ctx is done. A closed channel means the
	// watch ended; an error on the channel means it ended badly, and the
	// caller decides whether that is fatal.
	Watch(ctx context.Context) (<-chan Event, error)
}

// Service is one reachable instance, as it describes itself.
type Service struct {
	// Name is the proto service fully-qualified name, which is also the
	// queue group a NATS deployment balances over.
	Name string

	// Instance distinguishes replicas of the same service.
	Instance string

	// Version is the contract version the instance advertises.
	Version string

	// Identity is opaque to garmd, and deliberately so.
	//
	// A tool service advertises its descriptor hash here; an agent runner
	// advertises the digest of the bundle it loaded. garmd compares it
	// against what the catalogue pins and refuses to route on a mismatch —
	// without knowing, or needing to know, which of those it is holding.
	//
	// One mechanism rather than two is what keeps garmd from acquiring
	// knowledge of agents by the back door.
	Identity string
}

// EventKind is what happened to a service.
type EventKind int

const (
	// Added means an instance became reachable.
	Added EventKind = iota
	// Removed means an instance stopped being reachable, whether it drained
	// cleanly or vanished. garmd treats both the same: stop routing.
	Removed
)

// Event is one change to what is reachable.
type Event struct {
	Kind    EventKind
	Service Service
	Err     error
}
