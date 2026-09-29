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
	"errors"

	"google.golang.org/protobuf/proto"
)

// ErrUnreachable is a tool the catalogue declares with nothing serving it.
//
// Distinguished from a failure because they are different people's problems:
// unreachable is an operator's, and a tool that ran and failed is the
// caller's. Collapsing them makes a missing deployment look like a broken
// tool.
var ErrUnreachable = errors.New("no service is serving this tool")

// CodedError is a tool that RAN and answered with a code: NATS micro's
// error headers, as tool-go's toolbind.CodedError puts them there.
//
// It is the tool's answer, not a transport failure, and the two are
// different people's problems — which is why it is a type the chain can
// recognise rather than text in an error string. The code is the transport's
// spelling ("404"); which codes mean what to a caller is the chain's
// decision, in toolplane, and this type carries no opinion on it.
//
// Message is the tool's own words. Tools promise a page-free message, and
// nothing on this side relies on the promise: the chain keeps it for the
// ledger and the wire gets a static sentence for the code.
type CodedError struct {
	Procedure string
	Code      string
	Message   string
}

func (e *CodedError) Error() string {
	return e.Procedure + " returned " + e.Code + ": " + e.Message
}

// ToolCode and ToolMessage are how the chain reads a coded answer without
// importing this package: it asks errors.As for anything that answers both.
func (e *CodedError) ToolCode() string    { return e.Code }
func (e *CodedError) ToolMessage() string { return e.Message }

// Invoker executes one tool call.
//
// The caller supplies BOTH messages. It holds the catalogue, so it is the only
// side that knows what a reply should be unmarshalled into — and a transport
// that had to know would have to be re-released whenever a catalogue changed,
// which is the coupling this whole design removes.
//
// proto.Message rather than a generated type because garmd builds both from
// catalogue descriptors as dynamic messages. The wire bytes are identical
// either way.
type Invoker interface {
	Invoke(ctx context.Context, procedure string, req, resp proto.Message) error
}

// ErrIncompleteRound is a discovery round that could not be heard in full.
//
// It is NOT a failure: the replies that did arrive are good, and Round carries
// them. What it withdraws is the licence to reason from SILENCE. A service
// missing from an incomplete round may be gone or may simply not have been
// heard, and the whole value of discovery is that garmd can say "declared but
// unreachable" and mean it.
//
// Spelled as a sentinel so a caller can tell the two questions apart with
// errors.Is: "this service did not answer" is a fact about the plane, and "I
// could not hear the whole plane" is a fact about the round.
var ErrIncompleteRound = errors.New("discovery round was incomplete")

// Round is one discovery answer: what was heard, and what was not heard
// well enough to reason from.
//
// The two are separate fields because they license different conclusions.
// Services is positive evidence and is always usable — an instance that
// answered answered. Enumeration and Partial are the boundaries of the
// negative evidence, and negative evidence is what quarantines are lifted on.
type Round struct {
	// Services is every instance that answered, across every service heard.
	Services []Service

	// Enumeration is non-nil when the round could not establish the full set
	// of services running on the plane — wrapping [ErrIncompleteRound].
	//
	// While it is set, ABSENCE MEANS NOTHING. A service missing from
	// Services may be stopped or may simply never have been heard, and a
	// caller that concludes the first is one dropped reply away from
	// refusing a healthy tool.
	Enumeration error

	// Partial names the services whose own round was incomplete, and why —
	// each wrapping [ErrIncompleteRound].
	//
	// The service was heard; some of its INSTANCES were not. That is enough
	// to act on what was heard (an instance advertising the wrong contract
	// is advertising the wrong contract) and not enough to clear a verdict,
	// because the instance that would have contradicted it may be the one
	// that went unheard.
	Partial map[string]error
}

// ConcludesAbsence reports whether this round is evidence about what is NOT
// running.
//
// False means the round heard an unknown amount of the plane, so a caller
// must leave its previous verdicts standing rather than lift them.
func (r Round) ConcludesAbsence() bool { return r.Enumeration == nil }

// Complete reports whether name was heard in full, and so whether a verdict
// about it may be cleared by this round.
func (r Round) Complete(name string) bool {
	if r.Enumeration != nil {
		return false
	}
	_, partial := r.Partial[name]
	return !partial
}

// Discoverer reports what is reachable.
type Discoverer interface {
	// Services asks the plane what is running, once.
	//
	// The error is reserved for a round that could not be RUN — a closed
	// connection, a cancelled caller. A round that ran and heard only part
	// of the plane is a successful call returning an incomplete Round, and
	// the distinction matters: the first says nothing about the plane, the
	// second says something about part of it.
	Services(ctx context.Context) (Round, error)

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

	// Subjects is what this instance answers on. Needed to work out which
	// tools it claims to serve, which is what Identity gets compared for.
	Subjects []string
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
