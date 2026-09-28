// Package nats reaches tool services over NATS.
//
// The one adapter. A second transport waits for a named trigger — an
// enterprise that cannot run NATS — rather than for a feeling that
// abstraction is tidy. Invocation is the easy half: any protocol does
// request/reply. Discovery is not. $SRV.INFO reports a service's contract
// version from the running process, where an HTTP deployment would report it
// from configuration — an observation against a promise.
package nats

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/garm-ai/garm/contracts/callctx"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/wire"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/garm-ai/garmd/internal/transport"
)

// Transport implements both ports over one connection.
type Transport struct {
	nc *nats.Conn

	// DiscoverWait is how long Services collects replies. Discovery is a
	// scatter-gather with no way to know how many will answer, so the only
	// termination condition is time.
	DiscoverWait time.Duration
}

func New(nc *nats.Conn) *Transport {
	return &Transport{nc: nc, DiscoverWait: 500 * time.Millisecond}
}

var (
	_ transport.Invoker    = (*Transport)(nil)
	_ transport.Discoverer = (*Transport)(nil)
)

// Invoke sends a request and unmarshals the reply into resp.
//
// The deadline comes from ctx and nowhere else. A transport imposing its own
// would silently cap a caller's, and a call that reports a timeout the caller
// did not ask for is a call whose effect is unknown.
func (t *Transport) Invoke(ctx context.Context, procedure string, req, resp proto.Message) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshalling the request for %s: %w", procedure, err)
	}

	// The context travels as a HEADER rather than in the body, so a tool
	// runtime reads it without the daemon and the service having to agree on
	// an envelope — and so that Plan 2 can move it into a sealed one by
	// changing contracts/callctx and nothing here.
	//
	// It carries ASSERTIONS, never the caller's credential. Forwarding the
	// token would hand every tool a replayable bearer credential and undo the
	// intersection property that makes delegation safe to reason about.
	ic := invocationFor(ctx)
	encoded, err := callctx.Encode(ic)
	if err != nil {
		return fmt.Errorf("encoding the invocation context for %s: %w", procedure, err)
	}
	msg := nats.NewMsg(wire.Subject(procedure))
	msg.Data = body
	msg.Header.Set(callctx.Header, encoded)

	reply, err := t.nc.RequestMsgWithContext(ctx, msg)
	if err != nil {
		if errors.Is(err, nats.ErrNoResponders) {
			// Distinguished on purpose: nothing is listening on that subject,
			// which means the catalogue declares a tool no service
			// implements. That is an operator's problem, and reporting it as
			// a tool failure sends someone to read handler code that is
			// working fine.
			return fmt.Errorf("%w: %s", transport.ErrUnreachable, procedure)
		}
		return fmt.Errorf("calling %s: %w", procedure, err)
	}

	// micro reports handler failures in headers, so a reply carrying an error
	// header is an error however well-formed its body.
	if code := reply.Header.Get(micro.ErrorCodeHeader); code != "" {
		return fmt.Errorf("%s returned %s: %s", procedure, code, reply.Header.Get(micro.ErrorHeader))
	}
	if err := proto.Unmarshal(reply.Data, resp); err != nil {
		// The response type came from this process's catalogue. A failure
		// here means the service is implementing a different contract from
		// the one being served, which reconciliation should have caught.
		return fmt.Errorf("%s replied with something that is not its declared response: %w",
			procedure, err)
	}
	return nil
}

// invocationFor is what this hop asserts, built from what the chain put on
// ctx.
//
// CLONED rather than mutated. The value on the context is shared with every
// other hop this call makes — a step-7 filter that re-resolves, a retry — and
// two resolvers writing into one instance would report two hops under one
// call_id, which is precisely the correlation the id exists to provide.
//
// An absent context is not an error here. An in-process caller — a probe, a
// test — legitimately has none, and the far side refuses a request whose
// header is missing or whose call_id is empty, so a well-formed header with a
// minted id is the honest thing to send: it identifies this hop and claims
// nothing about a principal.
func invocationFor(ctx context.Context) *toolv1.InvocationContext {
	ic := &toolv1.InvocationContext{}
	if up := callctx.FromContext(ctx); up != nil {
		ic = proto.Clone(up).(*toolv1.InvocationContext)
	}
	if ic.GetCallId() == "" {
		ic.CallId = newCallID()
	}
	// ABSOLUTE, from this context. A relative deadline would restart on every
	// hop, so a chain of three would take three times what the caller allowed
	// — and a call that reports a timeout the caller did not ask for is a call
	// whose effect is unknown.
	if deadline, ok := ctx.Deadline(); ok {
		ic.Deadline = timestamppb.New(deadline)
	}
	return ic
}

func newCallID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("call_%d", time.Now().UnixNano())
	}
	return "call_" + hex.EncodeToString(b[:])
}

// Services lists what is reachable, asking the services themselves.
//
// A scatter-gather on $SRV.INFO: publish once, collect for a window. There is
// no way to know how many instances exist, so the window is the termination
// condition — which means this reports what answered in time, not what exists.
// Treating a slow instance as absent is the safe direction: routing to one
// that never answers is worse than not routing to it.
func (t *Transport) Services(ctx context.Context) ([]transport.Service, error) {
	subject, err := micro.ControlSubject(micro.InfoVerb, "", "")
	if err != nil {
		return nil, fmt.Errorf("building the discovery subject: %w", err)
	}

	inbox := nats.NewInbox()
	replies := make(chan *nats.Msg, 64)
	sub, err := t.nc.ChanSubscribe(inbox, replies)
	if err != nil {
		return nil, fmt.Errorf("subscribing for discovery replies: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	if err := t.nc.PublishRequest(subject, inbox, nil); err != nil {
		return nil, fmt.Errorf("asking for service info: %w", err)
	}
	if err := t.nc.Flush(); err != nil {
		return nil, fmt.Errorf("flushing the discovery request: %w", err)
	}

	wait := t.DiscoverWait
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d < wait {
			wait = d
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	var out []transport.Service
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-timer.C:
			return out, nil
		case msg := <-replies:
			var info micro.Info
			if err := json.Unmarshal(msg.Data, &info); err != nil {
				// One malformed reply is not a reason to report nothing:
				// every other service answered correctly.
				continue
			}
			subjects := make([]string, 0, len(info.Endpoints))
			for _, e := range info.Endpoints {
				subjects = append(subjects, e.Subject)
			}
			out = append(out, transport.Service{
				Name:     info.Name,
				Instance: info.ID,
				Version:  info.Version,
				Identity: info.Metadata["garm.identity"],
				Subjects: subjects,
			})
		}
	}
}

// Watch is not implemented. Discovery is a poll today, and a watch that
// silently never fired would be worse than one that says so.
func (t *Transport) Watch(context.Context) (<-chan transport.Event, error) {
	return nil, errors.New("watch is not implemented; poll Services instead")
}
