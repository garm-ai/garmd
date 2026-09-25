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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"google.golang.org/protobuf/proto"

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

// Subject maps a route to a NATS subject: the same string in two syntaxes, so
// neither side keeps a mapping table that could disagree with the other's.
func Subject(fullMethod string) string {
	return strings.ReplaceAll(strings.TrimPrefix(fullMethod, "/"), "/", ".")
}

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

	msg, err := t.nc.RequestWithContext(ctx, Subject(procedure), body)
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
	if code := msg.Header.Get(micro.ErrorCodeHeader); code != "" {
		return fmt.Errorf("%s returned %s: %s", procedure, code, msg.Header.Get(micro.ErrorHeader))
	}
	if err := proto.Unmarshal(msg.Data, resp); err != nil {
		// The response type came from this process's catalogue. A failure
		// here means the service is implementing a different contract from
		// the one being served, which reconciliation should have caught.
		return fmt.Errorf("%s replied with something that is not its declared response: %w",
			procedure, err)
	}
	return nil
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
			out = append(out, transport.Service{
				Name:     info.Name,
				Instance: info.ID,
				Version:  info.Version,
				Identity: info.Metadata["garm.identity"],
			})
		}
	}
}

// Watch is not implemented. Discovery is a poll today, and a watch that
// silently never fired would be worse than one that says so.
func (t *Transport) Watch(context.Context) (<-chan transport.Event, error) {
	return nil, errors.New("watch is not implemented; poll Services instead")
}
