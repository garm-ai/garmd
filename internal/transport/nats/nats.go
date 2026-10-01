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
	"sort"
	"sync"
	"time"

	"github.com/garm-ai/contracts/callctx"
	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/wire"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/synadia-io/orbit.go/natsext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/garm-ai/garmd/internal/transport"
)

// Transport implements both ports over one connection.
type Transport struct {
	nc *nats.Conn

	// DiscoverWait is the CEILING on one call to Services — the whole call,
	// not each round inside it.
	//
	// It used to be the termination condition, and every sweep paid all of
	// it however fast the plane answered. DiscoverStall terminates a round
	// now, so this binds only when the plane is silent or pathologically
	// slow. Two seconds because the cost is no longer paid on the happy
	// path, and because it has to stay comfortably under the reconciler's
	// five-second per-sweep timeout: discovery's own ceiling should be what
	// ends a slow round, not the caller's, so the round can report what it
	// heard instead of being cut off mid-collection.
	DiscoverWait time.Duration

	// DiscoverStall is how long a round waits for the NEXT reply before
	// deciding the answers have stopped.
	//
	// A $SRV.INFO reply is assembled in the responding process with no I/O,
	// so replicas of one service answer in a tight cluster: the spread is
	// the broker's fan-out plus each process's scheduling, which is
	// sub-millisecond to a few milliseconds on a LAN. A hundred milliseconds
	// is about two orders of magnitude above that, so a quiet hundred
	// milliseconds means the service has finished answering rather than that
	// one replica was descheduled.
	//
	// Being wrong is bounded and visible rather than silent: a replica that
	// misses the stall makes the count fall short of what the enumeration
	// said exists, which is exactly the condition that marks the service
	// Partial.
	DiscoverStall time.Duration

	// DiscoverConcurrency is how many per-service rounds run at once.
	//
	// The work is waiting, not computing, so this is about bounding open
	// subscriptions rather than CPU. Eight keeps a plane of a few dozen
	// services to a handful of waves inside the ceiling while never holding
	// more than eight inboxes open.
	DiscoverConcurrency int
}

func New(nc *nats.Conn) *Transport {
	return &Transport{
		nc:                  nc,
		DiscoverWait:        2 * time.Second,
		DiscoverStall:       100 * time.Millisecond,
		DiscoverConcurrency: 8,
	}
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
	// header is an error however well-formed its body. It is a TYPED error:
	// the tool answered, with a code it chose, and the chain decides what
	// that code means to the caller — see toolplane's ToolRefusal.
	if code := reply.Header.Get(micro.ErrorCodeHeader); code != "" {
		return &transport.CodedError{
			Procedure: procedure,
			Code:      code,
			Message:   reply.Header.Get(micro.ErrorHeader),
		}
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
// # Two rounds, and why not one
//
// The obvious implementation publishes once to the plane-wide $SRV.INFO and
// collects whatever comes back. That is what this did, and it has a fairness
// bug on top of a capacity one. One request draws a reply from every instance
// of every service at once — services times replicas, a number this daemon
// cannot know in advance and which grows with every scale-out — and all of
// those replies then compete for one collection. An over-replicated service
// can crowd out a healthy one's reply, so a tool gets reported unreachable
// because something unrelated was scaled up. tool-go is moving to one micro
// instance per unit of concurrency, which multiplies the fan-in again.
//
// So: enumerate first, then ask each service on its own.
//
//  1. $SRV.PING plane-wide, to learn which services are running and how many
//     instances each has. PING rather than INFO because this round only needs
//     identity and liveness, and a Ping carries a name, an id, a version and
//     metadata where an Info carries every endpoint of every tool as well.
//     It is the cheapest question that answers "who is out there", and it is
//     the round that still has the whole plane answering at once.
//
//  2. $SRV.INFO.<name> per service, bounded by DiscoverConcurrency. This is
//     where the endpoint subjects and the advertised descriptor hash come
//     from, which reconciliation needs and PING does not carry. Each round's
//     reply count is one service's replica count — small, and now KNOWN,
//     because step 1 counted it.
//
// Incompleteness becomes per-service, which is the point: a reply lost for
// one service can no longer change the conclusion about its neighbour.
//
// # Addressing by name, and the naming convention it rests on
//
// $SRV.INFO.<name> addresses a micro service by the name it registered, and
// micro validates that name against ^[A-Za-z0-9\-_]+$ — no dots, so it is
// never the proto FQN. This function does not need to know the spelling: it
// asks the plane for the names in step 1 and uses whatever comes back. That
// is deliberate. Driving step 2 from the CATALOGUE's service names instead
// would be one fewer round trip and would silently discover nothing for any
// service whose author chose a name the catalogue cannot predict — see
// KNOWN-GAPS.md.
//
// # What an incomplete round is allowed to mean
//
// A round still reports what answered in time rather than what exists, and
// treating a slow instance as absent is still the safe direction for
// ROUTING. It is not a safe direction for the reconciler, which lifts
// quarantines on silence. So silence that this function knows to be
// suspicious is marked rather than passed off as a verdict: see
// [transport.Round].
func (t *Transport) Services(parent context.Context) (transport.Round, error) {
	wait := t.DiscoverWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	if deadline, ok := parent.Deadline(); ok {
		if d := time.Until(deadline); d < wait {
			wait = d
		}
	}
	// ONE ceiling for the whole call, shared by every round. Per-round
	// ceilings would multiply: a plane of forty services would take forty
	// windows in the worst case, and a bound that scales with the plane is
	// not a bound.
	ctx, cancel := context.WithTimeout(parent, wait)
	defer cancel()

	instances, enumErr, err := t.ping(ctx)
	if err != nil {
		return transport.Round{}, err
	}
	if err := parent.Err(); err != nil {
		// The CALLER went away. Distinguished from our own ceiling expiring,
		// which is an incomplete round rather than a failed call.
		return transport.Round{}, err
	}

	round := transport.Round{Enumeration: enumErr, Partial: map[string]error{}}

	names := make([]string, 0, len(instances))
	for name := range instances {
		names = append(names, name)
	}
	// Sorted so that which services a truncated round reaches is stable
	// across sweeps rather than a map's iteration order — an operator
	// chasing an intermittent verdict should not also be chasing a
	// different subset each time.
	sort.Strings(names)

	limit := t.DiscoverConcurrency
	if limit <= 0 {
		limit = 8
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, limit)
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			svcs, incomplete := t.info(ctx, name, instances[name])
			mu.Lock()
			defer mu.Unlock()
			round.Services = append(round.Services, svcs...)
			if incomplete != nil {
				round.Partial[name] = incomplete
			}
		}(name)
	}
	wg.Wait()

	if err := parent.Err(); err != nil {
		return transport.Round{}, err
	}
	sort.Slice(round.Services, func(i, j int) bool {
		if round.Services[i].Name != round.Services[j].Name {
			return round.Services[i].Name < round.Services[j].Name
		}
		return round.Services[i].Instance < round.Services[j].Instance
	})
	return round, nil
}

// ping enumerates the plane: which services are running, and the instance ids
// of each.
//
// The second return is the round's incompleteness, not a failure — it is
// non-nil when this round heard an unknown amount of the plane, and while it
// is set nothing downstream may reason from a service's absence. The third is
// a failure: the round could not be run at all.
func (t *Transport) ping(ctx context.Context) (map[string][]string, error, error) {
	subject, err := micro.ControlSubject(micro.PingVerb, "", "")
	if err != nil {
		return nil, nil, fmt.Errorf("building the discovery subject: %w", err)
	}

	instances := map[string][]string{}
	seen := map[string]bool{}
	_, incomplete, failed := t.collect(ctx, subject, func(data []byte) {
		var p micro.Ping
		if json.Unmarshal(data, &p) != nil {
			// One malformed reply is not a reason to report nothing: every
			// other service answered correctly.
			return
		}
		key := p.Name + "\x00" + p.ID
		if p.Name == "" || seen[key] {
			return
		}
		seen[key] = true
		instances[p.Name] = append(instances[p.Name], p.ID)
	})
	if failed != nil {
		return nil, nil, failed
	}
	if incomplete != nil {
		return instances, fmt.Errorf("%w: the plane-wide enumeration %v",
			transport.ErrIncompleteRound, incomplete), nil
	}
	return instances, nil, nil
}

// info asks one service for its endpoints and the contract it advertises.
//
// want is the instance ids PING reported for this service, and it is what
// makes completeness checkable rather than assumed: fewer instances than the
// enumeration counted means a reply went missing, whatever the transport
// thought of the round.
func (t *Transport) info(ctx context.Context, name string, want []string) ([]transport.Service, error) {
	subject, err := micro.ControlSubject(micro.InfoVerb, name, "")
	if err != nil {
		return nil, fmt.Errorf("%w: building the discovery subject for %s: %v",
			transport.ErrIncompleteRound, name, err)
	}

	var out []transport.Service
	seen := map[string]bool{}
	_, incomplete, failed := t.collect(ctx, subject, func(data []byte) {
		var info micro.Info
		if json.Unmarshal(data, &info) != nil {
			return
		}
		if seen[info.ID] {
			return
		}
		seen[info.ID] = true
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
	})
	switch {
	case failed != nil:
		// One service's round failing to run is this service's problem and
		// not the plane's: it is reported as a service that could not be
		// heard, which is what it is.
		return out, fmt.Errorf("%w: %s could not be asked: %v",
			transport.ErrIncompleteRound, name, failed)
	case incomplete != nil:
		return out, fmt.Errorf("%w: %s answered %d of %d instances and the round %v",
			transport.ErrIncompleteRound, name, len(out), len(want), incomplete)
	case len(out) < len(want):
		// MORE than expected is fine: an instance that started between the
		// two rounds is news, not a fault. Fewer is a reply this round did
		// not hear, and the instance it would have come from may be the one
		// running the wrong contract.
		return out, fmt.Errorf("%w: %s answered %d of the %d instances the enumeration counted",
			transport.ErrIncompleteRound, name, len(out), len(want))
	}
	return out, nil
}

// collect runs one scatter-gather and hands each reply's payload to fn.
//
// natsext.RequestMany is Synadia's — the NATS authors' own extension
// collection — and it is here to remove a bug class rather than to tidy one
// up. What this used to be was a ChanSubscribe into make(chan *nats.Msg, 64)
// with a select loop draining it. nats.go DISCARDS a message when a
// subscription's channel is full, increments a counter and tells the reader
// nothing, so the buffer was a correctness boundary: whether a round
// overflowed depended on goroutine scheduling, it failed more the more the
// plane scaled out, and a discarded reply became a tool reported unreachable.
// RequestMany returns an iterator, so replies are consumed as they arrive and
// there is no fixed buffer to overflow at all.
//
// It adds no transitive dependency: natsext v0.1.3 is one file and requires
// only github.com/nats-io/nats.go, which this adapter already links.
//
// The second return is the round's incompleteness. nats.go reports a slow
// consumer to a synchronous reader as nats.ErrSlowConsumer on the next
// receive, which the iterator surfaces as an error, so the drop that used to
// be silent is now the thing that marks the round. The ceiling expiring
// counts too — but only once a reply has arrived, because a round that heard
// NOTHING in its whole window cannot tell an empty plane from an unreachable
// one, and reporting every empty plane as incomplete would freeze the
// reconciler on a deployment that legitimately has nothing running. That
// remaining blind spot is in KNOWN-GAPS.md.
func (t *Transport) collect(ctx context.Context, subject string, fn func([]byte)) (int, error, error) {
	stall := t.DiscoverStall
	if stall <= 0 {
		stall = 100 * time.Millisecond
	}
	// RequestManyMaxMessages is deliberately NOT used, even for a round whose
	// instance count is known. It would stop at the expected count, so an
	// instance that started since the enumeration would be truncated away and
	// the round would look complete while being short a reply — the exact
	// failure this rewrite exists to end.
	replies, err := natsext.RequestMany(ctx, t.nc, subject, nil,
		natsext.RequestManyStall(stall))
	if err != nil {
		// The round could not be RUN — a closed connection, a bad subject.
		// Not an incomplete answer about the plane: no answer at all.
		return 0, nil, fmt.Errorf("asking %s: %w", subject, err)
	}

	heard := 0
	for msg, err := range replies {
		if errors.Is(err, nats.ErrNoResponders) {
			// Nothing is subscribed to that subject. A COMPLETE answer, not
			// a truncated one: the server said so rather than the window
			// running out, and a plane with nothing on it is a fact the
			// reconciler is entitled to act on. For a per-service round it
			// means the service stopped between the enumeration and now,
			// which the instance count below reports as unheard anyway.
			break
		}
		if err != nil {
			return heard, err, nil
		}
		heard++
		fn(msg.Data)
	}
	if heard > 0 && ctx.Err() != nil {
		return heard, fmt.Errorf("the collection window closed after %d replies: %w",
			heard, ctx.Err()), nil
	}
	return heard, nil, nil
}

// Watch is not implemented. Discovery is a poll today, and a watch that
// silently never fired would be worse than one that says so.
func (t *Transport) Watch(context.Context) (<-chan transport.Event, error) {
	return nil, errors.New("watch is not implemented; poll Services instead")
}
