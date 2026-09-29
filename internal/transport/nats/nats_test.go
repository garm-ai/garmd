package nats_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/garm-ai/contracts/callctx"
	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/contracts/wire"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/garm-ai/garmd/internal/transport"
	natstransport "github.com/garm-ai/garmd/internal/transport/nats"
)

// Everything here runs against a real embedded NATS server rather than a
// mocked connection. What is under test is almost entirely how this adapter
// reads what NATS says — no-responders, micro's error headers, a $SRV.INFO
// scatter-gather — and a mock would be this file asserting its own opinion of
// those instead of the server's behaviour.
//
// The fake tool services are plain subscriptions. Importing garm-ai/tool-go
// would give a more faithful one and would also make the daemon depend on the
// tool runtime, which CI refuses: the whole architecture is that this side
// never builds against the other.

const procedure = "/t.v1.S/Get"

// connect starts a server on an ephemeral port and returns a connection to it.
//
// Port: -1 because 4222 is usually already taken by whatever the developer is
// running, and a test suite that fails on a busy laptop gets disabled.
func connect(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatalf("starting the embedded server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatal("the embedded server never became ready")
	}
	t.Cleanup(srv.Shutdown)

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("connecting to the embedded server: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// serveTool subscribes a fake service on the subject the adapter will publish
// to, deriving that subject the same way the adapter does. Spelling it out
// here would make the test pass even if both sides stopped agreeing.
func serveTool(t *testing.T, nc *nats.Conn, reply func(*nats.Msg) *nats.Msg) {
	t.Helper()
	sub, err := nc.Subscribe(wire.Subject(procedure), func(m *nats.Msg) {
		if out := reply(m); out != nil {
			out.Subject = m.Reply
			_ = nc.PublishMsg(out)
		}
	})
	if err != nil {
		t.Fatalf("subscribing the fake service: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatalf("flushing the subscription: %v", err)
	}
}

func marshalled(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshalling a fixture: %v", err)
	}
	return b
}

func TestAReplyIsUnmarshalledIntoTheCallersResponse(t *testing.T) {
	nc := connect(t)
	serveTool(t, nc, func(m *nats.Msg) *nats.Msg {
		var in wrapperspb.StringValue
		if err := proto.Unmarshal(m.Data, &in); err != nil {
			t.Errorf("the request did not arrive as its declared type: %v", err)
		}
		if in.GetValue() != "ping" {
			t.Errorf("the service received %q, want ping", in.GetValue())
		}
		return &nats.Msg{Data: marshalled(t, wrapperspb.String("pong"))}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var out wrapperspb.StringValue
	if err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"), &out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if out.GetValue() != "pong" {
		t.Errorf("response = %q, want pong", out.GetValue())
	}
}

// TestAnUnreachableToolIsNotReportedAsAFailure is the distinction that decides
// who gets paged. Nothing is listening, which means the catalogue declares a
// tool no service implements — an operator's problem. Reported as a tool
// failure it sends someone to read handler code that is working fine.
func TestAnUnreachableToolIsNotReportedAsAFailure(t *testing.T) {
	nc := connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"),
		&wrapperspb.StringValue{})
	if !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("Invoke on a subject nothing serves = %v, want %v",
			err, transport.ErrUnreachable)
	}
	// The procedure has to be in the message: an operator reading this needs
	// to know WHICH declared tool has nothing behind it.
	if !contains(err.Error(), procedure) {
		t.Errorf("the error does not name the tool: %v", err)
	}
}

// A micro handler reports failure in headers, not in the body — and it may
// still send a perfectly well-formed body alongside. Trusting the body would
// turn every handler error into a successful call returning a zero value.
func TestAnErrorHeaderIsAnErrorHoweverWellFormedTheBody(t *testing.T) {
	nc := connect(t)
	serveTool(t, nc, func(*nats.Msg) *nats.Msg {
		m := nats.NewMsg("")
		m.Header.Set(micro.ErrorCodeHeader, "500")
		m.Header.Set(micro.ErrorHeader, "the account does not exist")
		m.Data = marshalled(t, wrapperspb.String("pong"))
		return m
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var out wrapperspb.StringValue
	err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"), &out)
	if err == nil {
		t.Fatal("a reply carrying a micro error header was reported as a success")
	}
	if errors.Is(err, transport.ErrUnreachable) {
		t.Error("a handler that ran and failed was reported as unreachable")
	}
	for _, want := range []string{"500", "the account does not exist"} {
		if !contains(err.Error(), want) {
			t.Errorf("the error omits %q, which is what the handler said: %v", want, err)
		}
	}
	// Typed, so the chain can tell a tool's answer from a broken hop: the
	// code and the message as the tool put them on the headers.
	var coded *transport.CodedError
	if !errors.As(err, &coded) {
		t.Fatalf("a micro error is not a transport.CodedError: %T %v", err, err)
	}
	if coded.Code != "500" || coded.Message != "the account does not exist" {
		t.Errorf("coded = %+v, want code 500 and the handler's message", coded)
	}
	if out.GetValue() != "" {
		t.Error("the body of a failed reply was unmarshalled into the response")
	}
}

// The response type came from this process's catalogue, so a reply that does
// not fit it means the service implements a different contract — not a
// generic transport failure. Saying so is the difference between checking a
// deployment's version and restarting NATS.
//
// Note how little reaches this branch: protobuf accepts a renumbered or
// retyped field without a word, which is exactly why the reconciler exists.
// Only a reply that is not a message at all fails here.
func TestAReplyThatDoesNotFitSaysTheServiceImplementsADifferentContract(t *testing.T) {
	nc := connect(t)
	serveTool(t, nc, func(*nats.Msg) *nats.Msg {
		// Field 1, length-delimited, declaring five bytes and carrying one.
		return &nats.Msg{Data: []byte{0x0a, 0x05, 'a'}}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"),
		&wrapperspb.StringValue{})
	if err == nil {
		t.Fatal("a reply that does not unmarshal was reported as a success")
	}
	if !contains(err.Error(), "declared response") {
		t.Errorf("the error does not say the contract differs, so nobody will check "+
			"the service's version: %v", err)
	}
}

// TestTheDeadlineComesFromTheCallersContext: a transport imposing its own
// would silently cap a caller's, and a call that reports a timeout the caller
// did not ask for is a call whose effect is unknown.
func TestTheDeadlineComesFromTheCallersContext(t *testing.T) {
	nc := connect(t)
	// Subscribed but never answering, so the only thing that can end this
	// call is the caller's deadline. Without a subscriber it would end as
	// no-responders instead and prove nothing.
	serveTool(t, nc, func(*nats.Msg) *nats.Msg { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"),
		&wrapperspb.StringValue{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a call nobody answered returned successfully")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a call that outlived its context reported %v, not the deadline", err)
	}
	if elapsed > 2*time.Second {
		// nats.go's own default request timeout is two seconds. Waiting that
		// long means the adapter is using it rather than the caller's.
		t.Errorf("the call took %v, so the deadline did not come from the context", elapsed)
	}
}

// fakeService answers discovery the way a micro service does: $SRV.PING
// plane-wide, so the enumeration finds it, and $SRV.INFO.<name> for itself.
//
// Raw JSON rather than micro.AddService so that a test can also send a reply
// that is not valid JSON at all, which AddService cannot be made to do — and
// so that a test can leave one of the two verbs UNANSWERED, which is how the
// incomplete-round rule is exercised without having to provoke a real drop.
//
// answerInfo false makes an instance that the enumeration counts and the
// per-service round never hears from: the shape of a lost reply, produced on
// purpose.
func fakeService(t *testing.T, nc *nats.Conn, name, id string, info []byte, answerInfo bool) {
	t.Helper()
	subscribe := func(subject string, payload []byte) {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			_ = nc.Publish(m.Reply, payload)
		})
		if err != nil {
			t.Fatalf("subscribing a fake service to %s: %v", subject, err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}

	ping, err := micro.ControlSubject(micro.PingVerb, "", "")
	if err != nil {
		t.Fatal(err)
	}
	subscribe(ping, pingJSON(t, name, id))

	if answerInfo {
		byName, err := micro.ControlSubject(micro.InfoVerb, name, "")
		if err != nil {
			t.Fatal(err)
		}
		subscribe(byName, info)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func pingJSON(t *testing.T, name, id string) []byte {
	t.Helper()
	b, err := json.Marshal(micro.Ping{
		ServiceIdentity: micro.ServiceIdentity{Name: name, ID: id, Version: "1.0.0"},
		Type:            micro.PingResponseType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func infoJSON(t *testing.T, info micro.Info) []byte {
	t.Helper()
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServicesReportsWhatEachInstanceSaysAboutItself(t *testing.T) {
	nc := connect(t)
	fakeService(t, nc, "t_v1_S", "instance-1", infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{
			Name:     "t_v1_S",
			ID:       "instance-1",
			Version:  "1.2.3",
			Metadata: map[string]string{"garm.identity": "sha256:abc"},
		},
		Endpoints: []micro.EndpointInfo{{Name: "get", Subject: wire.Subject(procedure)}},
	}), true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 2 * time.Second
	round, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if !round.ConcludesAbsence() || !round.Complete("t_v1_S") {
		t.Fatalf("a round that heard everything reported itself incomplete: %+v", round)
	}
	got := round.Services
	if len(got) != 1 {
		t.Fatalf("got %d services, want 1: %+v", len(got), got)
	}
	want := transport.Service{
		Name:     "t_v1_S",
		Instance: "instance-1",
		Version:  "1.2.3",
		// Opaque to garmd and read from this one metadata key. Reconciliation
		// compares it against what the catalogue pins, so a discoverer that
		// dropped it would silently disable the drift check.
		Identity: "sha256:abc",
		Subjects: []string{wire.Subject(procedure)},
	}
	if got[0].Name != want.Name || got[0].Instance != want.Instance ||
		got[0].Version != want.Version || got[0].Identity != want.Identity {
		t.Errorf("service = %+v, want %+v", got[0], want)
	}
	if len(got[0].Subjects) != 1 || got[0].Subjects[0] != want.Subjects[0] {
		t.Errorf("subjects = %v, want %v", got[0].Subjects, want.Subjects)
	}
}

// One instance answering with rubbish is not a reason to report that nothing
// is running: every other service answered correctly, and discarding their
// replies would quarantine tools that are perfectly healthy.
func TestOneMalformedDiscoveryReplyDoesNotHideTheRest(t *testing.T) {
	nc := connect(t)
	fakeService(t, nc, "rubbish", "i1", []byte("this is not JSON"), true)
	fakeService(t, nc, "healthy", "i2", infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{Name: "healthy", ID: "i2"},
		Endpoints:       []micro.EndpointInfo{{Subject: wire.Subject(procedure)}},
	}), true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	round, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	got := round.Services
	if len(got) != 1 || got[0].Name != "healthy" {
		t.Fatalf("got %+v, want only the service that answered properly", got)
	}
	// And the one that answered rubbish is reported as a service that was
	// not heard, rather than quietly forgotten: it answered the enumeration,
	// so something IS running under that name, and a round that cannot say
	// what must not let a caller conclude it is gone.
	if round.Complete("rubbish") {
		t.Error("a service whose reply could not be read was reported as heard in full")
	}
	if !errors.Is(round.Partial["rubbish"], transport.ErrIncompleteRound) {
		t.Errorf("Partial[rubbish] = %v, want an ErrIncompleteRound", round.Partial["rubbish"])
	}
}

// Nothing running is an empty list and no error. An error would make an
// operator look for a broken transport when the answer is that nothing is
// deployed.
func TestDiscoveringNothingIsNotAnError(t *testing.T) {
	nc := connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 100 * time.Millisecond
	round, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services with nothing running: %v", err)
	}
	if len(round.Services) != 0 {
		t.Errorf("got %+v, want nothing", round.Services)
	}
	// And it is a VERDICT, not a shrug: an empty plane that answered its
	// whole window is evidence about what is not running, which is what lets
	// the reconciler clear a stale quarantine. The blind spot this leaves —
	// a plane that is merely unreachable looks identical — is in
	// KNOWN-GAPS.md.
	if !round.ConcludesAbsence() {
		t.Error("an empty plane was reported as a round that heard too little to judge")
	}
}

// The collection window is capped by the caller's deadline, so a sweep run
// under a tight context returns when the caller asked rather than when the
// transport's own window elapses.
func TestDiscoveryDoesNotOutlastTheCallersDeadline(t *testing.T) {
	nc := connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 30 * time.Second
	start := time.Now()
	if _, err := tr.Services(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Services: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("discovery took %v; the caller's deadline did not shorten the window", elapsed)
	}
}

// A cancelled sweep reports the cancellation rather than an empty result. The
// reconciler distinguishes them: an empty result is a verdict, an error
// leaves the previous one standing.
func TestACancelledDiscoveryReportsTheCancellation(t *testing.T) {
	nc := connect(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 30 * time.Second
	if _, err := tr.Services(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Services on a cancelled context = %v, want context.Canceled", err)
	}
}

func TestDiscoveryOnAClosedConnectionIsAnError(t *testing.T) {
	nc := connect(t)
	nc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := natstransport.New(nc).Services(ctx); err == nil {
		t.Error("discovery over a closed connection reported success")
	}
}

// TestWatchSaysItIsNotImplemented: discovery is a poll today, and a watch that
// silently never fired would leave a caller believing it was subscribed to
// changes that will never arrive.
func TestWatchSaysItIsNotImplemented(t *testing.T) {
	nc := connect(t)

	ch, err := natstransport.New(nc).Watch(context.Background())
	if err == nil {
		t.Fatal("Watch reported success for something that does not watch anything")
	}
	if ch != nil {
		t.Error("Watch returned a channel nothing will ever send on")
	}
	if !contains(err.Error(), "not implemented") {
		t.Errorf("the error does not say it is unimplemented: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// What crosses the hop beside the request.
//
// A fake service decodes the header the way tool-go does, so this asserts the
// bytes on the wire rather than this package's opinion of them. Assertions,
// never credentials: the caller's token does not appear here in any form.
func TestTheInvocationContextCrossesTheHopOnItsHeader(t *testing.T) {
	nc := connect(t)

	// Built before subscribing: the reply function runs on nats.go's own
	// goroutine, where a t.Fatalf would be a test-framework misuse rather
	// than a failure anybody can read.
	reply := marshalled(t, wrapperspb.String("pong"))
	got := make(chan *toolv1.InvocationContext, 1)
	bad := make(chan error, 1)
	serveTool(t, nc, func(m *nats.Msg) *nats.Msg {
		ic, err := callctx.Decode(m.Header.Get(callctx.Header))
		if err != nil {
			bad <- err
		} else {
			got <- ic
		}
		return &nats.Msg{Data: reply}
	})

	deadline := time.Now().Add(9 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	ctx = callctx.NewContext(ctx, &toolv1.InvocationContext{
		CallId: "ev-1",
		Attribution: &toolv1.CallContext{
			Tenant:        "acme",
			CorrelationId: "corr-1",
		},
		Principal: &toolv1.InvocationPrincipal{
			Subject: "employee:jdoe",
			Kind:    toolv1.PrincipalKind_PRINCIPAL_KIND_USER,
		},
		Act: []*toolv1.Act{{
			Subject: "agent:support-assistant",
			Kind:    toolv1.PrincipalKind_PRINCIPAL_KIND_AGENT,
		}},
	})

	var out wrapperspb.StringValue
	if err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"), &out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	select {
	case err := <-bad:
		t.Fatalf("the service could not decode the header: %v", err)
	case ic := <-got:
		if ic.GetCallId() != "ev-1" {
			t.Errorf("call_id = %q, want ev-1: the ledger row and the hop must "+
				"carry the same id or they cannot be joined", ic.GetCallId())
		}
		if ic.GetPrincipal().GetSubject() != "employee:jdoe" {
			t.Errorf("subject = %q, want employee:jdoe", ic.GetPrincipal().GetSubject())
		}
		if ic.GetPrincipal().GetKind() != toolv1.PrincipalKind_PRINCIPAL_KIND_USER {
			t.Errorf("kind = %v, want USER", ic.GetPrincipal().GetKind())
		}
		if len(ic.GetAct()) != 1 || ic.GetAct()[0].GetSubject() != "agent:support-assistant" {
			t.Errorf("act = %v; a delegated call reached the service looking direct, "+
				"and whatever exchanges on it would mint for the wrong chain", ic.GetAct())
		}
		if ic.GetAttribution().GetTenant() != "acme" {
			t.Errorf("tenant = %q, want acme", ic.GetAttribution().GetTenant())
		}
		if d := ic.GetDeadline(); d == nil {
			t.Error("no deadline on the hop; a relative one would restart here and a " +
				"chain of hops would outlive what the caller allowed")
		} else if diff := d.AsTime().Sub(deadline); diff > time.Second || diff < -time.Second {
			t.Errorf("deadline = %s, want %s", d.AsTime(), deadline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the service was called but reported no header")
	}
}

// A caller with no context on ctx is an in-process one — a test, a direct
// probe — and the header still has to be well formed, because the other side
// refuses a request without one. A minted call_id is honest about what it is:
// this hop's identifier, and no claim about a principal.
func TestAHopWithNoUpstreamContextStillCarriesAUsableHeader(t *testing.T) {
	nc := connect(t)

	reply := marshalled(t, wrapperspb.String("pong"))
	got := make(chan string, 1)
	serveTool(t, nc, func(m *nats.Msg) *nats.Msg {
		got <- m.Header.Get(callctx.Header)
		return &nats.Msg{Data: reply}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var out wrapperspb.StringValue
	if err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"), &out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	raw := <-got
	if raw == "" {
		t.Fatal("no Garm-Invocation header; the far side refuses a request without one")
	}
	ic, err := callctx.Decode(raw)
	if err != nil {
		t.Fatalf("the header does not decode: %v", err)
	}
	if ic.GetCallId() == "" {
		t.Error("call_id is empty, which callctx.Decode refuses by design")
	}
	if ic.GetPrincipal().GetSubject() != "" {
		t.Errorf("subject = %q was invented for a call that asserted nobody",
			ic.GetPrincipal().GetSubject())
	}
}

// The context on ctx is shared with every hop this call makes. Mutating it
// would let two resolvers collide on one call_id, so each hop clones.
func TestTheHopDoesNotMutateTheContextItWasGiven(t *testing.T) {
	nc := connect(t)

	reply := marshalled(t, wrapperspb.String("pong"))
	serveTool(t, nc, func(*nats.Msg) *nats.Msg { return &nats.Msg{Data: reply} })

	upstream := &toolv1.InvocationContext{
		CallId:    "ev-1",
		Principal: &toolv1.InvocationPrincipal{Subject: "employee:jdoe"},
	}
	ctx, cancel := context.WithTimeout(callctx.NewContext(context.Background(), upstream),
		5*time.Second)
	defer cancel()

	var out wrapperspb.StringValue
	if err := natstransport.New(nc).Invoke(ctx, procedure, wrapperspb.String("ping"), &out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if upstream.GetDeadline() != nil {
		t.Error("the hop wrote its own deadline into the context the chain owns")
	}
}

// ---------------------------------------------------------------------------
// The shape that broke discovery: many instances answering one round.
// ---------------------------------------------------------------------------

// A plane that has scaled out is discovered whole.
//
// This is the regression test for a fixed buffer. Discovery used to collect
// replies through a ChanSubscribe into make(chan *nats.Msg, 64), and nats.go
// DISCARDS a message when that channel is full rather than blocking — it
// increments a counter, marks the subscription a slow consumer and tells the
// reader nothing. Because the reader drained in a select loop, 64 was a burst
// limit rather than a total, so whether a round overflowed came down to
// goroutine scheduling: intermittent, and more likely the larger the plane,
// which is exactly backwards. A discarded reply became a service reported
// absent, and an absent service becomes "declared but no service is serving
// it" at the door.
//
// Two hundred instances, well past that buffer, arriving as one burst. The
// assertion is not "most of them": it is all of them, and a round that says
// so.
func TestAPlaneThatHasScaledOutIsDiscoveredWhole(t *testing.T) {
	nc := connect(t)

	const (
		services         = 8
		replicasEach     = 25
		total            = services * replicasEach
		theOldBufferSize = 64
	)
	if total <= theOldBufferSize {
		t.Fatalf("this test is pointless below the old buffer of %d", theOldBufferSize)
	}

	for s := range services {
		name := fmt.Sprintf("svc_%d", s)
		for r := range replicasEach {
			id := fmt.Sprintf("%s-instance-%d", name, r)
			fakeService(t, nc, name, id, infoJSON(t, micro.Info{
				ServiceIdentity: micro.ServiceIdentity{
					Name: name, ID: id, Version: "1.0.0",
					Metadata: map[string]string{"garm.identity": "sha256:" + name},
				},
				Endpoints: []micro.EndpointInfo{{Subject: name + ".Get"}},
			}), true)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	round, err := natstransport.New(nc).Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(round.Services) != total {
		t.Errorf("discovery heard %d of %d instances; a reply was lost",
			len(round.Services), total)
	}
	if !round.ConcludesAbsence() {
		t.Errorf("the enumeration was reported incomplete: %v", round.Enumeration)
	}
	if len(round.Partial) != 0 {
		t.Errorf("services reported as heard only in part: %v", round.Partial)
	}
}

// A service heard in the enumeration but not in its own round is NOT absent.
//
// This is the rule the whole redesign exists for. Discovery reports what
// answered in time, so silence is ambiguous: a service that did not answer
// may be stopped, or may simply not have been heard. Those are different
// facts and a caller has to be able to tell them apart, because one of them
// licenses lifting a quarantine and the other does not.
//
// The instance here answers the plane-wide enumeration and never answers its
// own $SRV.INFO — the shape of a lost reply, produced deterministically
// rather than by trying to provoke a real drop.
func TestAServiceHeardOnlyInPartIsNotReportedAbsent(t *testing.T) {
	nc := connect(t)

	answering := infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{Name: "loud", ID: "loud-1"},
		Endpoints:       []micro.EndpointInfo{{Subject: wire.Subject(procedure)}},
	})
	fakeService(t, nc, "loud", "loud-1", answering, true)
	fakeService(t, nc, "quiet", "quiet-1", nil, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = time.Second
	round, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}

	// The silent one contributes no Service — there is nothing to report
	// about an instance that said nothing.
	for _, svc := range round.Services {
		if svc.Name == "quiet" {
			t.Fatalf("the silent service produced a Service record: %+v", svc)
		}
	}
	// But the round says it could not hear it, which is the whole point: a
	// caller reading Services alone would conclude "quiet" is gone.
	if round.Complete("quiet") {
		t.Error("a service that never answered its own round was reported as heard in full")
	}
	if !errors.Is(round.Partial["quiet"], transport.ErrIncompleteRound) {
		t.Errorf("Partial[quiet] = %v, want an ErrIncompleteRound", round.Partial["quiet"])
	}
	// And one service going unheard says nothing about its neighbour. This
	// is what per-service rounds buy: under a single plane-wide collection,
	// a noisy service could crowd out a quiet one's reply and the two were
	// indistinguishable.
	if !round.Complete("loud") {
		t.Errorf("a healthy service was tainted by its neighbour: %v", round.Partial["loud"])
	}
}

// A round stops when the replies stop, rather than always paying the ceiling.
//
// The old collection had one termination condition — the window — so every
// reconciliation sweep waited it out even when the whole plane had answered
// in three milliseconds. The stall timer makes the common case cost what the
// plane costs.
func TestAQuietPlaneEndsTheRoundEarly(t *testing.T) {
	nc := connect(t)
	fakeService(t, nc, "prompt", "i1", infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{Name: "prompt", ID: "i1"},
		Endpoints:       []micro.EndpointInfo{{Subject: wire.Subject(procedure)}},
	}), true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	// A ceiling nobody should wait for.
	tr.DiscoverWait = 10 * time.Second
	tr.DiscoverStall = 50 * time.Millisecond

	start := time.Now()
	round, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(round.Services) != 1 {
		t.Fatalf("got %+v, want the one service", round.Services)
	}
	// Generous — two rounds of stall plus scheduling — and still two orders
	// of magnitude under the ceiling, which is the property under test.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the round took %v; it waited out the ceiling rather than the stall", elapsed)
	}
}
