package nats_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/garm-ai/garm/contracts/wire"
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

// infoReply subscribes a fake service to the discovery subject. Raw JSON
// rather than micro.AddService so that a test can also send a reply that is
// not valid JSON at all, which AddService cannot be made to do.
func infoReply(t *testing.T, nc *nats.Conn, payload []byte) {
	t.Helper()
	subject, err := micro.ControlSubject(micro.InfoVerb, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		_ = nc.Publish(m.Reply, payload)
	})
	if err != nil {
		t.Fatalf("subscribing a fake service to discovery: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
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
	infoReply(t, nc, infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{
			Name:     "t_v1_S",
			ID:       "instance-1",
			Version:  "1.2.3",
			Metadata: map[string]string{"garm.identity": "sha256:abc"},
		},
		Endpoints: []micro.EndpointInfo{{Name: "get", Subject: wire.Subject(procedure)}},
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 200 * time.Millisecond
	got, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
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
	infoReply(t, nc, []byte("this is not JSON"))
	infoReply(t, nc, infoJSON(t, micro.Info{
		ServiceIdentity: micro.ServiceIdentity{Name: "healthy", ID: "i2"},
		Endpoints:       []micro.EndpointInfo{{Subject: wire.Subject(procedure)}},
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := natstransport.New(nc)
	tr.DiscoverWait = 300 * time.Millisecond
	got, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(got) != 1 || got[0].Name != "healthy" {
		t.Fatalf("got %+v, want only the service that answered properly", got)
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
	got, err := tr.Services(ctx)
	if err != nil {
		t.Fatalf("Services with nothing running: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
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
