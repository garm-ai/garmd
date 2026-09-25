package jetstream_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	ledgerv1 "github.com/garm-ai/garm/contracts/garm/ledger/v1"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/contracts/wire"
	auditjs "github.com/garm-ai/garmd/internal/audit/jetstream"
)

// Everything that can run against a real broker does. What is under test is
// what JetStream actually does with an ack, a duplicate id and a full
// DiscardNew stream — and a mock would be this file asserting its own opinion
// of those rather than the server's behaviour.
//
// Nothing here skips. A test that skips when the broker is missing reports ok
// while covering nothing, which for these properties is worse than no test.

// serverWithJetStream starts an embedded broker on an ephemeral port.
//
// Port: -1 because 4222 is usually taken by whatever the developer is running,
// and a suite that fails on a busy laptop gets disabled.
func serverWithJetStream(t *testing.T) *natsserver.Server {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	})
	if err != nil {
		t.Fatalf("starting the embedded server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("the embedded server never became ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv
}

func connect(t *testing.T, srv *natsserver.Server) natsjs.JetStream {
	t.Helper()
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("connecting to the embedded server: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := natsjs.New(nc)
	if err != nil {
		t.Fatalf("building a JetStream context: %v", err)
	}
	return js
}

// auditStream creates the stream the way a correct deployment would, so a
// test asserting a publish is not also asserting a configuration.
func auditStream(t *testing.T, js natsjs.JetStream, mutate func(*natsjs.StreamConfig)) natsjs.Stream {
	t.Helper()
	cfg := natsjs.StreamConfig{
		Name:       wire.AuditStream,
		Subjects:   []string{wire.AuditSubject + ".>"},
		Discard:    natsjs.DiscardNew,
		Storage:    natsjs.FileStorage,
		Duplicates: time.Minute,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := js.CreateOrUpdateStream(context.Background(), cfg)
	if err != nil {
		t.Fatalf("creating the audit stream: %v", err)
	}
	return s
}

func event(id string, outcome ledger.Outcome) ledger.Event {
	return ledger.Event{
		ID:      id,
		Time:    time.Now(),
		Tenant:  "acme",
		App:     "payments",
		Tool:    "/pay.v1.Payments/Transfer",
		Outcome: outcome,
	}
}

func sinkOn(t *testing.T, js auditjs.Publisher, opts ...func(*auditjs.Config)) *auditjs.Sink {
	t.Helper()
	cfg := auditjs.Config{JS: js, Retention: 30 * 24 * time.Hour}
	for _, o := range opts {
		o(&cfg)
	}
	s, err := auditjs.New(cfg)
	if err != nil {
		t.Fatalf("building the sink: %v", err)
	}
	return s
}

func msgs(t *testing.T, s natsjs.Stream) uint64 {
	t.Helper()
	info, err := s.Info(context.Background())
	if err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	return info.State.Msgs
}

// The guarantee this package exists for: one call, one message, and the write
// is over when the server says so.
//
// Three writes must leave three messages. A sink that buffered them into one
// would still pass every "the record was written" assertion phrased as "the
// data is in the stream eventually" — so this counts, and the count is the
// test.
func TestEachWriteIsItsOwnMessageAndNeverABatch(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	stream := auditStream(t, js, nil)
	sink := sinkOn(t, js)

	ids := []string{"aaaa", "bbbb", "cccc"}
	for _, id := range ids {
		if err := sink.Write(context.Background(), event(id, ledger.OutcomeIntent)); err != nil {
			t.Fatalf("Write(%s): %v", id, err)
		}
		// Before the next write, so the count cannot be satisfied by a flush
		// that happens to arrive later. Each write must have landed already.
		if got := msgs(t, stream); got == 0 {
			t.Fatalf("after writing %s the stream holds nothing; the write returned "+
				"before the record was durable", id)
		}
	}

	if got := msgs(t, stream); got != uint64(len(ids)) {
		t.Fatalf("the stream holds %d message(s) for %d write(s); the audit sink batched, "+
			"and a write-ahead still sitting in a buffer is a write-ahead that never "+
			"happened", got, len(ids))
	}

	for i, want := range ids {
		raw, err := stream.GetMsg(context.Background(), uint64(i+1))
		if err != nil {
			t.Fatalf("reading message %d: %v", i+1, err)
		}
		var ev ledgerv1.Event
		if err := proto.Unmarshal(raw.Data, &ev); err != nil {
			t.Fatalf("message %d does not parse as one Event: %v", i+1, err)
		}
		if ev.GetEventId() != want {
			t.Errorf("message %d carries event id %q, want %q", i+1, ev.GetEventId(), want)
		}
	}
}

// A write that the server will not accept must return an error, because that
// error is what refuses a fail_closed call.
//
// The stream is full and discards new, which is the configuration the audit
// stream is required to have: full means refuse.
func TestAWriteTheServerRefusesReturnsAnError(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, func(c *natsjs.StreamConfig) { c.MaxMsgs = 1 })
	sink := sinkOn(t, js)

	if err := sink.Write(context.Background(), event("first", ledger.OutcomeIntent)); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	err := sink.Write(context.Background(), event("second", ledger.OutcomeIntent))
	if err == nil {
		t.Fatal("a write into a full DiscardNew stream reported success; a fail_closed " +
			"tool would run with no record of it")
	}
}

// With no broker there is no ack, and no ack must read as a failure rather
// than as something in flight.
func TestAWriteFailsWhenTheBrokerIsGone(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, nil)
	sink := sinkOn(t, js, func(c *auditjs.Config) { c.Timeout = 500 * time.Millisecond })
	srv.Shutdown()

	if err := sink.Write(context.Background(), event("orphan", ledger.OutcomeIntent)); err == nil {
		t.Fatal("writing to a dead broker reported success")
	}
}

// A retried publish of the same record must not become a second row. The
// server dedupes on Nats-Msg-Id, which only works if the sink sets it.
func TestARetriedWriteIsDedupedByTheServer(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	stream := auditStream(t, js, nil)
	sink := sinkOn(t, js)

	ev := event("stable-id", ledger.OutcomeIntent)
	for i := 0; i < 3; i++ {
		if err := sink.Write(context.Background(), ev); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := msgs(t, stream); got != 1 {
		t.Fatalf("the stream holds %d copies of one record; the msg id is not being set, "+
			"so a retry duplicates the row", got)
	}
}

// One call writes TWICE with one event id — the intent before the tool runs
// and the outcome after. Both must be stored.
//
// Keying dedupe on the event id alone makes the outcome an exact duplicate of
// the intent: the server acks it and stores nothing, and every audited call is
// permanently recorded as started and never finished, with no error anywhere.
func TestTheIntentAndTheOutcomeOfOneCallAreBothStored(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	stream := auditStream(t, js, nil)
	sink := sinkOn(t, js)

	const id = "one-call"
	if err := sink.Write(context.Background(), event(id, ledger.OutcomeIntent)); err != nil {
		t.Fatalf("the intent write: %v", err)
	}
	if err := sink.Write(context.Background(), event(id, ledger.OutcomeOK)); err != nil {
		t.Fatalf("the outcome write: %v", err)
	}

	if got := msgs(t, stream); got != 2 {
		t.Fatalf("the stream holds %d message(s) for one call's intent and outcome; the "+
			"outcome was deduped away against its own intent", got)
	}
}

// The record lands where a consumer filtering to one tenant will look for it.
func TestTheRecordLandsUnderItsTenantAndApp(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	stream := auditStream(t, js, nil)
	sink := sinkOn(t, js)

	if err := sink.Write(context.Background(), event("placed", ledger.OutcomeIntent)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := stream.GetMsg(context.Background(), 1)
	if err != nil {
		t.Fatalf("reading the message: %v", err)
	}
	if want := wire.AuditSubjectFor("acme", "payments"); raw.Subject != want {
		t.Errorf("subject = %q, want %q", raw.Subject, want)
	}
}

// blockingPublisher never answers, which is what an unreachable broker looks
// like from inside a publish.
type blockingPublisher struct {
	calls   atomic.Int64
	release chan struct{}
}

func (p *blockingPublisher) Publish(ctx context.Context, _ string, _ []byte, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	p.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.release:
		return &natsjs.PubAck{}, nil
	}
}

// A publish that waits forever holds the request path open for as long as
// JetStream is unreachable. For a fail_closed tool that is an outage shaped
// like a hang, and a hang is the one failure an operator cannot triage.
func TestAWriteIsBoundedByItsTimeout(t *testing.T) {
	p := &blockingPublisher{release: make(chan struct{})}
	defer close(p.release)
	sink := sinkOn(t, p, func(c *auditjs.Config) { c.Timeout = 100 * time.Millisecond })

	start := time.Now()
	err := sink.Write(context.Background(), event("slow", ledger.OutcomeIntent))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a publish that never got an ack reported success")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Write took %s against a 100ms timeout; it is not bounded", elapsed)
	}
}

// The caller's own deadline still applies. A sink timeout longer than the
// request's would outlive the call it is recording.
func TestTheCallersDeadlineStillBoundsAWrite(t *testing.T) {
	p := &blockingPublisher{release: make(chan struct{})}
	defer close(p.release)
	sink := sinkOn(t, p, func(c *auditjs.Config) { c.Timeout = time.Hour })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := sink.Write(ctx, event("slow", ledger.OutcomeIntent)); err == nil {
		t.Fatal("a write outlived the caller's deadline and reported success")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Write took %s; the caller's deadline was ignored", elapsed)
	}
}

// Retention is what the operator declared, and the mount check compares a
// tool's retain_days against exactly this number.
func TestRetentionIsWhatTheOperatorDeclared(t *testing.T) {
	sink := sinkOn(t, &blockingPublisher{release: make(chan struct{})},
		func(c *auditjs.Config) { c.Retention = 2555 * 24 * time.Hour })
	if got, want := sink.Retention(), 2555*24*time.Hour; got != want {
		t.Errorf("Retention() = %s, want %s", got, want)
	}
}

func TestASinkWithoutAPublisherIsRefused(t *testing.T) {
	if _, err := auditjs.New(auditjs.Config{}); err == nil {
		t.Fatal("a sink was built with no publisher")
	}
}

// --- the startup assertions -------------------------------------------------

func logTo(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// DiscardOld is JetStream's DEFAULT, and under it a full stream drops the
// oldest records while every publish goes on returning a successful ack. A
// fail_closed tool would keep running against records that are quietly
// evaporating, which is the exact shape of protection that is not there.
func TestAnAuditStreamThatDiscardsOldIsRefusedAtStartup(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, func(c *natsjs.StreamConfig) { c.Discard = natsjs.DiscardOld })

	err := auditjs.AssertStream(context.Background(), js, logTo(&bytes.Buffer{}))
	if err == nil {
		t.Fatal("a DiscardOld audit stream was accepted; records would vanish while " +
			"every publish still acked")
	}
	if !strings.Contains(err.Error(), "discard") {
		t.Errorf("the refusal does not name the discard policy: %v", err)
	}
}

func TestAnAuditStreamThatDiscardsNewIsAccepted(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, func(c *natsjs.StreamConfig) { c.Replicas = 1 })

	if err := auditjs.AssertStream(context.Background(), js, logTo(&bytes.Buffer{})); err != nil {
		t.Fatalf("a correctly configured audit stream was refused: %v", err)
	}
}

// An ack from memory says the record survived as far as the next restart.
func TestAnInMemoryAuditStreamIsRefusedAtStartup(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, func(c *natsjs.StreamConfig) { c.Storage = natsjs.MemoryStorage })

	err := auditjs.AssertStream(context.Background(), js, logTo(&bytes.Buffer{}))
	if err == nil {
		t.Fatal("an in-memory audit stream was accepted")
	}
	if !strings.Contains(err.Error(), "file storage") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
}

// A single-node stream is a real risk and a legitimate dev setup, so it warns
// rather than refusing. Refusing would get the check turned off.
func TestASingleReplicaAuditStreamWarnsButStarts(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)
	auditStream(t, js, func(c *natsjs.StreamConfig) { c.Replicas = 1 })

	var buf bytes.Buffer
	if err := auditjs.AssertStream(context.Background(), js, logTo(&buf)); err != nil {
		t.Fatalf("a single-replica stream was refused: %v", err)
	}
	if !strings.Contains(buf.String(), "replicat") {
		t.Errorf("nothing was logged about replication:\n%s", buf.String())
	}
}

// Publishing to a subject no stream captures fails on every call, which is
// the safe direction — so a missing stream is a warning, not a refusal.
func TestAMissingAuditStreamIsNotAStartupFailure(t *testing.T) {
	srv := serverWithJetStream(t)
	js := connect(t, srv)

	var buf bytes.Buffer
	if err := auditjs.AssertStream(context.Background(), js, logTo(&buf)); err != nil {
		t.Fatalf("a missing audit stream stopped startup: %v", err)
	}
	if !strings.Contains(buf.String(), wire.AuditStream) {
		t.Errorf("nothing was logged about the missing stream:\n%s", buf.String())
	}
}

// brokenLookup stands in for a broker that answers the lookup with something
// other than a stream, which must stop startup rather than be read as absent.
type brokenLookup struct{}

func (brokenLookup) Stream(context.Context, string) (natsjs.Stream, error) {
	return nil, errors.New("the JetStream API did not answer")
}

func TestAnUnreadableAuditStreamStopsStartup(t *testing.T) {
	if err := auditjs.AssertStream(context.Background(), brokenLookup{}, nil); err == nil {
		t.Fatal("startup continued without knowing how the audit stream is configured")
	}
}
