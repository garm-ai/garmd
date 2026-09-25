package jetstream_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
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
	"github.com/garm-ai/garmd/internal/record"
	recordjs "github.com/garm-ai/garmd/internal/record/jetstream"
)

// Nothing here skips. The bounds are the whole design, and a file whose tests
// skip when something is missing reports ok while covering none of them.

const forever = time.Hour

// capture is a Publisher that keeps what it was given.
//
// The counter is atomic because Record runs on the caller's goroutine and the
// flush on the recorder's, so a plain int here would be a data race in the
// test rather than in the code — and -race would then report the fake.
type capture struct {
	mu      sync.Mutex
	batches []captured
	count   atomic.Int64
	err     error
	blockOn chan struct{}
}

type captured struct {
	subject string
	batch   *ledgerv1.Batch
}

func (c *capture) Publish(ctx context.Context, subject string, payload []byte, _ ...natsjs.PublishOpt) (*natsjs.PubAck, error) {
	c.count.Add(1)
	// A real JetStream publish honours the context, and the fake has to as
	// well: without this, a flush on an already-cancelled context succeeds
	// here and fails in production, which is exactly the shutdown bug the
	// Close tests exist to catch.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.blockOn != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.blockOn:
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	var b ledgerv1.Batch
	if err := proto.Unmarshal(payload, &b); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.batches = append(c.batches, captured{subject: subject, batch: &b})
	c.mu.Unlock()
	return &natsjs.PubAck{}, nil
}

func (c *capture) taken() []captured {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]captured(nil), c.batches...)
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func recorderWith(t *testing.T, cfg recordjs.Config) (*recordjs.Recorder, *record.Memory) {
	t.Helper()
	fallback := &record.Memory{}
	if cfg.Fallback == nil {
		cfg.Fallback = fallback
	}
	if cfg.Log == nil {
		cfg.Log = quietLog()
	}
	r, err := recordjs.New(cfg)
	if err != nil {
		t.Fatalf("building the recorder: %v", err)
	}
	t.Cleanup(func() { _ = r.Close(context.Background()) })
	return r, fallback
}

func ev(tenant, id string) ledger.Event {
	return ledger.Event{
		ID:      id,
		Time:    time.Now(),
		Tenant:  tenant,
		App:     "payments",
		Tool:    "/pay.v1.Payments/Transfer",
		Outcome: ledger.OutcomeOK,
	}
}

// waitFor polls until cond holds. A fixed sleep would either be flaky or slow,
// and these are all "has the flusher got to it yet" questions.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The contract this implements: Record must not fail the call, and must not
// be able to make a call slow either.
func TestRecordNeitherFailsNorBlocksWhenTheBrokerIsDown(t *testing.T) {
	pub := &capture{blockOn: make(chan struct{})}
	defer close(pub.blockOn)
	r, fallback := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond,
		MaxEvents: 4, MaxBuffered: 8, PublishTimeout: 50 * time.Millisecond,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			r.Record(context.Background(), ev("acme", ""))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a broker that never answers; a metering publisher " +
			"must never be able to slow a call down")
	}

	// And nothing was lost: past the buffer ceiling, events go to the
	// fallback rather than growing the heap until the outage ends.
	waitFor(t, "the overflow to reach the fallback", func() bool {
		return len(fallback.Events()) > 0
	})
}

// The interval bound on its own. One event on a quiet tenant must leave
// within the window rather than waiting for 255 more that never come.
func TestABatchFlushesOnTheIntervalAlone(t *testing.T) {
	pub := &capture{}
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 20 * time.Millisecond, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	r.Record(context.Background(), ev("acme", "solo"))

	waitFor(t, "the interval to flush a single event", func() bool {
		return len(pub.taken()) == 1
	})
	if got := pub.taken()[0].batch.GetEvents(); len(got) != 1 {
		t.Fatalf("the interval flush carried %d events, want 1", len(got))
	}
}

// The count bound on its own: the interval is out of reach, so only the count
// can have caused this.
func TestABatchFlushesWhenItReachesTheCountBound(t *testing.T) {
	pub := &capture{}
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: forever, MaxEvents: 4, MaxBytes: 1 << 20,
	})
	for i := 0; i < 5; i++ {
		r.Record(context.Background(), ev("acme", ""))
	}

	waitFor(t, "the count bound to flush", func() bool { return len(pub.taken()) == 1 })
	if got := len(pub.taken()[0].batch.GetEvents()); got != 4 {
		t.Fatalf("the batch carried %d events, want the bound of 4", got)
	}
}

// The byte bound on its own, and it is not optional: NATS refuses payloads
// over 1MB by default, so a count-only bound eventually assembles a message
// the server rejects — first on the highest-volume tenant, whose rows are the
// ones least likely to be missed in time.
func TestABatchFlushesWhenItReachesTheByteBound(t *testing.T) {
	pub := &capture{}
	// Small enough that a second event cannot fit beside the first, and a
	// count bound far out of reach so nothing else can explain a flush.
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: forever, MaxEvents: 1000, MaxBytes: 40,
	})
	for i := 0; i < 4; i++ {
		r.Record(context.Background(), ev("acme", ""))
	}

	waitFor(t, "the byte bound to flush", func() bool { return len(pub.taken()) >= 3 })
	for i, c := range pub.taken() {
		if n := len(c.batch.GetEvents()); n != 1 {
			t.Fatalf("batch %d carried %d events past a 40 byte bound; the bound is not "+
				"being applied and a batch will eventually exceed what NATS accepts", i, n)
		}
	}
}

// A published batch must never be over the byte bound, which means the bound
// is checked BEFORE the append rather than after.
func TestNoPublishedBatchExceedsTheByteBound(t *testing.T) {
	pub := &capture{}
	const limit = 4096
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond, MaxEvents: 100000, MaxBytes: limit,
	})
	for i := 0; i < 500; i++ {
		r.Record(context.Background(), ev("acme", ""))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i, c := range pub.taken() {
		if n := proto.Size(c.batch); n > limit {
			t.Errorf("batch %d is %d bytes, over the %d byte bound", i, n, limit)
		}
	}
}

// Shutdown must not be where the last interval's rows go missing.
func TestCloseFlushesAPartialBatch(t *testing.T) {
	pub := &capture{}
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: forever, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	r.Record(context.Background(), ev("acme", "last"))

	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	taken := pub.taken()
	if len(taken) != 1 || len(taken[0].batch.GetEvents()) != 1 {
		t.Fatalf("Close published %d batch(es); the partial batch was dropped", len(taken))
	}
	if got := taken[0].batch.GetEvents()[0].GetEventId(); got != "last" {
		t.Errorf("the flushed event is %q, want %q", got, "last")
	}
}

// Close is called from the shutdown path, where the context is ALREADY
// cancelled — that cancellation is what started the shutdown. A flush that
// honoured it would publish nothing at exactly the moment it matters.
func TestCloseFlushesEvenWhenItsContextIsAlreadyCancelled(t *testing.T) {
	pub := &capture{}
	r, fallback := recorderWith(t, recordjs.Config{
		JS: pub, Interval: forever, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	r.Record(context.Background(), ev("acme", "shutting-down"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(pub.taken()) != 1 {
		t.Fatalf("Close published nothing against a cancelled context; the last batch "+
			"was dropped at shutdown (the fallback holds %d)", len(fallback.Events()))
	}
}

// A subject carries the tenant and the app, and a consumer filtering to one
// tenant reads whole messages. A batch mixing tenants would put one tenant's
// rows behind another's filter.
func TestEventsForDifferentTenantsNeverShareABatch(t *testing.T) {
	pub := &capture{}
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	for i := 0; i < 20; i++ {
		r.Record(context.Background(), ev("acme", ""))
		r.Record(context.Background(), ev("globex", ""))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i, c := range pub.taken() {
		want := c.subject
		for _, e := range c.batch.GetEvents() {
			if got := wire.LedgerSubjectFor(e.GetTenant(), e.GetApp()); got != want {
				t.Fatalf("batch %d on %s carries an event for %s; a consumer filtering "+
					"to one tenant would read the other's rows", i, want, got)
			}
		}
	}
	if len(pub.taken()) < 2 {
		t.Fatalf("two tenants produced %d batch(es); they were mixed", len(pub.taken()))
	}
}

// Consumers dedupe on the event id, which only works if a redelivered event
// carries the id it had the first time. Recording the same event twice — a
// retry one layer up — must not change it.
func TestAnEventKeepsTheIdItWasRecordedWith(t *testing.T) {
	pub := &capture{}
	r, _ := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	r.Record(context.Background(), ev("acme", "fixed-id"))
	r.Record(context.Background(), ev("acme", "fixed-id"))
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var seen int
	for _, c := range pub.taken() {
		for _, e := range c.batch.GetEvents() {
			seen++
			if e.GetEventId() != "fixed-id" {
				t.Fatalf("the published id is %q, not the one the event was recorded "+
					"with; a republished event would look like a distinct call",
					e.GetEventId())
			}
		}
	}
	if seen != 2 {
		t.Fatalf("published %d events, want 2", seen)
	}
}

// The id is assigned at ENQUEUE, not at publish, and the difference is only
// visible on an event that is never published at all.
//
// These events overflow the buffer and go straight to the fallback while the
// broker is wedged. Under enqueue-time assignment they carry an id, because
// they were given one the moment the call was observed. Under publish-time
// assignment they carry none — and the events that DO get published get a
// fresh id on every retry, so a redelivered event is indistinguishable from a
// distinct call and every consumer's dedupe quietly stops working.
func TestAnIdIsMintedWhenAnEventIsRecordedAndNotWhenItIsPublished(t *testing.T) {
	pub := &capture{blockOn: make(chan struct{})}
	defer close(pub.blockOn)
	r, fallback := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond,
		MaxEvents: 4, MaxBuffered: 8,
		PublishTimeout: forever, CloseTimeout: 50 * time.Millisecond,
	})
	for i := 0; i < 100; i++ {
		r.Record(context.Background(), ev("acme", "")) // no id of its own
	}

	waitFor(t, "the overflow to reach the fallback", func() bool {
		return len(fallback.Events()) > 0
	})
	for i, e := range fallback.Events() {
		if e.ID == "" {
			t.Fatalf("event %d reached the fallback with no id: it was never published, "+
				"so nothing minted one. Ids minted at publish time make every retry a "+
				"new call as far as a consumer can tell", i)
		}
	}
}

// A failed publish degrades to the fallback. It never returns an error,
// because by now there is nobody left to return one to.
func TestNothingIsLostWhenThePublishFails(t *testing.T) {
	pub := &capture{err: errors.New("the broker refused")}
	r, fallback := recorderWith(t, recordjs.Config{
		JS: pub, Interval: 10 * time.Millisecond, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	for i := 0; i < 10; i++ {
		r.Record(context.Background(), ev("acme", ""))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(fallback.Events()); got != 10 {
		t.Fatalf("the fallback holds %d of 10 events; the rest were lost", got)
	}
}

// Recording after Close must still leave a row somewhere.
func TestRecordingAfterCloseStillReachesTheFallback(t *testing.T) {
	pub := &capture{}
	r, fallback := recorderWith(t, recordjs.Config{
		JS: pub, Interval: forever, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r.Record(context.Background(), ev("acme", "late"))
	if got := len(fallback.Events()); got != 1 {
		t.Fatalf("the fallback holds %d events after a post-Close record, want 1", got)
	}
}

func TestARecorderWithoutAFallbackIsRefused(t *testing.T) {
	if _, err := recordjs.New(recordjs.Config{JS: &capture{}}); err == nil {
		t.Fatal("a recorder was built with nothing to degrade to")
	}
}

func TestARecorderWithoutAPublisherIsRefused(t *testing.T) {
	if _, err := recordjs.New(recordjs.Config{Fallback: &record.Memory{}}); err == nil {
		t.Fatal("a recorder was built with no publisher")
	}
}

// End to end against a real broker, because what the fake cannot check is
// that the server accepts what this produces at all.
func TestABatchLandsInTheLedgerStream(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{
		Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true,
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

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := natsjs.New(nc)
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}
	// The ledger discards OLD, which is the opposite of the audit stream and
	// the reason they are two streams: metering volume must never evict the
	// records someone is obliged to keep.
	stream, err := js.CreateOrUpdateStream(context.Background(), natsjs.StreamConfig{
		Name:     wire.LedgerStream,
		Subjects: []string{wire.LedgerSubject + ".>"},
		Discard:  natsjs.DiscardOld,
		Storage:  natsjs.FileStorage,
	})
	if err != nil {
		t.Fatalf("creating the ledger stream: %v", err)
	}

	r, fallback := recorderWith(t, recordjs.Config{
		JS: js, Interval: 10 * time.Millisecond, MaxEvents: 1000, MaxBytes: 1 << 20,
	})
	for i := 0; i < 3; i++ {
		r.Record(context.Background(), ev("acme", ""))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := fallback.Events(); len(got) != 0 {
		t.Fatalf("%d events degraded to the fallback against a healthy broker", len(got))
	}

	info, err := stream.Info(context.Background())
	if err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	if info.State.Msgs == 0 {
		t.Fatal("nothing reached the ledger stream")
	}

	var total int
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		raw, err := stream.GetMsg(context.Background(), seq)
		if err != nil {
			continue
		}
		var b ledgerv1.Batch
		if err := proto.Unmarshal(raw.Data, &b); err != nil {
			t.Fatalf("message %d does not parse as a Batch: %v", seq, err)
		}
		total += len(b.GetEvents())
	}
	if total != 3 {
		t.Fatalf("the stream holds %d events, want 3", total)
	}
}
