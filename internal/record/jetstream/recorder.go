// Package jetstream publishes the ledger to a NATS JetStream stream, in
// batches.
//
// It is the opposite of internal/audit/jetstream in every way that matters,
// and deliberately so. ledger.Recorder is documented "must not fail the call":
// every call leaves a row, and a recorder having a bad day must never be why a
// request fails. So Record returns nothing, never blocks, and degrades to a
// fallback Recorder — normally slog — rather than to an error nobody can act
// on. The audit Sink makes the opposite promise and must not borrow anything
// from this file.
//
// # Why batch
//
// Not because Record needs to be asynchronous; it already is. The costs are
// per-event: a goroutine and a marshal for every single call, and — worse —
// WithPublishAsyncMaxPending, which is a hard ceiling rather than a
// backpressure signal. When the pending window fills, publishing starts
// returning errors and metering silently degrades to log lines under exactly
// the load that made the metering worth having. One publish per batch keeps
// the window nearly empty at the volumes where it used to overflow.
//
// # Why the byte bound is not optional
//
// NATS rejects payloads over 1MB by default. A batcher bounded only by a
// count eventually assembles a message the server refuses — and it happens
// first on the highest-volume tenant, whose events are also the largest,
// which is to say on the account that would notice the missing rows last.
//
// # Why the interval is short
//
// The buffer holds billing data, and a crash destroys whatever is in it. The
// benefit of a longer window saturates almost immediately — the batch is
// already one publish — while the loss window grows linearly with it.
package jetstream

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	ledgerv1 "github.com/garm-ai/garm/contracts/garm/ledger/v1"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/contracts/wire"
)

// Publisher is the one JetStream method a Recorder uses.
type Publisher interface {
	Publish(ctx context.Context, subject string, payload []byte, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// The defaults. Every one of them is a loss window or a rejection threshold,
// so they are named rather than spelled inline.
const (
	// DefaultInterval is how long an event may sit unpublished. It is the
	// crash-loss window, and it is short for that reason alone.
	DefaultInterval = 200 * time.Millisecond

	// DefaultMaxEvents bounds a batch by count.
	DefaultMaxEvents = 256

	// DefaultMaxBytes bounds a batch by size, half of the 1MB NATS refuses
	// above. Half rather than nine tenths because the bound is checked
	// BEFORE appending and one event can still be large.
	DefaultMaxBytes = 512 * 1024

	// DefaultPublishTimeout bounds one publish. A broker that stops answering
	// must cost the buffer, not the process.
	DefaultPublishTimeout = 10 * time.Second

	// DefaultCloseTimeout bounds the final flush.
	DefaultCloseTimeout = 5 * time.Second
)

// Config builds a Recorder.
type Config struct {
	// JS is required.
	JS Publisher

	// Fallback is required, and it is what makes "must not fail the call"
	// true. Everything this recorder cannot publish goes there instead: a
	// full buffer, a marshalling failure, a broker that is down, and whatever
	// is recorded after Close. Nil would mean those events are simply lost,
	// which is the failure the contract forbids.
	Fallback ledger.Recorder

	Log *slog.Logger

	Interval       time.Duration
	MaxEvents      int
	MaxBytes       int
	PublishTimeout time.Duration
	CloseTimeout   time.Duration

	// MaxBuffered caps how many events may be held across all batches at
	// once, and it exists because the alternative to dropping is growing.
	// With the broker down, publishes block until their timeout while Record
	// keeps accepting; without a ceiling the buffer is bounded only by the
	// outage. Past it, events go straight to the fallback — degraded, but
	// written, and the process survives to publish again.
	MaxBuffered int
}

// Recorder implements ledger.Recorder over JetStream.
type Recorder struct {
	js       Publisher
	fallback ledger.Recorder
	log      *slog.Logger

	interval     time.Duration
	maxEvents    int
	maxBytes     int
	pubTimeout   time.Duration
	closeTimeout time.Duration
	maxBuffered  int

	mu       sync.Mutex
	open     map[string]*batch
	ready    []*batch
	buffered int
	closed   bool

	wake chan struct{}
	stop chan struct{}
	done chan struct{}
}

// batch is one message in the making: the events for ONE subject.
//
// Per subject, because a subject carries the tenant and the app, and a
// consumer filtering to one tenant reads whole messages. Mixing tenants in a
// batch would put another tenant's rows behind that filter — records the
// consumer either sees and should not, or drops and should not.
type batch struct {
	subject string
	// id is minted when the batch is created, never when it is sent, so the
	// client's own publish retry carries the id it had the first time and the
	// server dedupes it.
	id     string
	events []*ledgerv1.Event
	bytes  int
}

var _ ledger.Recorder = (*Recorder)(nil)

func New(cfg Config) (*Recorder, error) {
	if cfg.JS == nil {
		return nil, errors.New("a ledger publisher needs a JetStream publisher")
	}
	if cfg.Fallback == nil {
		return nil, errors.New("a ledger publisher needs a fallback Recorder: without " +
			"one, everything it cannot publish is lost, and a Recorder that loses rows " +
			"under load is not a ledger")
	}
	r := &Recorder{
		js:           cfg.JS,
		fallback:     cfg.Fallback,
		log:          cfg.Log,
		interval:     orDuration(cfg.Interval, DefaultInterval),
		maxEvents:    orInt(cfg.MaxEvents, DefaultMaxEvents),
		maxBytes:     orInt(cfg.MaxBytes, DefaultMaxBytes),
		pubTimeout:   orDuration(cfg.PublishTimeout, DefaultPublishTimeout),
		closeTimeout: orDuration(cfg.CloseTimeout, DefaultCloseTimeout),
		open:         map[string]*batch{},
		wake:         make(chan struct{}, 1),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	r.maxBuffered = orInt(cfg.MaxBuffered, 8*r.maxEvents)
	if r.log == nil {
		r.log = slog.Default()
	}
	go r.run()
	return r, nil
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Record buffers ev. It never returns an error and never waits on the broker.
func (r *Recorder) Record(ctx context.Context, ev ledger.Event) {
	// At ENQUEUE, not at publish. Delivery is at-least-once and consumers
	// dedupe on this id, which only works if a redelivered event carries the
	// id it had the first time. An id minted while sending would give every
	// retry a fresh one, making duplicates indistinguishable from distinct
	// calls — the whole dedupe story rests on this line being here.
	if ev.ID == "" {
		ev.ID = ledger.NewEventID()
	}

	p := ledger.ToProto(ev)
	size := framedSize(p)
	subject := wire.LedgerSubjectFor(ev.Tenant, ev.App)

	r.mu.Lock()
	if r.closed || r.buffered >= r.maxBuffered {
		full := !r.closed
		r.mu.Unlock()
		if full {
			r.log.Warn("the ledger buffer is full; recording to the fallback instead",
				"buffered", r.maxBuffered, "tenant", ev.Tenant, "app", ev.App)
		}
		r.fallback.Record(ctx, ev)
		return
	}

	b := r.open[subject]
	// Sealed BEFORE the append, so a sent batch is never over either bound.
	// Sealing after would let one event carry a batch past 1MB, and the
	// server's refusal would take the whole batch with it.
	if b != nil && (b.bytes+size > r.maxBytes || len(b.events)+1 > r.maxEvents) {
		r.ready = append(r.ready, b)
		b = nil
	}
	if b == nil {
		b = &batch{subject: subject, id: ledger.NewEventID()}
		r.open[subject] = b
	}
	b.events = append(b.events, p)
	b.bytes += size
	r.buffered++
	sealed := len(r.ready) > 0
	r.mu.Unlock()

	if sealed {
		r.signal()
	}
}

// signal is non-blocking: the wake channel holds one pending flush, and a
// second one while the first is unread would be the same flush.
// framedSize is what one event costs INSIDE a Batch: its own bytes plus the
// tag and length prefix that carry it.
//
// proto.Size of the event alone under-counts by those few bytes per event,
// which sounds harmless and is not: the bound exists to stay under what NATS
// accepts, and a bound that is wrong by 2 bytes per event is wrong by
// kilobytes at the batch sizes where the limit is reached. The error is
// always in the direction of a batch bigger than intended.
func framedSize(p *ledgerv1.Event) int {
	n := proto.Size(p)
	return protowire.SizeTag(batchEventsField) + protowire.SizeBytes(n)
}

// The field number of Batch.events, which is what frames each event.
const batchEventsField = 1

func (r *Recorder) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Recorder) run() {
	defer close(r.done)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			// The interval bound. Sealing every open batch is what makes a
			// quiet tenant's single event leave within the window rather than
			// waiting for 255 more that may never come.
			r.sealAll()
			r.publishReady(context.Background())
		case <-r.wake:
			// The count and byte bounds. Record has already sealed what
			// crossed them; nothing open is touched, so a batch that is
			// merely in progress keeps filling.
			r.publishReady(context.Background())
		}
	}
}

func (r *Recorder) sealAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for subject, b := range r.open {
		if len(b.events) > 0 {
			r.ready = append(r.ready, b)
		}
		delete(r.open, subject)
	}
}

func (r *Recorder) publishReady(ctx context.Context) {
	for {
		r.mu.Lock()
		if len(r.ready) == 0 {
			r.mu.Unlock()
			return
		}
		b := r.ready[0]
		r.ready = r.ready[1:]
		r.mu.Unlock()
		r.publish(ctx, b)
	}
}

func (r *Recorder) publish(ctx context.Context, b *batch) {
	defer func() {
		r.mu.Lock()
		r.buffered -= len(b.events)
		r.mu.Unlock()
	}()

	payload, err := proto.Marshal(&ledgerv1.Batch{Events: b.events})
	if err == nil {
		pctx, cancel := context.WithTimeout(ctx, r.pubTimeout)
		_, err = r.js.Publish(pctx, b.subject, payload, natsjs.WithMsgID(b.id))
		cancel()
	}
	if err == nil {
		return
	}

	// Degrade, never fail. The call this event describes finished long ago;
	// there is nobody left to return an error to, and the only question is
	// whether the row survives somewhere legible.
	r.log.Error("the ledger batch could not be published; recording it to the fallback",
		"subject", b.subject, "events", len(b.events), "stream", wire.LedgerStream, "err", err)
	for _, p := range b.events {
		r.fallback.Record(ctx, ledger.FromProto(p))
	}
}

// Close flushes what is buffered and stops the flusher.
//
// The context is stripped of cancellation. Close is called on the shutdown
// path, where the context is ALREADY cancelled — that is what started the
// shutdown — so a flush that honoured it would publish nothing and silently
// drop the last batch, which on a busy process is every row of the final
// interval.
func (r *Recorder) Close(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()

	close(r.stop)
	<-r.done

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.closeTimeout)
	defer cancel()
	r.sealAll()
	r.publishReady(ctx)
	return nil
}
