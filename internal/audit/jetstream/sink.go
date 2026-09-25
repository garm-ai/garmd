// Package jetstream writes the audit record to a NATS JetStream stream.
//
// It is the half of the record that MAY refuse a call, and everything here
// follows from that. One publish per write, synchronous, the server's ack
// awaited and its error returned — because a tool declaring fail_closed is
// saying the call must not proceed unless the record is durable, and the only
// way to know that is to have been told so.
//
// Nothing here batches, buffers or retries in the background. The ledger's
// publisher does all three and is right to (see internal/record/jetstream);
// doing any of them here would turn "the record is written" into "the record
// is scheduled", and a write-ahead that is still in a buffer when the process
// dies is a write-ahead that never happened. The whole guarantee is the wait.
package jetstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	"github.com/garm-ai/garm/contracts/audit"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/contracts/wire"
)

// Publisher is the one JetStream method a Sink uses.
//
// Narrow on purpose: a Sink holding the whole JetStream interface could grow
// a consumer, a stream update or an async publish, and the last of those is
// the one mistake this package exists to not make.
type Publisher interface {
	Publish(ctx context.Context, subject string, payload []byte, opts ...natsjs.PublishOpt) (*natsjs.PubAck, error)
}

// Config builds a Sink.
type Config struct {
	// JS is required.
	JS Publisher

	// Retention is what this deployment promises, and it is the operator's
	// ASSERTION rather than anything measured.
	//
	// It cannot be derived from the stream, and deriving it would be worse
	// than asking. The forwarder acks a message as soon as it has flushed it
	// onward, which deletes it, so the stream's MaxAge is a buffer window of
	// hours — nothing like the years a tool asks for in `retain_days`. The
	// real retention is the lifecycle policy on the object store the
	// forwarder writes to, which this process cannot read and has no
	// business reading.
	//
	// So it is configuration, and a wrong value is silent: the mount check in
	// toolplane compares a tool's retain_days against this number, so an
	// operator who types seven years against a bucket configured for thirty
	// days gets a catalogue that mounts cleanly and a promise that is false.
	// It will be discovered by whoever goes looking for the row, years late.
	// Zero means indefinite, per the audit.Sink contract, and is therefore
	// the strongest claim available rather than the safest default.
	Retention time.Duration

	// Timeout bounds one publish, on top of whatever deadline the caller
	// brought. A caller with no deadline at all is the common case on a tool
	// call, and a publish that waits forever for an ack holds the request
	// path open for as long as JetStream is unreachable — which for a
	// fail_closed tool is an outage that looks like a hang rather than a
	// refusal.
	Timeout time.Duration
}

const defaultTimeout = 5 * time.Second

// Sink implements audit.Sink over JetStream.
type Sink struct {
	js        Publisher
	retention time.Duration
	timeout   time.Duration
}

var _ audit.Sink = (*Sink)(nil)

func New(cfg Config) (*Sink, error) {
	if cfg.JS == nil {
		return nil, errors.New("an audit Sink needs a JetStream publisher; nil would " +
			"make every audited call refuse, which is safe and useless")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Sink{js: cfg.JS, retention: cfg.Retention, timeout: timeout}, nil
}

// Write publishes ev and waits for the server to acknowledge it.
//
// The error is the point. It reaches toolplane.auditIntent, which refuses the
// call when the tool declared fail_closed — so a publish that has not been
// acked must report as a failure rather than as something in flight.
func (s *Sink) Write(ctx context.Context, ev ledger.Event) error {
	if ev.ID == "" {
		// A backstop, not the normal path: the chain assigns the id when it
		// opens the event, because an id minted here would be a different one
		// on every retry and dedupe would stop working. Minting one anyway
		// beats refusing the call over a missing string, and beats publishing
		// with an empty Nats-Msg-Id, which the server would treat as no id at
		// all.
		ev.ID = ledger.NewEventID()
	}

	payload, err := proto.Marshal(ledger.ToProto(ev))
	if err != nil {
		return fmt.Errorf("marshalling the audit record: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// The msg id carries the OUTCOME as well as the event id, and it has to.
	// One call publishes twice with one event id — the intent before the tool
	// runs and the outcome after — so keying dedupe on the id alone would
	// make the outcome an exact duplicate of the intent inside the stream's
	// duplicate window. The server would ack it and store nothing, leaving
	// every audited call permanently recorded as started and never finished,
	// with no error anywhere.
	msgID := ev.ID + "." + string(ev.Outcome)

	_, err = s.js.Publish(ctx, wire.AuditSubjectFor(ev.Tenant, ev.App), payload,
		natsjs.WithMsgID(msgID))
	if err != nil {
		return fmt.Errorf("publishing the audit record to %s: %w", wire.AuditStream, err)
	}
	return nil
}

// Retention reports what the operator declared. See Config.Retention: it is
// not measured, and it cannot be.
func (s *Sink) Retention() time.Duration { return s.retention }

// StreamLookup is the lookup half of JetStream, for AssertStream.
type StreamLookup interface {
	Stream(ctx context.Context, name string) (natsjs.Stream, error)
}

// AssertStream refuses to start against an audit stream configured to lose
// records.
//
// A silently lossy audit stream is worse than no audit stream, because it
// reads as protection. Every check here is one where the publish still
// succeeds and the record still disappears:
//
//   - DiscardOld is JetStream's DEFAULT, and it drops the oldest messages to
//     stay within the limits while every publish goes on returning a
//     successful ack. A fail_closed tool would keep running, believing it had
//     been recorded, while its records aged out from under it. The audit
//     stream must be DiscardNew: full means refuse, and refusing is what
//     fail_closed asked for.
//   - MemoryStorage makes the ack meaningless. It says the record survived
//     as far as a process that is about to be restarted.
//
// Replicas only warns. A single-node stream loses records when the node does,
// but a laptop and a dev cluster are legitimate, and refusing to start there
// would push someone into turning the whole check off.
//
// A stream that does not exist is not an error here. Publishing to a subject
// no stream captures fails loudly on every call, which is the safe direction
// and is reported where it happens.
func AssertStream(ctx context.Context, js StreamLookup, log *slog.Logger) error {
	s, err := js.Stream(ctx, wire.AuditStream)
	if errors.Is(err, natsjs.ErrStreamNotFound) {
		if log != nil {
			log.Warn("no audit stream exists yet; every audited call will refuse until "+
				"one is created", "stream", wire.AuditStream, "subject", wire.AuditSubject)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the %s stream: %w", wire.AuditStream, err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		return fmt.Errorf("reading the %s stream's configuration: %w", wire.AuditStream, err)
	}

	cfg := info.Config
	if cfg.Discard != natsjs.DiscardNew {
		return fmt.Errorf("the %s stream discards %s; it must discard new. Discarding old "+
			"drops records while every publish still acks, so a fail_closed tool goes on "+
			"succeeding with nothing kept and nothing reported",
			wire.AuditStream, cfg.Discard)
	}
	if cfg.Storage != natsjs.FileStorage {
		return fmt.Errorf("the %s stream is %s; it must be file storage. An ack from memory "+
			"says the record survived as far as a process restart",
			wire.AuditStream, cfg.Storage)
	}
	if cfg.Replicas < 3 && log != nil {
		log.Warn("the audit stream is not replicated; losing the node loses records that "+
			"were acked as durable",
			"stream", wire.AuditStream, "replicas", cfg.Replicas)
	}
	return nil
}
