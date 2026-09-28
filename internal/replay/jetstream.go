package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// JetStream is a replay cache over a JetStream key-value bucket.
//
// NATS rather than a new datastore because it is already here: garmd holds a
// connection to route every call, so this adds a bucket rather than a
// dependency. It is also the only shared store in the stack that garmd is
// already required to be able to reach — a cache in something garmd could
// live without would make an outage of that thing an outage of every
// approval-gated tool, for no gain over the broker.
type JetStream struct {
	kv        jetstream.KeyValue
	retention time.Duration
}

// BucketName is fixed rather than configurable.
//
// Two garmd deployments sharing a NATS account must share this cache or the
// single-use property is per-deployment, and a configurable name is how two
// deployments end up with one each without anyone deciding to.
const BucketName = "GARM_GRANTS_SPENT"

// NewJetStream opens or creates the bucket.
//
// ttl must exceed the longest grant a catalogue declares; CheckRetention is
// what enforces that, against the artifact, at startup.
func NewJetStream(ctx context.Context, nc *nats.Conn, ttl time.Duration) (*JetStream, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("replay: a cache with no expiry grows without bound; " +
			"give it a ttl at least as long as the longest grant")
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("replay: jetstream: %w", err)
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: BucketName,
		TTL:    ttl,
		// File, not memory. A restart that forgot every spent grant would
		// make every approval in the window replayable, and a rolling deploy
		// is exactly when nobody is watching.
		Storage: jetstream.FileStorage,
		// History of one: this bucket answers a yes/no question and previous
		// revisions of "yes" are not interesting.
		History:     1,
		Description: "Spent approval-grant identifiers. One approval, one call.",
	})
	if err != nil {
		return nil, fmt.Errorf("replay: opening %s: %w", BucketName, err)
	}

	// Read the TTL back rather than trusting what we asked for. An existing
	// bucket created by an older deployment keeps its own configuration, and
	// believing our own request would report a retention this cache does not
	// have.
	actual := ttl
	if st, err := kv.Status(ctx); err == nil && st.TTL() > 0 {
		actual = st.TTL()
	}
	return &JetStream{kv: kv, retention: actual}, nil
}

// Spend records id, atomically.
//
// Create is the whole design: it succeeds only if the key is absent, so
// exactly one caller across every replica can win. A Get followed by a Put
// would let two replicas both find nothing and both allow, which is the
// failure this cache exists to prevent, reintroduced by the obvious
// implementation.
func (j *JetStream) Spend(ctx context.Context, id string) error {
	if id == "" {
		// A credential with no identifier cannot be single-use. Refusing is
		// the only answer that is not a silent exemption.
		return fmt.Errorf("replay: no identifier to record; a single-use " +
			"credential must carry one")
	}
	_, err := j.kv.Create(ctx, key(id), []byte(time.Now().UTC().Format(time.RFC3339)))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, jetstream.ErrKeyExists):
		return ErrAlreadySpent
	default:
		// Deliberately NOT ErrAlreadySpent. The caller must be able to tell
		// "this was used" from "I could not find out", because the first is a
		// caller's mistake and the second is an operator's — and both refuse,
		// but only one of them should page somebody.
		return fmt.Errorf("replay: recording %s: %w", id, err)
	}
}

func (j *JetStream) Retention() time.Duration { return j.retention }

// key makes a jti safe as a KV key.
//
// A JetStream key admits alphanumerics, dash, underscore, equals and dot. A
// jti is opaque and an issuer may put anything in it, so anything else is
// escaped rather than stripped — stripping would map two distinct identifiers
// onto one key, and the collision would silently refuse a legitimate grant as
// a replay.
func key(id string) string {
	out := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '=', c == '.':
			out = append(out, c)
		default:
			out = append(out, '.', hexDigit(c>>4), hexDigit(c&0x0f))
		}
	}
	return string(out)
}

func hexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}
