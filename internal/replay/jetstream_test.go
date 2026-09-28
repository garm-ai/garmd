package replay_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/garm-ai/garmd/internal/replay"
)

// Against a real broker with JetStream, because the property being tested is
// the broker's atomicity. A fake that returned ErrKeyExists on a second call
// would pass every test here and prove nothing about what happens when two
// replicas race.

func broker(t *testing.T) *nats.Conn {
	t.Helper()
	dir := t.TempDir()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats did not start")
	}
	t.Cleanup(srv.Shutdown)

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func cache(t *testing.T, ttl time.Duration) *replay.JetStream {
	t.Helper()
	c, err := replay.NewJetStream(context.Background(), broker(t), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnIdentifierCanBeSpentExactlyOnce(t *testing.T) {
	c := cache(t, time.Hour)
	ctx := context.Background()

	if err := c.Spend(ctx, "grant-1"); err != nil {
		t.Fatalf("first spend: %v", err)
	}
	err := c.Spend(ctx, "grant-1")
	if !errors.Is(err, replay.ErrAlreadySpent) {
		t.Fatalf("second spend = %v, want ErrAlreadySpent — one approval has just "+
			"authorised two calls", err)
	}
	if err := c.Spend(ctx, "grant-2"); err != nil {
		t.Errorf("a different grant was refused: %v", err)
	}
}

// The property the whole package exists for.
//
// Sixteen callers racing on one identifier, as two replicas would. Exactly one
// may win. A check-then-write implementation passes the sequential test above
// and fails this one — which is why the sequential test is not enough and why
// this runs against a real broker rather than a map with a mutex.
func TestExactlyOneRacingCallerWins(t *testing.T) {
	c := cache(t, time.Hour)

	const n = 16
	var won, spent atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := c.Spend(context.Background(), "contended"); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, replay.ErrAlreadySpent):
				spent.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := won.Load(); got != 1 {
		t.Errorf("%d callers were told the grant was unspent, want exactly 1. "+
			"Every extra one is an irreversible call authorised by an approval "+
			"somebody gave once", got)
	}
	if got := won.Load() + spent.Load(); got != n {
		t.Errorf("%d of %d calls got a definite answer; the rest errored, and an "+
			"error must refuse rather than allow", got, n)
	}
}

// A second cache over the same bucket is the same cache. This is what makes
// the property hold across replicas rather than within a process.
func TestASecondInstanceSeesTheFirstsSpends(t *testing.T) {
	nc := broker(t)
	ctx := context.Background()
	a, err := replay.NewJetStream(ctx, nc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := replay.NewJetStream(ctx, nc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Spend(ctx, "shared"); err != nil {
		t.Fatal(err)
	}
	if err := b.Spend(ctx, "shared"); !errors.Is(err, replay.ErrAlreadySpent) {
		t.Errorf("a second instance = %v, want ErrAlreadySpent. A per-process cache "+
			"lets one approval be spent once per replica, which gets worse the "+
			"better the service scales", err)
	}
}

// An unidentified credential cannot be single-use, and pretending otherwise
// would be a silent exemption for exactly the token an attacker controls.
func TestACredentialWithNoIdentifierIsRefused(t *testing.T) {
	c := cache(t, time.Hour)
	err := c.Spend(context.Background(), "")
	if err == nil {
		t.Fatal("an empty identifier was accepted")
	}
	if errors.Is(err, replay.ErrAlreadySpent) {
		t.Error("reported as a replay; it is a malformed credential, and the two " +
			"send an operator to different places")
	}
}

// A jti is opaque and an issuer may put anything in it. Escaping rather than
// stripping, because stripping maps two identifiers onto one key and the
// collision refuses a legitimate grant as a replay.
func TestTwoIdentifiersThatDifferOnlyInPunctuationDoNotCollide(t *testing.T) {
	c := cache(t, time.Hour)
	ctx := context.Background()
	if err := c.Spend(ctx, "a/b+c"); err != nil {
		t.Fatal(err)
	}
	if err := c.Spend(ctx, "a:b*c"); err != nil {
		t.Errorf("a distinct identifier was refused as a replay: %v — two grants "+
			"collided onto one key", err)
	}
}

// A cache that forgets faster than a grant lives is replayable in the gap, and
// nothing about that is visible when it is configured.
func TestACacheThatForgetsBeforeTheGrantExpiresIsRefused(t *testing.T) {
	c := cache(t, 5*time.Minute)

	if err := replay.CheckRetention(c, 15*time.Minute); err == nil {
		t.Fatal("a five-minute cache was accepted against fifteen-minute grants")
	}
	if err := replay.CheckRetention(c, 5*time.Minute); err != nil {
		t.Errorf("an exactly-sufficient cache was refused: %v", err)
	}
	if err := replay.CheckRetention(c, time.Minute); err != nil {
		t.Errorf("a more-than-sufficient cache was refused: %v", err)
	}
}

func TestACacheWithNoExpiryIsRefusedOutright(t *testing.T) {
	if _, err := replay.NewJetStream(context.Background(), broker(t), 0); err == nil {
		t.Error("a bucket with no ttl was created; it would grow without bound")
	}
}
