package catalogue_test

import (
	"context"
	"testing"
	"time"

	"github.com/garm-ai/garmd/internal/catalogue"
)

func TestLoadBuildsDefsFromDescriptors(t *testing.T) {
	c, err := catalogue.Load(buildCatalogue(t, "get_status"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Defs) != 1 {
		t.Fatalf("got %d defs, want 1", len(c.Defs))
	}
	d := c.Defs[0]
	if d.FQN != "t.v1.get_status" {
		t.Errorf("FQN = %q, want t.v1.get_status", d.FQN)
	}
	if d.FullMethod != "/t.v1.S/Get" {
		t.Errorf("FullMethod = %q, want /t.v1.S/Get", d.FullMethod)
	}
	if d.Service() != "t.v1.S" {
		t.Errorf("Service() = %q, want t.v1.S", d.Service())
	}
	if d.Input == nil || d.Output == nil {
		t.Error("input and output descriptors must come from the catalogue's own registry")
	}
	if c.Digest == "" {
		t.Error("no digest")
	}
}

// TestABadCatalogueNeverBecomesCurrent is the property reload exists to hold.
//
// Everything that can fail does so before the swap, so a process handed
// rubbish keeps serving what it was serving. Without this, a bad reload is an
// outage with no rollback.
func TestABadCatalogueNeverBecomesCurrent(t *testing.T) {
	good := buildCatalogue(t, "get_status")
	s := catalogue.NewStore(catalogue.Options{})
	ctx := context.Background()

	if _, err := s.Reload(ctx, catalogue.BytesSource{Body: good}); err != nil {
		t.Fatal(err)
	}
	was := s.Current()

	for _, bad := range []struct {
		name string
		body []byte
	}{
		{"not a catalogue", []byte("definitely not protobuf at all, not even close")},
		{"empty", nil},
		{"truncated", good[:len(good)/2]},
	} {
		if _, err := s.Reload(ctx, catalogue.BytesSource{Body: bad.body, Name: bad.name}); err == nil {
			t.Errorf("%s: reload succeeded", bad.name)
		}
		if s.Current() != was {
			t.Fatalf("%s: the current catalogue changed after a failed reload", bad.name)
		}
	}
}

// TestReloadingTheSameDigestDoesNotChurn: a watcher that fires on a touched
// file should not cost a generation.
func TestReloadingTheSameDigestDoesNotChurn(t *testing.T) {
	body := buildCatalogue(t, "get_status")
	s := catalogue.NewStore(catalogue.Options{})
	ctx := context.Background()

	first, err := s.Reload(ctx, catalogue.BytesSource{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Reload(ctx, catalogue.BytesSource{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Error("an identical digest produced a new generation")
	}
	if got := len(s.Generations()); got != 1 {
		t.Errorf("%d generations retained, want 1", got)
	}
}

func TestRetentionIsBoundedByCountAndAge(t *testing.T) {
	a := buildCatalogue(t, "tool_a")
	b := buildCatalogue(t, "tool_b")
	c := buildCatalogue(t, "tool_c")

	clock := time.Now()
	s := catalogue.NewStore(catalogue.Options{
		KeepDepth: 1,
		TTL:       time.Hour,
		Now:       func() time.Time { return clock },
	})
	ctx := context.Background()
	for _, body := range [][]byte{a, b, c} {
		if _, err := s.Reload(ctx, catalogue.BytesSource{Body: body}); err != nil {
			t.Fatal(err)
		}
	}
	// Current plus one superseded: the third reload evicted the first.
	if got := len(s.Generations()); got != 2 {
		t.Errorf("KeepDepth 1 held %d generations, want 2 (current + 1)", got)
	}

	clock = clock.Add(2 * time.Hour)
	s.Sweep()
	if got := len(s.Generations()); got != 1 {
		t.Errorf("after the TTL expired, %d generations held, want 1 (current only)", got)
	}
	if s.Current() == nil {
		t.Error("the TTL swept the current catalogue; it is not superseded and never ages out")
	}
}

// TestAnInFlightRequestKeepsItsGeneration: retention is for rollback, not for
// safety. A holder of a *Catalogue keeps it alive whatever the store does,
// which is what makes a swap safe with KeepDepth of zero.
func TestAnInFlightRequestKeepsItsGeneration(t *testing.T) {
	a := buildCatalogue(t, "tool_a")
	b := buildCatalogue(t, "tool_b")
	s := catalogue.NewStore(catalogue.Options{KeepDepth: -1}) // retain nothing
	ctx := context.Background()

	if _, err := s.Reload(ctx, catalogue.BytesSource{Body: a}); err != nil {
		t.Fatal(err)
	}
	inFlight := s.Current() // as a request would, once, at entry

	if _, err := s.Reload(ctx, catalogue.BytesSource{Body: b}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Generations()); got != 1 {
		t.Errorf("KeepDepth -1 retained %d, want 1 (current only)", got)
	}
	if len(inFlight.Defs) != 1 || inFlight.Defs[0].FQN != "t.v1.tool_a" {
		t.Error("the in-flight generation was disturbed by a swap")
	}
	if s.Current().Defs[0].FQN != "t.v1.tool_b" {
		t.Error("the swap did not take effect for new requests")
	}
}

// TestUniqueShortNamesAreLeftAlone: the common case pays nothing. A model
// reasons better about get_balance than about acme_accounts_v1_get_balance,
// so the namespace is shown only where it earns its place.
func TestUniqueShortNamesAreLeftAlone(t *testing.T) {
	c, err := catalogue.Load(buildCatalogueFrom(t, map[string]string{
		"acme.accounts.v1": "get_balance",
		"acme.payments.v1": "refund",
	}), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range c.Defs {
		if d.ClientName != d.Name {
			t.Errorf("%s: client name %q, want the short name %q — nothing collided",
				d.FQN, d.ClientName, d.Name)
		}
	}
}

// TestCollidingNamesAreBothPrefixed pins the two properties that make
// disambiguation safe rather than clever.
//
// BOTH sides get prefixed, because prefixing only the newcomer would make a
// tool's name depend on which package the loader happened to read first. And
// the result is deterministic, because two replicas that disagree route the
// same call to different tools.
func TestCollidingNamesAreBothPrefixed(t *testing.T) {
	body := buildCatalogueFrom(t, map[string]string{
		"acme.accounts.v1": "get_status",
		"acme.payments.v1": "get_status",
	})

	first, err := catalogue.Load(body, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range first.Defs {
		got[d.FQN] = d.ClientName
	}
	want := map[string]string{
		"acme.accounts.v1.get_status": "acme_accounts_v1_get_status",
		"acme.payments.v1.get_status": "acme_payments_v1_get_status",
	}
	for fqn, w := range want {
		if got[fqn] != w {
			t.Errorf("%s: client name %q, want %q", fqn, got[fqn], w)
		}
	}

	// Determinism: the same bytes must give the same answer every time.
	for i := 0; i < 5; i++ {
		again, err := catalogue.Load(body, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range again.Defs {
			if d.ClientName != got[d.FQN] {
				t.Fatalf("%s: client name %q on one load and %q on another; "+
					"two replicas would route the same call to different tools",
					d.FQN, got[d.FQN], d.ClientName)
			}
		}
	}
}

// TestDefsAreOrdered: RangeFiles promises no order, and a catalogue that
// lists its tools differently on each boot makes every diff and log useless.
func TestDefsAreOrdered(t *testing.T) {
	c, err := catalogue.Load(buildCatalogueFrom(t, map[string]string{
		"zeta.v1":  "z_tool",
		"alpha.v1": "a_tool",
		"mid.v1":   "m_tool",
	}), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(c.Defs); i++ {
		if c.Defs[i-1].FQN > c.Defs[i].FQN {
			t.Fatalf("defs are not sorted: %q before %q", c.Defs[i-1].FQN, c.Defs[i].FQN)
		}
	}
}
