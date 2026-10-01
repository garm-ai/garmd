package serve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/transport"
)

// fakeDiscoverer answers with whatever a test says is running.
//
// calls is atomic because Run sweeps on its own goroutine while the test
// watches: a plain int here races, and the race detector is right about it
// even though the test would pass without one.
type fakeDiscoverer struct {
	services []transport.Service
	// enumeration and partial are the two kinds of incompleteness a round
	// reports. A test sets one to say "this sweep did not hear everything".
	enumeration error
	partial     map[string]error
	err         error
	calls       atomic.Int64
}

func (f *fakeDiscoverer) Services(context.Context) (transport.Round, error) {
	f.calls.Add(1)
	return transport.Round{
		Services:    f.services,
		Enumeration: f.enumeration,
		Partial:     f.partial,
	}, f.err
}
func (f *fakeDiscoverer) Watch(context.Context) (<-chan transport.Event, error) {
	return nil, errors.New("not implemented")
}

// fixed is a Catalogues that always returns one generation. Built directly
// rather than loaded, because what is under test is the comparison and not
// the loader.
type fixed struct{ c *catalogue.Catalogue }

func (f fixed) Current() *catalogue.Catalogue { return f.c }

func storeWith(t *testing.T, pkg, hash string) Catalogues {
	t.Helper()
	return fixed{&catalogue.Catalogue{
		Digest: "sha256:test",
		Defs: []tool.Def{{
			FullMethod: "/" + pkg + ".Svc/Do",
			FQN:        pkg + ".do",
		}},
		DescriptorHashes: map[string]string{pkg: hash},
	}}
}

func recon(t *testing.T, pkg, catalogueHash string, running []transport.Service) *Reconciler {
	t.Helper()
	r := &Reconciler{
		Store:      storeWith(t, pkg, catalogueHash),
		Discoverer: &fakeDiscoverer{services: running},
	}
	r.sweep(context.Background())
	return r
}

const (
	subject = "acme.v1.Svc.Do"
	good    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	drifted = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestAgreeingContractsAreNotQuarantined(t *testing.T) {
	r := recon(t, "acme.v1", good, []transport.Service{
		{Name: "svc", Identity: good, Subjects: []string{subject}},
	})
	if why, bad := r.Quarantined("acme.v1"); bad {
		t.Errorf("quarantined a matching service: %s", why)
	}
}

// TestDriftIsRefused is the whole point. Protobuf unmarshals a renumbered
// field without complaining, so the call would otherwise succeed with a field
// read as something else — authorised, sanitised and ledgered as fine.
func TestDriftIsRefused(t *testing.T) {
	r := recon(t, "acme.v1", good, []transport.Service{
		{Name: "svc", Identity: drifted, Subjects: []string{subject}},
	})
	why, bad := r.Quarantined("acme.v1")
	if !bad {
		t.Fatal("a service advertising a different contract was allowed")
	}
	for _, want := range []string{"svc", "acme.v1", "bbbbbbbbbbbb", "aaaaaaaaaaaa"} {
		if !contains(why, want) {
			t.Errorf("the reason omits %q, which an operator needs to act: %s", want, why)
		}
	}
}

// A service that advertises nothing cannot be shown to implement anything.
// Treating silence as agreement would make the check trivially bypassable by
// deploying an older runtime.
func TestSilenceIsNotAgreement(t *testing.T) {
	r := recon(t, "acme.v1", good, []transport.Service{
		{Name: "svc", Identity: "", Subjects: []string{subject}},
	})
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Error("a service advertising no hash was treated as matching")
	}
}

// Likewise a catalogue built before hashes existed: nothing to compare
// against is not the same as nothing wrong.
func TestACatalogueWithoutHashesCannotVerify(t *testing.T) {
	r := recon(t, "acme.v1", "", []transport.Service{
		{Name: "svc", Identity: good, Subjects: []string{subject}},
	})
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Error("a catalogue with no recorded hash was treated as verified")
	}
}

// TestAFailedSweepLeavesTheVerdictStanding: discovery being unavailable is
// not evidence that a mismatched service became correct. Clearing on error
// would make a quarantine vanish exactly when nobody can check it.
func TestAFailedSweepLeavesTheVerdictStanding(t *testing.T) {
	f := &fakeDiscoverer{services: []transport.Service{
		{Name: "svc", Identity: drifted, Subjects: []string{subject}},
	}}
	r := &Reconciler{Store: storeWith(t, "acme.v1", good), Discoverer: f}
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Fatal("setup: expected a quarantine")
	}

	f.err = errors.New("nats is unreachable")
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Error("a failed discovery sweep cleared the quarantine")
	}
}

// A subject the catalogue does not declare is not this daemon's business and
// must not quarantine anything it does serve.
func TestAnUnknownSubjectIsIgnored(t *testing.T) {
	r := recon(t, "acme.v1", good, []transport.Service{
		{Name: "ours", Identity: good, Subjects: []string{subject}},
		{Name: "theirs", Identity: "whatever", Subjects: []string{"other.v1.Svc.Do"}},
	})
	if why, bad := r.Quarantined("acme.v1"); bad {
		t.Errorf("an unrelated service quarantined ours: %s", why)
	}
}

func TestRunSweepsImmediately(t *testing.T) {
	f := &fakeDiscoverer{}
	r := &Reconciler{Store: storeWith(t, "acme.v1", good), Discoverer: f, Interval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.calls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if f.calls.Load() == 0 {
		// Waiting a full interval before the first sweep would route to a
		// mismatched service for that entire window.
		t.Error("Run did not sweep before its first tick")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// A quarantine is not lifted by a round that could not hear the service.
//
// This is the asymmetry the whole incomplete-round contract exists for.
// Quarantining is driven by a POSITIVE observation — an instance advertising
// a hash that does not match — and a reply that never arrived cannot produce
// one. Lifting is driven by the ABSENCE of that observation, and a reply that
// never arrived is indistinguishable from a service that has stopped
// misbehaving.
//
// The service scales out, a reply goes missing, and the sweep that would
// otherwise say "the mismatch is gone" must say nothing instead. Before
// discovery could report incompleteness, this was a silent green light.
func TestAnIncompleteRoundDoesNotLiftAQuarantine(t *testing.T) {
	f := &fakeDiscoverer{services: []transport.Service{
		{Name: "svc", Identity: drifted, Subjects: []string{subject}},
	}}
	r := &Reconciler{Store: storeWith(t, "acme.v1", good), Discoverer: f}
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Fatal("setup: the first sweep produced no quarantine")
	}

	// The next sweep hears only the healthy replica of the same service, and
	// knows it heard only part of it.
	f.services = []transport.Service{
		{Name: "svc", Identity: good, Subjects: []string{subject}},
	}
	f.partial = map[string]error{
		"svc": fmt.Errorf("%w: svc answered 1 of the 2 instances the enumeration counted",
			transport.ErrIncompleteRound),
	}
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Error("a partial round lifted the quarantine; the instance that did not " +
			"answer may be the one still running the wrong contract")
	}

	// A round that heard the service in full is entitled to clear it.
	f.partial = nil
	r.sweep(context.Background())
	if why, bad := r.Quarantined("acme.v1"); bad {
		t.Errorf("a complete round did not clear the verdict: %s", why)
	}
}

// An enumeration that came up short clears nothing at all, not even for a
// package whose own service answered.
//
// When the plane-wide round is incomplete, garmd does not know which services
// exist, so it cannot tell a service that stopped from one it never heard —
// and every verdict rests on that distinction.
func TestAnIncompleteEnumerationClearsNothing(t *testing.T) {
	f := &fakeDiscoverer{services: []transport.Service{
		{Name: "svc", Identity: drifted, Subjects: []string{subject}},
	}}
	r := &Reconciler{Store: storeWith(t, "acme.v1", good), Discoverer: f}
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Fatal("setup: the first sweep produced no quarantine")
	}

	f.services = nil
	f.enumeration = fmt.Errorf("%w: the plane-wide enumeration was cut short",
		transport.ErrIncompleteRound)
	r.sweep(context.Background())
	if _, bad := r.Quarantined("acme.v1"); !bad {
		t.Error("a sweep that could not enumerate the plane lifted a quarantine")
	}
}
