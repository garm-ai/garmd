// Package reload replaces the catalogue a process is serving, or refuses to.
//
// The refusal is the interesting half. A file catalogue is placed by whoever
// deployed the binary; an object in a bucket is writable by whoever holds a
// key, and the process is already serving when it changes. So the rule is the
// same fail-closed rule as boot, minus the process dying: **a generation this
// deployment cannot serve never becomes current**, and the one that is serving
// keeps serving.
//
// That forces the order. Everything that can refuse — loading, the compartment
// taxonomy, what this deployment's configuration covers, the chain's mount
// check — happens on a candidate BEFORE the store swaps, because a Store has
// no way to put a generation back. Swapping first and rolling back on failure
// would leave a window in which requests were governed by a document that was
// about to be withdrawn.
package reload

import (
	"context"
	"log/slog"
	"time"

	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
)

// Object is the thing being polled: bytes, and a cheap change signal.
//
// An interface so the poller does not depend on S3 in particular — the ETag is
// opaque here, compared and never interpreted, which is also what lets a
// future source signal a change with a version id or a generation number.
type Object interface {
	Read(ctx context.Context) ([]byte, error)
	ETag(ctx context.Context) (string, error)
	String() string
}

// Preparer builds the governance chain for a generation, and refuses one it
// cannot build. serve.Handler is the implementation.
//
// Two methods, because the difference matters here and nowhere else. Check
// builds a candidate's chain and throws it away: it answers "could this be
// governed" about a generation nothing is serving yet. Prepare publishes one,
// and must therefore be called only about the generation that is current —
// publishing a candidate's chain would leave every request on the outgoing
// generation rebuilding its own, for as long as the pre-flight took.
type Preparer interface {
	Check(cat *catalogue.Catalogue) error
	Prepare(cat *catalogue.Catalogue) error
}

// Registries is where a rebuilt compartment taxonomy is published.
// authn.Swappable is the implementation.
type Registries interface {
	Set(reg *policy.Registry)
}

// Outcome is what one poll did, so a caller — a test, above all — can assert
// on the decision rather than on a log line.
type Outcome int

const (
	// Unchanged: the object is the one already being served.
	Unchanged Outcome = iota
	// Swapped: a new generation is now current.
	Swapped
	// Kept: something refused, and the previous generation still serves. It
	// covers an unreachable store as well as a bad artifact, deliberately:
	// both mean "not now", and neither is a reason to stop serving.
	Kept
)

func (o Outcome) String() string {
	switch o {
	case Unchanged:
		return "Unchanged"
	case Swapped:
		return "Swapped"
	case Kept:
		return "Kept"
	}
	return "unknown"
}

// Poller re-reads a catalogue object when its ETag changes.
type Poller struct {
	Source       Object
	Store        *catalogue.Store
	Handler      Preparer
	Compartments Registries
	Log          *slog.Logger

	// Admit is a refusal this deployment's CONFIGURATION makes, as opposed to
	// one its chain makes. Optional; nil admits every generation the rest of
	// the pre-flight accepts.
	//
	// It exists because not everything a reload can break is visible to the
	// mount check. The replay bucket's expiry is derived once, at startup,
	// from the boot catalogue's longest max_grant_age — a generation raising
	// that ceiling mounts perfectly happily and leaves an approval replayable
	// after its spent-record has expired. The daemon knows that; this package
	// does not, and should not have to.
	Admit func(cat *catalogue.Catalogue) error

	// Interval between polls. Thirty seconds in the daemon, matching the
	// reconciler's cadence — there is no notification, and a shorter interval
	// only asks the object store more often.
	Interval time.Duration

	// etag of the generation now serving. Only Run and Once touch it, and they
	// are the same goroutine.
	etag string
}

// Run polls until ctx is done.
//
// There is no immediate first poll. Unlike the reconciler, which must refuse a
// mismatched service from the first request, the catalogue this process booted
// with was read seconds ago — polling it again straight away would only ask
// the store to confirm what boot just read.
func (p *Poller) Run(ctx context.Context) {
	interval := p.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Once(ctx)
		}
	}
}

// Once polls, and reloads if the object changed.
//
// Every failure returns Kept. A bucket that cannot be reached is not evidence
// that what is serving is wrong, and treating it as such would withdraw a
// working catalogue exactly when nobody can replace it.
func (p *Poller) Once(ctx context.Context) Outcome {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	etag, err := p.Source.ETag(ctx)
	if err != nil {
		p.Log.Warn("the catalogue object could not be checked; the generation now "+
			"serving is unaffected",
			"source", p.Source.String(), "serving", p.serving(), "err", err)
		return Kept
	}
	if etag == "" {
		// A store that reports no ETag gives nothing to compare, and re-reading
		// on every poll would churn a generation for nothing. Say so once per
		// poll rather than silently never reloading.
		p.Log.Warn("the catalogue object reports no ETag, so a change cannot be "+
			"detected and this process will not reload",
			"source", p.Source.String())
		return Kept
	}
	if etag == p.etag {
		return Unchanged
	}

	body, err := p.Source.Read(ctx)
	if err != nil {
		p.Log.Warn("the changed catalogue object could not be read; the generation "+
			"now serving is unaffected",
			"source", p.Source.String(), "serving", p.serving(), "etag", etag, "err", err)
		return Kept
	}

	// The DIGEST decides, not the ETag. The ETag only says "look again":
	// this process boots by reading the object's bytes and never sees the
	// header, so the first poll always looks; a re-upload of identical bytes
	// changes it; and S3 stores disagree about how they compute it anyway.
	// Swapping on it would retire a generation and rebuild every compiled
	// plan to arrive at the artifact already being served.
	//
	// Reading the object ONCE and validating those exact bytes is the other
	// half: re-reading for the swap could take a different object, and then
	// what was checked is not what is served.
	candidate := catalogue.DigestOf(body)
	if cur := p.Store.Current(); cur != nil && cur.Digest == candidate {
		p.etag = etag
		return Unchanged
	}

	// The pre-flight, on a candidate nothing is serving yet.
	next, err := catalogue.Load(body, time.Now)
	if err != nil {
		p.Log.Error("the new catalogue does not load; the previous generation keeps serving",
			"source", p.Source.String(), "serving", p.serving(), "refused", candidate,
			"err", err)
		return Kept
	}
	reg, err := policy.NewRegistry(next.Compartments)
	if err != nil {
		p.Log.Error("the new catalogue's compartment declarations are unusable; the "+
			"previous generation keeps serving",
			"source", p.Source.String(), "serving", p.serving(), "refused", candidate,
			"err", err)
		return Kept
	}
	// Before the chain, because it is the cheap half and because building a
	// chain for a generation already refused is work nobody will use.
	if p.Admit != nil {
		if err := p.Admit(next); err != nil {
			p.Log.Error("the new catalogue is not covered by this deployment's "+
				"configuration; the previous generation keeps serving",
				"source", p.Source.String(), "serving", p.serving(), "refused", candidate,
				"err", err)
			return Kept
		}
	}
	if err := p.Handler.Check(next); err != nil {
		// The sharp one: a valid catalogue declaring supervision this
		// deployment cannot apply. Serving it would run a tool ungated while
		// its schema says it is supervised.
		p.Log.Error("the new catalogue cannot be governed by this deployment; the "+
			"previous generation keeps serving",
			"source", p.Source.String(), "serving", p.serving(), "refused", candidate,
			"err", err)
		return Kept
	}

	// Everything that can refuse has run. BytesSource rather than the object
	// again, so the store swaps in exactly what was checked.
	was := p.serving()
	swapped, err := p.Store.Reload(ctx, catalogue.BytesSource{
		Body: body, Name: p.Source.String(),
	})
	if err != nil {
		p.Log.Error("the new catalogue was refused by the store; the previous "+
			"generation keeps serving",
			"source", p.Source.String(), "serving", was, "refused", candidate, "err", err)
		return Kept
	}

	// The chain for the generation that is actually current, published now
	// that it IS current. The pre-flight built one for a different *Catalogue
	// value and threw it away — planes are keyed on pointer identity,
	// deliberately — so without this the first request after a reload pays to
	// compile every plan in the artifact. Identical bytes, so it cannot
	// refuse; if it somehow does, the generation is already current and the
	// lazy build will report it per request.
	if err := p.Handler.Prepare(swapped); err != nil {
		p.Log.Error("the chain could not be rebuilt for the generation now serving",
			"serving", swapped.Digest, "err", err)
	}

	// The taxonomy LAST, and in the same operation as the swap. A registry
	// published for a generation nobody is serving would resolve every token's
	// compartments against a document that is not in force; one left behind
	// after a swap does the same in the other direction. What rescues the
	// instant between the two is that a request pins the registry of the plane
	// serving it (authn.WithRegistry) — this value is the fallback for a
	// caller with no plane, and it must not be allowed to disagree for longer
	// than these three lines.
	p.Compartments.Set(reg)
	p.etag = etag
	p.Log.Info("the catalogue was reloaded",
		"source", p.Source.String(), "was", was, "now", swapped.Digest,
		"tools", len(swapped.Defs), "etag", etag)
	return Swapped
}

func (p *Poller) serving() string {
	if c := p.Store.Current(); c != nil {
		return c.Digest
	}
	return "none"
}

// Interface assertions, here rather than in the daemon: these are the
// implementations this package is written for, and a signature change should
// break the build in the package that cares.
var (
	_ Registries = (*authn.Swappable)(nil)
	_ Object     = (*catalogue.S3Source)(nil)
)
