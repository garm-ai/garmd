package serve

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/garm-ai/contracts/wire"
	"github.com/garm-ai/garmd/internal/transport"
)

// Reconciler compares what is running against what the catalogue declares,
// and quarantines the difference.
//
// This exists because protobuf will not tell you. A service built from a
// different contract does not fail to unmarshal — unknown fields are ignored
// and absent ones defaulted — so it answers, with fields read as something
// else, and the call is authorised, sanitised and ledgered as a success. It
// is the only failure in this design that does not announce itself, which is
// exactly why it gets a mechanism rather than a runbook entry.
//
// The comparison is a string equality on an opaque digest. garmd does not
// interpret what a service advertises; it checks that the two agree. That is
// what lets a runner advertise a bundle digest through the same mechanism
// without garmd learning what a bundle is.
type Reconciler struct {
	Store      Catalogues
	Discoverer transport.Discoverer
	Log        *slog.Logger

	// Interval between sweeps. Discovery is a scatter-gather, so this is a
	// poll rather than a subscription.
	Interval time.Duration

	mu          sync.RWMutex
	quarantined map[string]string // proto package -> why
	seen        map[string]bool   // proto package -> something is serving it
	last        time.Time
}

// Quarantined reports why a package is refused, if it is.
func (r *Reconciler) Quarantined(pkg string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	why, bad := r.quarantined[pkg]
	return why, bad
}

// Run sweeps until ctx is done. The first sweep happens immediately: a
// process that will refuse a mismatched service should refuse it from the
// first request, not from the first tick.
func (r *Reconciler) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	r.sweep(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.sweep(ctx)
		}
	}
}

func (r *Reconciler) sweep(ctx context.Context) {
	cat := r.Store.Current()
	if cat == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	round, err := r.Discoverer.Services(ctx)
	if err != nil {
		// A failed sweep leaves the previous verdict standing rather than
		// clearing it. Discovery being unavailable is not evidence that a
		// mismatched service became correct, and treating it as such would
		// make a quarantine disappear exactly when nobody can check.
		if r.Log != nil {
			r.Log.Warn("discovery sweep failed; previous verdicts stand", "err", err)
		}
		return
	}

	// Which proto package each subject belongs to, from the catalogue rather
	// than by parsing a subject — the catalogue is the authority on what a
	// route is, and a parser would be a second one.
	pkgOf := make(map[string]string, len(cat.Defs))
	for _, d := range cat.Defs {
		// The same function the tool side uses to decide where to listen.
		// Deriving it separately here is how the two ends stop agreeing.
		pkgOf[wire.Subject(d.FullMethod)] = pkgOfFQN(d.FQN)
	}

	bad := map[string]string{}
	seen := map[string]bool{}
	// Which micro service carried each proto package this round, so a
	// package's verdict can be held against the completeness of the round
	// that would have cleared it. A package nothing answered for has no
	// entry, and Round.Complete("") is false unless the enumeration was
	// complete — which is the right answer: if the whole plane was heard and
	// nothing served the package, silence is a verdict.
	pkgService := map[string]string{}
	for _, svc := range round.Services {
		for _, subject := range svc.Subjects {
			pkg, known := pkgOf[subject]
			if !known {
				// Something is serving a subject this catalogue does not
				// declare. Not this daemon's business to route, and not a
				// reason to quarantine anything it does serve.
				continue
			}
			seen[pkg] = true
			pkgService[pkg] = svc.Name

			want := cat.DescriptorHashes[pkg]
			switch {
			case want == "":
				bad[pkg] = fmt.Sprintf("the catalogue records no descriptor hash for %s, "+
					"so nothing can be verified against %s; rebuild it with a garm that stamps one",
					pkg, svc.Name)
			case svc.Identity == "":
				bad[pkg] = fmt.Sprintf("%s advertises no descriptor hash, so it cannot be "+
					"shown to implement %s; it was built with a runtime that does not publish one",
					svc.Name, pkg)
			case svc.Identity != want:
				bad[pkg] = fmt.Sprintf("%s implements a different contract from the catalogue "+
					"for %s (advertises %s, catalogue declares %s)",
					svc.Name, pkg, short(svc.Identity), short(want))
			}
		}
	}

	// A verdict is CLEARED by silence, and silence is only evidence when the
	// round heard the whole plane.
	//
	// This is the half of reconciliation an incomplete round is dangerous
	// for. Quarantining is driven by a positive observation — an instance
	// advertising a hash that does not match — and a reply that never
	// arrived cannot produce one of those. Lifting a quarantine is driven by
	// the absence of that observation, and a reply that never arrived looks
	// exactly like a service that stopped misbehaving. So a round that could
	// not hear everything may ADD a verdict and may not remove one; the
	// instance whose reply went missing may be precisely the one still
	// running the wrong contract.
	//
	// Fail-closed in the direction that costs an operator a stale
	// quarantine, which is visible in the log and fixed by the next complete
	// round, rather than one that silently starts routing to a service
	// nobody has checked.
	r.mu.Lock()
	prev := r.quarantined
	for pkg, why := range prev {
		if _, replaced := bad[pkg]; replaced {
			// This round saw the package again and reached its own verdict,
			// which supersedes whatever stood before.
			continue
		}
		// Round.Complete reports false for every name once the enumeration
		// itself was short, so a plane that could not be enumerated clears
		// nothing at all, and a plane that could clears only the packages
		// whose service was heard in full. A package nothing answered for
		// this round has no service name, and an empty name is complete
		// exactly when the enumeration was: if the whole plane was heard and
		// nothing served the package, silence IS the verdict.
		if !round.Complete(pkgService[pkg]) {
			bad[pkg] = why
		}
	}
	if !round.ConcludesAbsence() {
		for pkg := range r.seen {
			seen[pkg] = true
		}
	}
	r.quarantined, r.seen, r.last = bad, seen, time.Now()
	r.mu.Unlock()

	if r.Log != nil {
		if round.Enumeration != nil {
			r.Log.Warn("discovery could not hear the whole plane; "+
				"no verdict was cleared this sweep", "err", round.Enumeration)
		}
		for name, why := range round.Partial {
			r.Log.Warn("a service was heard only in part; "+
				"its verdict was not cleared this sweep", "service", name, "err", why)
		}
	}

	if r.Log != nil {
		for pkg, why := range bad {
			if prev[pkg] != why {
				r.Log.Error("refusing to route: contract mismatch", "package", pkg, "reason", why)
			}
		}
		for pkg := range prev {
			if _, still := bad[pkg]; !still {
				r.Log.Info("contract mismatch resolved", "package", pkg)
			}
		}
	}
}

func pkgOfFQN(fqn string) string {
	if i := strings.LastIndex(fqn, "."); i >= 0 {
		return fqn[:i]
	}
	return fqn
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
