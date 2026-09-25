package serve

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

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

	services, err := r.Discoverer.Services(ctx)
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
		pkgOf[strings.ReplaceAll(strings.TrimPrefix(d.FullMethod, "/"), "/", ".")] = pkgOfFQN(d.FQN)
	}

	bad := map[string]string{}
	seen := map[string]bool{}
	for _, svc := range services {
		for _, subject := range svc.Subjects {
			pkg, known := pkgOf[subject]
			if !known {
				// Something is serving a subject this catalogue does not
				// declare. Not this daemon's business to route, and not a
				// reason to quarantine anything it does serve.
				continue
			}
			seen[pkg] = true

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

	r.mu.Lock()
	prev := r.quarantined
	r.quarantined, r.seen, r.last = bad, seen, time.Now()
	r.mu.Unlock()

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
