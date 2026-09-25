package serve

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// plane pairs a catalogue generation with the governance chain built for it.
//
// The Core is not state that sits beside the catalogue; it is DERIVED from
// it. The compartment declarations the chain decides with, the tools it will
// admit, and the policy plan compiled for every message all come out of the
// generation. A Core outliving its catalogue would be enforcing the previous
// generation's policy over the current generation's tools — the precise
// disagreement that making a generation immutable exists to prevent.
//
// So the two are replaced together or not at all, and a request that has read
// one has read both.
type plane struct {
	cat  *catalogue.Catalogue
	core *toolplane.Core
}

// planeFor returns the chain for this generation, building it on first sight.
//
// Generations are immutable and swapped whole, so pointer identity is an
// exact test for "the one I already built for" — no digest comparison, and no
// way for two generations to share an answer.
//
// It is lazy rather than built at boot because the catalogue reloads. A
// handler that could only ever chain the generation it started with would
// route the new tools through the old policy, which is worse than not
// reloading at all.
func (h *Handler) planeFor(cat *catalogue.Catalogue) (*plane, error) {
	if p := h.plane.Load(); p != nil && p.cat == cat {
		return p, nil
	}

	// Build under a lock, so a reload does not set every in-flight request
	// compiling the same plans. The load is repeated inside it: by the time a
	// waiter takes the lock the first holder has usually already published.
	h.buildMu.Lock()
	defer h.buildMu.Unlock()
	if p := h.plane.Load(); p != nil && p.cat == cat {
		return p, nil
	}

	p, err := h.newPlane(cat)
	if err != nil {
		return nil, err
	}
	h.plane.Store(p)
	return p, nil
}

// Prepare builds the chain for a generation up front, so a catalogue this
// deployment cannot govern is a startup failure.
//
// Without it the lazy build turns that refusal into a process that binds
// cleanly and answers 503 to everything — which reads as healthy to an
// orchestrator, rolls out across every replica, and is discovered by a
// caller. A tool declaring supervision nobody will apply is exactly what
// AddTools refuses, and the refusal is worth nothing if it arrives one
// request at a time after the deploy is green.
func (h *Handler) Prepare(cat *catalogue.Catalogue) error {
	_, err := h.planeFor(cat)
	return err
}

func (h *Handler) newPlane(cat *catalogue.Catalogue) (*plane, error) {
	core, err := toolplane.NewCore(toolplane.CoreConfig{
		HashKey: h.HashKey,
		// From the catalogue, not from this binary's configuration. Which
		// compartments exist is a property of the tools on offer and changes
		// when they do: an enterprise defines its own taxonomy and ships it
		// in the artifact.
		Compartments: cat.Compartments,
		Recorder:     h.Recorder,
		Audit:        h.Audit,
	})
	if err != nil {
		return nil, fmt.Errorf("building the chain for catalogue %s: %w", cat.Digest, err)
	}
	if err := core.AddTools(cat.Defs); err != nil {
		return nil, fmt.Errorf("mounting catalogue %s: %w", cat.Digest, err)
	}
	for _, d := range cat.Defs {
		if err := core.Register(d.FullMethod, requestFactory(d.Input), h.resolverFor(d)); err != nil {
			return nil, fmt.Errorf("registering %s: %w", d.FullMethod, err)
		}
	}
	return &plane{cat: cat, core: core}, nil
}

// requestFactory builds an empty request from the catalogue's descriptor.
// This binary has never seen the type and does not need to.
func requestFactory(md protoreflect.MessageDescriptor) func() proto.Message {
	return func() proto.Message { return dynamicpb.NewMessage(md) }
}

// resolverFor makes the network hop into step 6's resolver.
//
// The chain was written when a resolver was an in-process function, where a
// failure is the tool's failure. Over a hop there is a third outcome — the
// tool is declared and nothing is serving it — and that one is an operator's
// problem, not the caller's.
//
// The transport's sentinel is returned unwrapped so it reaches the surface as
// itself. The chain records the text and returns the error unchanged, and the
// surface is what turns "nobody answered" into a 503 rather than a 500 that
// would send someone to read handler code that is working fine.
func (h *Handler) resolverFor(d tool.Def) toolplane.ResolverFunc {
	return func(ctx context.Context, req proto.Message) (proto.Message, error) {
		resp := dynamicpb.NewMessage(d.Output)
		if err := h.Invoker.Invoke(ctx, d.FullMethod, req, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
}
