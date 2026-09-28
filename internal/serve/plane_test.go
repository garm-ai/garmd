package serve

import (
	"testing"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
)

// A reload pre-flights a candidate before the store swaps, and the candidate
// is a generation NOTHING is serving yet. Building its chain must not publish
// it: every request arriving in the window between the pre-flight and the swap
// reads the generation still current, and would find the cached plane belonging
// to a different one — so each of them would rebuild the outgoing chain,
// compiling every plan in the artifact, for as long as the pre-flight took.
func TestCheckDoesNotPublishTheChainOfAGenerationNothingIsServing(t *testing.T) {
	serving := aCatalogue()
	h := chained(&Handler{Store: &countingStore{c: serving}, Invoker: &fakeInvoker{}})
	if err := h.Prepare(serving); err != nil {
		t.Fatalf("the generation being served would not prepare: %v", err)
	}

	candidate := aCatalogue()
	candidate.Digest = "sha256:candidate"
	if err := h.Check(candidate); err != nil {
		t.Fatalf("a governable candidate was refused: %v", err)
	}

	if p := h.plane.Load(); p == nil || p.cat != serving {
		t.Error("the pre-flight published the chain of a generation nothing is serving")
	}
}

// Check still REFUSES what Prepare would refuse — it is the same build, minus
// the publication. A pre-flight that only built the easy half would let a
// catalogue this deployment cannot govern become current.
func TestCheckRefusesWhatCannotBeGoverned(t *testing.T) {
	cat := aCatalogue()
	cat.Defs[0].ApprovalMode = toolv1.Approval_MODE_GRANT

	h := chained(&Handler{Store: &countingStore{c: aCatalogue()}, Invoker: &fakeInvoker{}})
	if err := h.Check(cat); err == nil {
		t.Fatal("a tool declaring MODE_GRANT passed the pre-flight with no GrantVerifier")
	}
}

// Two requests can straddle a reload: one that read the previous generation
// reaches the plane cache after the new one has been published. Storing its
// chain there would put the OUTGOING generation back, and every request after
// it would rebuild — the pair flipping for as long as the old requests kept
// arriving.
//
// Generations are ordered by when they were loaded, so a builder that is
// behind uses the plane it built and does not publish it.
func TestAStalePlaneIsNotPublishedOverTheGenerationNowServing(t *testing.T) {
	was := aCatalogue()
	was.Digest = "sha256:was"
	was.LoadedAt = time.Now().Add(-time.Minute)

	now := aCatalogue()
	now.Digest = "sha256:now"
	now.LoadedAt = time.Now()

	h := chained(&Handler{Store: &countingStore{c: now}, Invoker: &fakeInvoker{}})
	if err := h.Prepare(now); err != nil {
		t.Fatalf("the generation now serving would not prepare: %v", err)
	}

	// The straggler: a request that took `was` before the swap.
	stale, err := h.planeFor(was)
	if err != nil {
		t.Fatalf("the previous generation's chain would not build: %v", err)
	}
	if stale.cat != was {
		t.Fatal("the straggler was handed a chain for a generation it did not read")
	}
	if p := h.plane.Load(); p == nil || p.cat != now {
		t.Error("a request on the outgoing generation published its chain over the " +
			"generation now serving")
	}
}
