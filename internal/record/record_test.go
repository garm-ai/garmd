package record_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/garm-ai/garm/contracts/ledger"

	"github.com/garm-ai/garmd/internal/record"
)

func TestMemoryKeepsEveryEventInOrder(t *testing.T) {
	var m record.Memory
	for _, tenant := range []string{"first", "second", "third"} {
		m.Record(context.Background(), ledger.Event{Tenant: tenant})
	}

	got := m.Events()
	if len(got) != 3 {
		t.Fatalf("recorded %d events, want 3", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Tenant != want {
			t.Errorf("event %d is %q, want %q; a recorder that reorders makes a "+
				"ledger useless for reconstructing what happened", i, got[i].Tenant, want)
		}
	}
}

// Events hands back a copy. A caller that could mutate the recorder's own
// slice would be editing the record of what happened, which is the one thing
// a ledger must not allow — and in a test it would make a later assertion
// pass against evidence an earlier one changed.
func TestEventsCannotBeEditedThroughWhatItReturns(t *testing.T) {
	var m record.Memory
	m.Record(context.Background(), ledger.Event{Tenant: "acme"})

	got := m.Events()
	got[0].Tenant = "someone-else"

	if again := m.Events(); again[0].Tenant != "acme" {
		t.Errorf("the recorded event became %q after a caller edited the returned "+
			"slice", again[0].Tenant)
	}
}

// The chain records from whatever goroutine a call is on, so concurrent
// Records must not lose one or race. -race is what makes this test worth
// having; without it, it passes on a broken implementation.
func TestConcurrentRecordsAreAllKept(t *testing.T) {
	var m record.Memory
	var wg sync.WaitGroup
	const writers = 16
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Record(context.Background(), ledger.Event{Tenant: "acme"})
		}()
	}
	// Reading while writing, because Events is called from a test goroutine
	// while the chain is still recording.
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.Events()
	}()
	wg.Wait()

	if n := len(m.Events()); n != writers {
		t.Errorf("kept %d of %d concurrent events", n, writers)
	}
}

func logged(t *testing.T, ev ledger.Event) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	record.NewSlog(slog.New(slog.NewJSONHandler(&buf, nil))).Record(context.Background(), ev)

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("the degraded recorder did not emit JSON: %v (%q)", err, buf.String())
	}
	return got
}

// Without a database the event still has to leave the process, flagged so
// that nobody mistakes a log line for a ledger row. A degraded mode that
// looked identical to the real one would be discovered at an audit.
func TestTheDegradedRecorderFlagsThatNothingWasLedgered(t *testing.T) {
	got := logged(t, ledger.Event{
		Tenant:  "acme",
		Outcome: ledger.OutcomeOK,
		Usage:   ledger.Usage{InputTokens: 11, OutputTokens: 22},
	})

	if got["unledgered"] != true {
		t.Error("the line is not flagged unledgered, so it reads as a ledger row")
	}
	if got["msg"] != "garm.usage" {
		t.Errorf("msg = %v, want garm.usage; the collector selects on it", got["msg"])
	}
	if got["tenant"] != "acme" {
		t.Errorf("tenant = %v, want acme", got["tenant"])
	}
	if got["input_tokens"] != float64(11) || got["output_tokens"] != float64(22) {
		t.Errorf("usage did not survive: %v / %v", got["input_tokens"], got["output_tokens"])
	}
}

// An empty list of violations is [] and not null. The e2e asserts the exact
// JSON, and a consumer iterating the field would have to special-case null
// for no reason other than Go's zero value.
func TestNoPolicyViolationsIsAnEmptyListNotNull(t *testing.T) {
	got := logged(t, ledger.Event{Tenant: "acme"})

	v, present := got["policy_violations"]
	if !present {
		t.Fatal("policy_violations is absent")
	}
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("policy_violations = %v (%T), want an empty list", v, v)
	}
	if len(list) != 0 {
		t.Errorf("policy_violations = %v, want empty", list)
	}
}

// The tool attribution block is written only for a tool call. A generation
// call carrying empty clearance and depth-zero fields would look like a tool
// call that governed nothing, which is exactly the wrong thing to read in an
// audit.
func TestToolAttributionIsWrittenOnlyForAToolCall(t *testing.T) {
	generation := logged(t, ledger.Event{Tenant: "acme", Alias: "fast"})
	for _, field := range []string{"tool", "principal_subject", "chain_depth",
		"clearance_effective", "redaction_count"} {
		if _, present := generation[field]; present {
			t.Errorf("a call with no tool wrote %q, which reads as a governed call "+
				"that governed nothing", field)
		}
	}

	toolCall := logged(t, ledger.Event{
		Tenant:                "acme",
		Tool:                  "t.v1.get_status",
		PrincipalSubject:      "user:1",
		PrincipalKind:         "user",
		ChainDepth:            2,
		ClearanceEffective:    "CLEARANCE_INTERNAL",
		CompartmentsEffective: []string{"finance"},
		RedactionPlan:         "sha256:plan",
		RedactionCount:        3,
		DisclosedCount:        4,
	})
	for field, want := range map[string]any{
		"tool":                "t.v1.get_status",
		"principal_subject":   "user:1",
		"principal_kind":      "user",
		"chain_depth":         float64(2),
		"redaction_count":     float64(3),
		"disclosed_count":     float64(4),
		"redaction_plan":      "sha256:plan",
		"clearance_effective": "CLEARANCE_INTERNAL",
	} {
		if toolCall[field] != want {
			t.Errorf("%s = %v, want %v", field, toolCall[field], want)
		}
	}
}

// TestACancelledRequestStillRecords. A call that was cancelled is exactly the
// one an audit asks about later, and a recorder that dropped it would leave
// no trace of the calls most worth tracing.
func TestACancelledRequestStillRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	record.NewSlog(slog.New(slog.NewJSONHandler(&buf, nil))).
		Record(ctx, ledger.Event{Tenant: "acme", Outcome: ledger.OutcomeInterrupted})

	if buf.Len() == 0 {
		t.Fatal("a cancelled call recorded nothing")
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["outcome"] != string(ledger.OutcomeInterrupted) {
		t.Errorf("outcome = %v, want %v", got["outcome"], ledger.OutcomeInterrupted)
	}
}
