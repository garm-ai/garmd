package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// Nil is the configured answer, not an oversight. serve.Handler.Audit being
// nil is what makes Prepare refuse a catalogue containing an audited tool, so
// a deployment that forgot to configure an audit stream stops at startup
// rather than serving an audited tool unaudited.
//
// A typed-nil *Sink assigned into the audit.Sink interface would be non-nil
// and defeat every one of those checks silently, which is the failure this
// pins.
func TestWithNoAuditConfigurationTheSinkIsNil(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	recorder, sink, closeRecord, err := records(context.Background(), nil, log, serveOpts{})
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	defer closeRecord()

	if sink != nil {
		t.Error("an audit Sink was built with no audit configuration; a catalogue " +
			"declaring an audited tool would now mount against it")
	}
	if recorder == nil {
		t.Error("no Recorder at all; a call that happened and left no row is the " +
			"failure this design is against")
	}
}
