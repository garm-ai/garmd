package main

import (
	"bytes"

	"github.com/garm-ai/garmd/internal/toolplane"
	"strings"
	"testing"
	"time"
)

// These cover the command surface. That a MODE_GRANT tool refuses without a
// verifier, and mounts with one, is covered where the decision is made —
// internal/toolplane's governance tests and internal/serve's Prepare tests —
// and end to end against a real bank catalogue in garm-ai/examples' CI. What
// is only testable here is the wiring: that the flags reach the seams and that
// a refusal is a non-zero exit rather than a printed warning.

func TestCheckRefusesWithoutACatalogue(t *testing.T) {
	cmd := newCheckCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("check ran with no catalogue; there is nothing to check")
	}
	if !strings.Contains(err.Error(), "--catalogue") {
		t.Errorf("the error does not name the missing flag: %v", err)
	}
}

// A refusal must come back as an error, because cobra turns that into a
// non-zero exit and CI reads nothing else. A check that printed "would not
// mount" and exited zero would be worse than no check: every build green,
// every deploy broken.
func TestAnUnreadableCatalogueIsAnError(t *testing.T) {
	cmd := newCheckCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--catalogue", "/nonexistent/no.binpb"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("a missing catalogue was not an error")
	}
}

// The summary line says what was assumed. Without it a green check is
// unreadable: "this mounts" means nothing until you know what it was checked
// against, and the answer differs per deployment.
func TestTheSummaryNamesWhatWasAssumed(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    checkOpts
		want []string
	}{
		{"nothing", checkOpts{}, []string{"none of the optional steps"}},
		{"grants only", checkOpts{withGrants: true}, []string{"grants"}},
		{"everything", checkOpts{
			withGrants: true, withFGA: true, withNotifier: true,
			auditRetention: 61320 * time.Hour,
		}, []string{"grants", "instance authorization", "notify", "61320h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := describeCapabilities(tc.o)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q does not mention %q", got, w)
				}
			}
		})
	}
}

// Zero retention means NO sink, not an eternal one.
//
// Read the other way round it is the worst possible default: a deployment that
// forgot the flag would claim to keep records forever and mount every audited
// tool in the bank.
func TestZeroRetentionMeansNoSinkRatherThanForever(t *testing.T) {
	if got := describeCapabilities(checkOpts{auditRetention: 0}); strings.Contains(got, "audit") {
		t.Errorf("summary %q claims an audit sink with retention unset", got)
	}
	if got := describeCapabilities(checkOpts{auditRetention: time.Hour}); !strings.Contains(got, "audit") {
		t.Errorf("summary %q omits a configured audit sink", got)
	}
}

// The stand-ins must never be mistaken for implementations.
//
// assumedGrants approves every grant and assumedAudit discards every record.
// Either in a serving path is a catastrophe, so they live in the check command
// and nothing else may reach them. If someone moves one into serve.go, this is
// the test that should have stopped them — and since a test cannot see an
// import that has not happened yet, it asserts the next best thing: that they
// are exactly as inert as their names claim, so nobody mistakes one for a
// partial implementation worth finishing.
func TestTheAssumedSeamsAreInert(t *testing.T) {
	if err := (assumedGrants{}).Verify(t.Context(), nil, toolplane.ToolDef{}); err != nil {
		t.Errorf("assumedGrants refused something; it is a stand-in, not a verifier: %v", err)
	}
	if got := (assumedAudit{retention: time.Hour}).Retention(); got != time.Hour {
		t.Errorf("Retention() = %v, want the configured value — the mount check "+
			"compares against it", got)
	}
}
