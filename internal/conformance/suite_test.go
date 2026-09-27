package conformance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garm-ai/garmd/internal/conformance"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "suite.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `{
  "issuer": "https://garmdev.invalid/idp",
  "audience": "garm",
  "compartments": ["financial", "pii-contact", "support"],
  "cases": [
    {"name": "alice direct", "mint": {"user": "alice"},
     "expect": {"subject": "user:alice", "kind": "PRINCIPAL_KIND_USER",
                "clearance": "CLEARANCE_RESTRICTED",
                "compartments": ["financial", "pii-contact"],
                "verbs": ["VERB_READ", "VERB_WRITE"]}}
  ]
}`

func TestLoadSuiteReadsAValidFile(t *testing.T) {
	s, err := conformance.LoadSuite(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != "https://garmdev.invalid/idp" || s.Audience != "garm" {
		t.Fatalf("header: %+v", s)
	}
	if len(s.Cases) != 1 || s.Cases[0].Name != "alice direct" {
		t.Fatalf("cases: %+v", s.Cases)
	}
	if s.Cases[0].Mint["user"] != "alice" {
		t.Fatalf("mint params: %+v", s.Cases[0].Mint)
	}
	if s.Cases[0].Expect == nil || s.Cases[0].Expect.Clearance != "CLEARANCE_RESTRICTED" {
		t.Fatalf("expect: %+v", s.Cases[0].Expect)
	}
}

func TestLoadSuiteRejectsMalformedSuites(t *testing.T) {
	for name, body := range map[string]string{
		"no issuer":   `{"audience":"garm","compartments":["a"],"cases":[{"name":"x","mint":{"user":"x"},"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		"no audience": `{"issuer":"i","compartments":["a"],"cases":[{"name":"x","mint":{"user":"x"},"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		"no cases":    `{"issuer":"i","audience":"garm","compartments":["a"],"cases":[]}`,
		"unnamed case": `{"issuer":"i","audience":"garm","compartments":["a"],
		                 "cases":[{"mint":{"user":"x"},"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		"neither expect nor mintError": `{"issuer":"i","audience":"garm","compartments":["a"],
		                                 "cases":[{"name":"x","mint":{"user":"x"}}]}`,
		"both expect and mintError": `{"issuer":"i","audience":"garm","compartments":["a"],
		                              "cases":[{"name":"x","mint":{"user":"x"},"mintError":true,
		                                        "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		"expect with no clearance": `{"issuer":"i","audience":"garm","compartments":["a"],
		                             "cases":[{"name":"x","mint":{"user":"x"},"expect":{"subject":"s"}}]}`,
	} {
		if _, err := conformance.LoadSuite(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Review Focus 5. A suite that expects a compartment it never declared is
// asserting something the verifier can never produce — SetLenient would drop
// it — so the suite would pass by agreeing with its own mistake.
func TestLoadSuiteRejectsAnExpectedCompartmentItDoesNotDeclare(t *testing.T) {
	body := `{"issuer":"i","audience":"garm","compartments":["support"],
	          "cases":[{"name":"x","mint":{"user":"x"},
	                    "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC",
	                              "compartments":["support","financial"]}}]}`
	_, err := conformance.LoadSuite(write(t, body))
	if err == nil {
		t.Fatal("accepted a suite expecting an undeclared compartment")
	}
	if !strings.Contains(err.Error(), "financial") {
		t.Fatalf("error must name the offending compartment, got: %v", err)
	}
}

// The mirror rule: a DROPPED compartment must NOT be declared, or it would
// not have been dropped.
func TestLoadSuiteRejectsADroppedCompartmentItDeclares(t *testing.T) {
	body := `{"issuer":"i","audience":"garm","compartments":["support"],
	          "cases":[{"name":"x","mint":{"user":"x"},
	                    "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC",
	                              "dropped":["support"]}}]}`
	if _, err := conformance.LoadSuite(write(t, body)); err == nil {
		t.Fatal("accepted a suite expecting a declared compartment to be dropped")
	}
}

// Fix round 2, minor 5. A case that lost its `mint` block still calls the
// minter, and a minter handed no parameters answers with whatever it
// defaults to — so the case fails, or worse passes, on something other than
// the persona it names.
func TestLoadSuiteRejectsACaseThatAsksTheMinterForNothing(t *testing.T) {
	for name, body := range map[string]string{
		"mint absent": `{"issuer":"i","audience":"garm","compartments":["support"],
		                 "cases":[{"name":"x","expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		"mint empty": `{"issuer":"i","audience":"garm","compartments":["support"],
		                "cases":[{"name":"x","mint":{},
		                          "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}]}`,
		// The rule holds for mintError cases too: a refusal is only
		// meaningful about a request that was actually made.
		"mint absent on a mintError case": `{"issuer":"i","audience":"garm","compartments":["support"],
		                                     "cases":[{"name":"x","mintError":true}]}`,
	} {
		_, err := conformance.LoadSuite(write(t, body))
		if err == nil {
			t.Errorf("%s: accepted a case that asks the minter for nothing", name)
			continue
		}
		if !strings.Contains(err.Error(), "minter for nothing") {
			t.Errorf("%s: the error must say the case asks for nothing, got: %v", name, err)
		}
	}
}

// Fix round 2, minor 7. `subject` is required for the same reason
// `clearance` is: compare asserts it unconditionally, so a case that omits
// one would pass for any identity the minter happened to return.
func TestLoadSuiteRejectsAnExpectationWithNoSubject(t *testing.T) {
	body := `{"issuer":"i","audience":"garm","compartments":["support"],
	          "cases":[{"name":"x","mint":{"user":"x"},
	                    "expect":{"clearance":"CLEARANCE_PUBLIC"}}]}`
	_, err := conformance.LoadSuite(write(t, body))
	if err == nil {
		t.Fatal("accepted an expectation that names no subject")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("the error must name subject as what is missing, got: %v", err)
	}
}
