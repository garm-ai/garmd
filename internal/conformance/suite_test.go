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

// A case must assert exactly one thing. Three kinds now (a folded
// Principal, a refusal, an approval grant) and the "exactly one" rule is
// what keeps a malformed suite from failing OPEN: a case that asserts
// nothing passes, and a suite of such cases reports success while checking
// nothing.
func TestLoadSuiteRequiresExactlyOneAssertionPerCase(t *testing.T) {
	for name, body := range map[string]string{
		"none of the three": `{"name":"x","mint":{"a":"b"}}`,
		"expect and mintError": `{"name":"x","mint":{"a":"b"},"mintError":true,
			"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"}}`,
		"expect and grant": `{"name":"x","mint":{"a":"b"},
			"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC"},
			"grant":{"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
		"mintError and grant": `{"name":"x","mint":{"a":"b"},"mintError":true,
			"grant":{"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCase(t, body); err == nil {
				t.Fatal("LoadSuite accepted a case asserting none or several things")
			}
		})
	}
}

// A grant case carries no mint params — it drives a different endpoint
// entirely — so the "asks the minter for nothing" rule must not apply to
// it, and its own required fields must be checked instead.
func TestLoadSuiteValidatesAGrantCase(t *testing.T) {
	good := `{"name":"x","grant":{"tool":"payments.v1.initiate_payment",
		"subject":"customer:C-8123","approver":"jdoe","approverClearance":"RESTRICTED",
		"expectApprover":"employee:jdoe","material":{"amount_minor_units":"25000"}}}`
	if _, err := loadCase(t, good); err != nil {
		t.Fatalf("LoadSuite refused a well-formed grant case: %v", err)
	}

	for name, body := range map[string]string{
		"no tool":            `{"name":"x","grant":{"subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
		"no subject":         `{"name":"x","grant":{"tool":"a.b","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
		"no approver":        `{"name":"x","grant":{"tool":"a.b","subject":"customer:C","expectApprover":"employee:jdoe"}}`,
		"no expectApprover":  `{"name":"x","grant":{"tool":"a.b","subject":"customer:C","approver":"jdoe"}}`,
		"malformed material": `{"name":"x","grant":{"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe","material":{"a=b":"1"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadCase(t, body); err == nil {
				t.Fatalf("LoadSuite accepted a grant case with %s", name)
			}
		})
	}
}

// `execution` is a field of Expect like any other, so a suite naming it must
// load. Without this the whole exchange-2 half of the sts suite is refused by
// DisallowUnknownFields before a single token is minted.
func TestLoadSuiteReadsAnExpectedExecution(t *testing.T) {
	body := `{"name":"x","mint":{"a":"b"},
		"expect":{"subject":"employee:jdoe","clearance":"CLEARANCE_INTERNAL",
		          "execution":"runner:conformance-client"}}`
	s, err := loadCase(t, body)
	if err != nil {
		t.Fatalf("LoadSuite refused a case naming an expected execution: %v", err)
	}
	if got := s.Cases[0].Expect.Execution; got != "runner:conformance-client" {
		t.Fatalf("expect.execution = %q, want runner:conformance-client", got)
	}
}

// loadCase wraps one case body in a minimal suite, so these tests read as the
// case they are about rather than as a suite header repeated five times.
func loadCase(t *testing.T, caseJSON string) (*conformance.Suite, error) {
	t.Helper()
	return conformance.LoadSuite(write(t, `{"issuer":"https://sts.example",`+
		`"audience":"garm://garmd","cases":[`+caseJSON+`]}`))
}

// The suites this repository SHIPS must load. Nothing else loads them in an
// ordinary `go test ./...`: the run that reads them is behind
// -tags conformance and needs two live services, and the CI job that starts
// those is skipped on a pull request from a fork. Without this, a misspelled
// key or an undeclared compartment in suites/*.json is caught by nobody
// until a maintainer's own build — which, for the one kind of file whose
// whole job is to be checked, is too late.
func TestTheShippedSuitesLoad(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("suites", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no suites found; this test would pass while checking nothing")
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			if _, err := conformance.LoadSuite(p); err != nil {
				t.Fatalf("a suite this repository ships does not load: %v", err)
			}
		})
	}
}
