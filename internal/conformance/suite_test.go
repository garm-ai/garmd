package conformance_test

import (
	"fmt"
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
                "verbs": ["VERB_READ", "VERB_WRITE"],
                "tenant": "bank", "chain": ["user:alice"]}}
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
	                    "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC","tenant":"t","chain":["s"],
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
	                    "expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC","tenant":"t","chain":["s"],
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

// A case must assert exactly one thing. Four kinds now (a folded
// Principal, a refusal, an approval grant, an approval refusal) and the "exactly one" rule is
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
		"toolApproverMinClearance":"RESTRICTED","toolMaxGrantAgeSeconds":900,
		"expectApprover":"employee:jdoe","material":{"amount_minor_units":"25000"}}}`
	if _, err := loadCase(t, good); err != nil {
		t.Fatalf("LoadSuite refused a well-formed grant case: %v", err)
	}

	// declared is the complete tool declaration every grant case must carry,
	// factored out so each entry below is about the ONE field it omits.
	const declared = `"approverClearance":"RESTRICTED","toolApproverMinClearance":"RESTRICTED",` +
		`"toolMaxGrantAgeSeconds":900,`
	for name, body := range map[string]string{
		"no tool":            `{"name":"x","grant":{` + declared + `"subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
		"no subject":         `{"name":"x","grant":{` + declared + `"tool":"a.b","approver":"jdoe","expectApprover":"employee:jdoe"}}`,
		"no approver":        `{"name":"x","grant":{` + declared + `"tool":"a.b","subject":"customer:C","expectApprover":"employee:jdoe"}}`,
		"no expectApprover":  `{"name":"x","grant":{` + declared + `"tool":"a.b","subject":"customer:C","approver":"jdoe"}}`,
		"malformed material": `{"name":"x","grant":{` + declared + `"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe","material":{"a=b":"1"}}}`,
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
		          "tenant":"acme","chain":["employee:jdoe"],
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

// A misspelled clearance must fail the LOAD, not become UNSPECIFIED.
//
// This is the one typo in a grant case that fails OPEN. `toolApproverMinClearance`
// becomes the ToolDef's ApproverMinClearance, and grants.Verifier skips the
// approver-seniority check entirely when that is UNSPECIFIED — so
// "RESTRICTD" would produce a case that mints a grant, verifies it without
// ever judging the approver, and reports ok. The same reasoning applies to
// `approverClearance`, which is what the approver's token is minted with: a
// misspelling there silently asks the upstream IdP for its default.
func TestLoadSuiteRejectsAMisspelledClearanceOnAGrantCase(t *testing.T) {
	for _, field := range []string{"approverClearance", "toolApproverMinClearance"} {
		for _, spelling := range []string{"RESTRICTD", "UNSPECIFIED", "CLEARANCE_UNSPECIFIED", ""} {
			t.Run(field+"="+spelling, func(t *testing.T) {
				body := fmt.Sprintf(`{"name":"x","grant":{"tool":"a.b","subject":"customer:C",
					"approver":"jdoe","expectApprover":"employee:jdoe",
					"approverClearance":%q,"toolApproverMinClearance":%q,
					"toolMaxGrantAgeSeconds":900}}`,
					valueFor(field, "approverClearance", spelling, "RESTRICTED"),
					valueFor(field, "toolApproverMinClearance", spelling, "RESTRICTED"))
				err := loadCaseErr(t, body)
				if err == nil {
					t.Fatalf("LoadSuite accepted %s=%q; an unknown clearance is UNSPECIFIED, "+
						"and UNSPECIFIED skips the approver check altogether", field, spelling)
				}
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("the error must name %s as the offending field, got: %v", field, err)
				}
			})
		}
	}
}

// valueFor returns bad for the field under test and good for the other, so one
// table drives both fields without a case ever being wrong in two places at once.
func valueFor(under, field, bad, good string) string {
	if under == field {
		return bad
	}
	return good
}

// A tool that declares no ceiling has no age this plane can enforce:
// grants.Verifier skips the age check when MaxGrantAge is zero, so a grant
// case without one asserts that an approval of ANY age is accepted. Same
// fail-open shape as the clearance above, and the same answer.
func TestLoadSuiteRequiresAGrantCaseToDeclareItsToolsCeilings(t *testing.T) {
	for name, body := range map[string]string{
		"no max grant age": `{"name":"x","grant":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","expectApprover":"employee:jdoe",
			"approverClearance":"RESTRICTED","toolApproverMinClearance":"RESTRICTED"}}`,
		"a negative max grant age": `{"name":"x","grant":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","expectApprover":"employee:jdoe",
			"approverClearance":"RESTRICTED","toolApproverMinClearance":"RESTRICTED",
			"toolMaxGrantAgeSeconds":-1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := loadCaseErr(t, body)
			if err == nil {
				t.Fatal("LoadSuite accepted a grant case declaring no age ceiling; " +
					"the verifier skips the age check entirely without one")
			}
			if !strings.Contains(err.Error(), "toolMaxGrantAgeSeconds") {
				t.Fatalf("the error must name toolMaxGrantAgeSeconds, got: %v", err)
			}
		})
	}
}

func loadCaseErr(t *testing.T, caseJSON string) error {
	t.Helper()
	_, err := loadCase(t, caseJSON)
	return err
}

// F12b. `tenant` and `chain` are asserted UNCONDITIONALLY by compare, so a
// case that omits either is not asserting "any tenant" or "any chain" — it
// is asserting nothing about the field that confines a caller to their own
// organisation's data, or about every hop the fold walked. Same fail-open
// shape as subject and clearance, and the same answer: refuse the load.
func TestLoadSuiteRequiresTenantAndChainOnAnExpectation(t *testing.T) {
	for name, tc := range map[string]struct{ body, names string }{
		"no tenant": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","clearance":"CLEARANCE_PUBLIC",
			          "chain":["user:alice"]}}`, "tenant"},
		"no chain": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","clearance":"CLEARANCE_PUBLIC",
			          "tenant":"bank"}}`, "chain"},
		"empty chain": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","clearance":"CLEARANCE_PUBLIC",
			          "tenant":"bank","chain":[]}}`, "chain"},
		"chain does not start with the subject": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","clearance":"CLEARANCE_PUBLIC",
			          "tenant":"bank","chain":["user:bob"]}}`, "chain"},
		"a direct chain but an actor named": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","actor":"agent:bot","clearance":"CLEARANCE_PUBLIC",
			          "tenant":"bank","chain":["user:alice"]}}`, "chain"},
		"a delegated chain whose last hop is not the actor": {`{"name":"x","mint":{"user":"x"},
			"expect":{"subject":"user:alice","actor":"agent:bot","clearance":"CLEARANCE_PUBLIC",
			          "tenant":"bank","chain":["user:alice","agent:other"]}}`, "chain"},
	} {
		t.Run(name, func(t *testing.T) {
			err := loadCaseErr(t, tc.body)
			if err == nil {
				t.Fatal("LoadSuite accepted an expectation that would pass for any " + tc.names)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("the error must name %s, got: %v", tc.names, err)
			}
		})
	}
}

func TestLoadSuiteReadsTenantAndChain(t *testing.T) {
	body := `{"name":"x","mint":{"a":"b"},
		"expect":{"subject":"employee:jdoe","actor":"agent:order-assistant",
		          "clearance":"CLEARANCE_INTERNAL","tenant":"acme",
		          "chain":["employee:jdoe","agent:order-assistant"]}}`
	s, err := loadCase(t, body)
	if err != nil {
		t.Fatalf("LoadSuite refused a case naming tenant and chain: %v", err)
	}
	e := s.Cases[0].Expect
	if e.Tenant != "acme" {
		t.Fatalf("expect.tenant = %q, want acme", e.Tenant)
	}
	if len(e.Chain) != 2 || e.Chain[0] != "employee:jdoe" || e.Chain[1] != "agent:order-assistant" {
		t.Fatalf("expect.chain = %v, want [employee:jdoe agent:order-assistant]", e.Chain)
	}
}

// F12a. A grantError case drives POST /approve and asserts the STS REFUSES.
// It carries no mint params and no tool declaration — there is no grant to
// judge — so its own required fields are checked instead, and for the same
// reason a grant case's are: a refusal case is satisfied by ANY refusal, so
// the request must at least be well-formed enough that the refusal is for
// the reason the case names rather than for a field it forgot.
func TestLoadSuiteValidatesAGrantErrorCase(t *testing.T) {
	for name, body := range map[string]string{
		"a customer identity as approver": `{"name":"x","grantError":{"tool":"payments.v1.initiate_payment",
			"subject":"customer:C-8123","approver":"customer:C-8123","approverClearance":"RESTRICTED",
			"material":{"amount_minor_units":"25000"}}}`,
		"a delegated approver": `{"name":"x","grantError":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","approverClearance":"RESTRICTED","approverActor":"agent:order-assistant"}}`,
		// The whole point of this one is that the path is malformed, so the
		// loader must NOT apply the grant case's ValidPath rule here.
		"a malformed material path": `{"name":"x","grantError":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","approverClearance":"RESTRICTED","material":{"amount=minor":"25000"}}}`,
		"no client assertion": `{"name":"x","grantError":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","approverClearance":"RESTRICTED","omitClientAssertion":true}}`,
	} {
		t.Run("loads: "+name, func(t *testing.T) {
			s, err := loadCase(t, body)
			if err != nil {
				t.Fatalf("LoadSuite refused a well-formed grantError case: %v", err)
			}
			if s.Cases[0].GrantError == nil {
				t.Fatal("the case loaded with no grantError block")
			}
		})
	}

	const declared = `"approverClearance":"RESTRICTED",`
	for name, tc := range map[string]struct{ body, names string }{
		"no tool":     {`{"name":"x","grantError":{` + declared + `"subject":"customer:C","approver":"jdoe"}}`, "tool"},
		"no subject":  {`{"name":"x","grantError":{` + declared + `"tool":"a.b","approver":"jdoe"}}`, "subject"},
		"no approver": {`{"name":"x","grantError":{` + declared + `"tool":"a.b","subject":"customer:C"}}`, "approver"},
		// A misspelled clearance asks the upstream IdP for its default, and
		// the STS then refuses "no usable authority" — a refusal, so the
		// case passes, for a reason that has nothing to do with its name.
		"misspelled approverClearance": {`{"name":"x","grantError":{"approverClearance":"RESTRICTD",
			"tool":"a.b","subject":"customer:C","approver":"jdoe"}}`, "approverClearance"},
		"no approverClearance": {`{"name":"x","grantError":{"tool":"a.b","subject":"customer:C","approver":"jdoe"}}`, "approverClearance"},
		// DisallowUnknownFields: a grant case's field on a grantError case
		// is a case that says it checks something it cannot.
		"expectApprover on a refusal case": {`{"name":"x","grantError":{` + declared +
			`"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe"}}`, "expectApprover"},
		// And the mirror: a refusal knob on a grant case is a case that
		// would fail at mint for a reason it never states.
		"approverActor on a grant case": {`{"name":"x","grant":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","expectApprover":"employee:jdoe","approverClearance":"RESTRICTED",
			"toolApproverMinClearance":"RESTRICTED","toolMaxGrantAgeSeconds":900,
			"approverActor":"agent:bot"}}`, "approverActor"},
		"omitClientAssertion on a grant case": {`{"name":"x","grant":{"tool":"a.b","subject":"customer:C",
			"approver":"jdoe","expectApprover":"employee:jdoe","approverClearance":"RESTRICTED",
			"toolApproverMinClearance":"RESTRICTED","toolMaxGrantAgeSeconds":900,
			"omitClientAssertion":true}}`, "omitClientAssertion"},
	} {
		t.Run("refuses: "+name, func(t *testing.T) {
			err := loadCaseErr(t, tc.body)
			if err == nil {
				t.Fatalf("LoadSuite accepted a case with %s", name)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("the error must name %s, got: %v", tc.names, err)
			}
		})
	}
}

// The "exactly one" rule extends to the fourth kind.
func TestLoadSuiteRequiresExactlyOneAssertionWithGrantError(t *testing.T) {
	const ge = `"grantError":{"tool":"a.b","subject":"customer:C","approver":"jdoe","approverClearance":"RESTRICTED"}`
	for name, body := range map[string]string{
		"grantError and grant": `{"name":"x",` + ge + `,
			"grant":{"tool":"a.b","subject":"customer:C","approver":"jdoe","expectApprover":"employee:jdoe",
			         "approverClearance":"RESTRICTED","toolApproverMinClearance":"RESTRICTED","toolMaxGrantAgeSeconds":900}}`,
		"grantError and mintError": `{"name":"x","mint":{"a":"b"},"mintError":true,` + ge + `}`,
		"grantError and expect": `{"name":"x","mint":{"a":"b"},` + ge + `,
			"expect":{"subject":"s","clearance":"CLEARANCE_PUBLIC","tenant":"t","chain":["s"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := loadCaseErr(t, body); err == nil {
				t.Fatal("LoadSuite accepted a case asserting several things")
			}
		})
	}
}
