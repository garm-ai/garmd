package serve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// errNoCredential is what a PrincipalFunc returns when the request carried no
// bearer token. Named rather than spelled inline at each use so the tests that
// need an unauthenticated call cannot drift apart on what "no credential"
// means — govern_test.go asserts the text never reaches the caller, and the
// test below asserts the refusal still gets a ledger row.
var errNoCredential = errors.New("no bearer token on the request")

// The ledger holds the whole story of a call and the caller holds none of it.
// Without the id on the response, joining a caller's own step record to the
// row that explains it means correlating on a timestamp, which stops working
// the moment two calls land in the same second.
func TestASuccessfulAnswerCarriesTheLedgerEventId(t *testing.T) {
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &fakeInvoker{fill: "x"},
		Recorder: rec,
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	got := w.Header().Get(EventHeader)
	if got == "" {
		t.Fatal("no Garm-Event-Id; the caller cannot join its step to the ledger row")
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q and the row is %q; the header names a row "+
			"that does not exist", got, events[0].ID)
	}
}

// The refused calls are the rows an auditor queries, so the refusal is where
// the id matters most — and a refusal is exactly where a caller has the least
// to go on.
func TestARefusalCarriesTheIdOfItsOwnLedgerRow(t *testing.T) {
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &fakeInvoker{fill: "x"},
		Recorder: rec,
		Principals: principalFunc(&toolplane.Principal{
			Subject:   "user:under-cleared",
			Clearance: toolv1.Clearance_CLEARANCE_PUBLIC,
			Verbs:     toolplane.NewVerbSet(toolv1.Verb_VERB_READ),
		}),
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if got := w.Header().Get(EventHeader); got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q, want %q", got, events[0].ID)
	}
}

// Step 1's own failure is ledgered through the chain rather than written
// straight out, so it has a row like any other outcome — and therefore an id.
func TestAnUnauthenticatedCallCarriesTheIdOfItsLedgerRow(t *testing.T) {
	rec := &record.Memory{}
	h := &Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &fakeInvoker{fill: "x"},
		HashKey:  []byte("a test hash key"),
		Recorder: rec,
		Principals: func(ctx context.Context) (*toolplane.Principal, error) {
			return nil, errNoCredential
		},
	}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if got := w.Header().Get(EventHeader); got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q, want %q", got, events[0].ID)
	}
}

// A route this build does not serve is refused by the catalogue, before the
// chain, so there is no row — and a header naming a row that does not exist
// would be worse than no header at all.
func TestARouteWithNoLedgerRowCarriesNoEventId(t *testing.T) {
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &fakeInvoker{fill: "x"},
		Recorder: rec,
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, "/t.v1.S/Nope", strings.NewReader("")))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(EventHeader); got != "" {
		t.Errorf("Garm-Event-Id = %q for a call that produced no ledger row", got)
	}
}

// panickingInvoker stands in for a resolver that comes apart. The chain's own
// recover is what turns that into a row and an answer, and this is the only
// way to reach it from the surface.
type panickingInvoker struct{ with any }

func (p *panickingInvoker) Invoke(_ context.Context, _ string, _, _ proto.Message) error {
	panic(p.with)
}

// The id has to survive the one path that does not return normally.
//
// The chain notes the id where the row is opened, before the resolver is
// reached, precisely so a resolver that panics is still a row the caller can
// find. An id noted after the resolver returned would be correct on every
// path a test bothers to write and missing on the one anybody would actually
// be debugging.
func TestAPanickingResolverStillCarriesTheIdOfItsRow(t *testing.T) {
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &panickingInvoker{with: "the resolver came apart"},
		Recorder: rec,
	})

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if got := w.Header().Get(EventHeader); got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q, want %q: a panic is exactly the row "+
			"someone will go looking for", got, events[0].ID)
	}
}

// http.ErrAbortHandler is a deliberate "write nothing", and the row is still
// owed.
//
// The two halves are separate promises. The ledger must see the call, because
// a connection dropped mid-call is a security-relevant outcome like any
// other; and the response must stay empty, because the whole meaning of
// ErrAbortHandler is that net/http drops the connection without answering.
// A header set on the way past would be this surface answering a request the
// handler decided not to answer.
func TestAnAbortedConnectionRecordsItsRowAndAnswersNothing(t *testing.T) {
	rec := &record.Memory{}
	h := chained(&Handler{
		Store:    &countingStore{c: aCatalogue()},
		Invoker:  &panickingInvoker{with: http.ErrAbortHandler},
		Recorder: rec,
	})

	w := httptest.NewRecorder()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))
	}()

	// Re-raised rather than converted: net/http is the only thing that may
	// decide what an aborted connection means.
	if recovered != http.ErrAbortHandler { //nolint:errorlint // net/http compares with ==, so we do too
		t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
	}
	if len(rec.Events()) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1: an aborted call still happened",
			len(rec.Events()))
	}
	if got := w.Header().Get(EventHeader); got != "" {
		t.Errorf("Garm-Event-Id = %q on a connection that was deliberately "+
			"never answered", got)
	}
	if w.Body.Len() != 0 {
		t.Errorf("wrote %q to a connection net/http is about to drop", w.Body.String())
	}
}
