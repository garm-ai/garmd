package serve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// errNoCredential is what a PrincipalFunc returns when the request carried no
// bearer token. Spelled here rather than inline so the three tests that need
// an unauthenticated call cannot drift apart on what "no credential" means.
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

// Nothing outside the chain may name a row. A surface that could write an id
// of its own would be a second, unaudited author of the ledger's join key.
func TestAnIdIsOnlyEverTheOneTheChainMinted(t *testing.T) {
	var id string
	ctx := toolplane.WithEventID(context.Background(), &id)
	if got := toolplane.EventIDForTest(ctx); got != "" {
		t.Errorf("an id appeared before any call was made: %q", got)
	}
}
