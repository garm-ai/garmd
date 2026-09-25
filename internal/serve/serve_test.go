package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/transport"
)

// The handler is tested against fakes rather than against NATS because what
// is under test is which of four answers a caller gets, and that is decided
// before and after the hop rather than during it. The hop itself is covered
// in internal/transport/nats.
//
// The four are deliberately distinct and each one sends a different person to
// a different place, so each is pinned separately below.

const (
	route   = "/t.v1.S/Get"
	fqn     = "t.v1.get_status"
	thePkg  = "t.v1"
	aDigest = "sha256:cafebabe"
)

// message is a stand-in for whatever a catalogue's descriptors declare. Any
// linked message with a scalar field would do: the handler never sees a
// generated type, only a descriptor it builds a dynamicpb message from, and
// this test takes the same route.
func message() protoreflect.MessageDescriptor {
	return (&cataloguev1.Provenance{}).ProtoReflect().Descriptor()
}

func aCatalogue() *catalogue.Catalogue {
	return &catalogue.Catalogue{
		Digest: aDigest,
		Defs: []tool.Def{{
			FullMethod: route,
			FQN:        fqn,
			Name:       "get_status",
			Input:      message(),
			Output:     message(),
		}},
		DescriptorHashes: map[string]string{thePkg: good},
	}
}

// countingStore records how often a request read the catalogue. Atomic
// because the handler runs on httptest's goroutine while the test reads the
// count on its own.
type countingStore struct {
	c     *catalogue.Catalogue
	reads atomic.Int64
}

func (s *countingStore) Current() *catalogue.Catalogue {
	s.reads.Add(1)
	return s.c
}

// fakeInvoker stands in for the hop. err is what the tool call produces; fill
// is what it writes into the response when it succeeds.
type fakeInvoker struct {
	err   error
	fill  string
	calls atomic.Int64
}

func (f *fakeInvoker) Invoke(_ context.Context, _ string, _, resp proto.Message) error {
	f.calls.Add(1)
	if f.err != nil {
		return f.err
	}
	m := resp.ProtoReflect()
	m.Set(m.Descriptor().Fields().ByName("producer"), protoreflect.ValueOfString(f.fill))
	return nil
}

// discardLogger exercises the handler's own logging without printing it. The
// lines matter — they are what an operator sees — but their text is not what
// these tests are about.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func protoBody(t *testing.T, producer string) []byte {
	t.Helper()
	m := dynamicpb.NewMessage(message())
	m.Set(message().Fields().ByName("producer"), protoreflect.ValueOfString(producer))
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// call runs one request against a handler wired with the given invoker, and
// returns the recorder so a test can read the status, headers and body.
func call(t *testing.T, h *Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// connectErr is the shape writeErr emits, which is what a Connect client
// reads. Asserting the code rather than only the status matters because two
// of the four answers share a status.
type connectErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) connectErr {
	t.Helper()
	var e connectErr
	if err := json.NewDecoder(w.Body).Decode(&e); err != nil {
		t.Fatalf("the error body is not Connect's shape: %v (%q)", err, w.Body.String())
	}
	return e
}

func TestACallToADeclaredToolIsRoutedAndAnswered(t *testing.T) {
	inv := &fakeInvoker{fill: "the-service"}
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}

	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(string(protoBody(t, "caller"))))
	req.Header.Set("Content-Type", contentProto)
	w := call(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if inv.calls.Load() != 1 {
		t.Errorf("the tool was invoked %d times, want once", inv.calls.Load())
	}
	out := dynamicpb.NewMessage(message())
	if err := proto.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("the reply is not the declared response type: %v", err)
	}
	got := out.Get(message().Fields().ByName("producer")).String()
	if got != "the-service" {
		t.Errorf("reply producer = %q, want the-service", got)
	}
}

// The digest is on every response rather than only at startup, so that
// someone debugging a surprising answer can see which catalogue produced it
// without correlating against a log line from hours earlier.
func TestEveryAnswerSaysWhichCatalogueProducedIt(t *testing.T) {
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: &fakeInvoker{fill: "x"}}

	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(""))
	w := call(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Garm-Catalogue-Digest"); got != aDigest {
		t.Errorf("Garm-Catalogue-Digest = %q, want %q", got, aDigest)
	}
}

// A JSON body is unmarshalled against the same descriptor and answered in
// JSON. Both encodings exist because a caller with a Connect client sends
// proto and a caller with curl sends JSON, and the tool on the other side
// must not be able to tell which.
func TestJSONAndBinaryBodiesReachTheSameTool(t *testing.T) {
	for _, c := range []struct {
		name        string
		contentType string
		body        string
		wantCT      string
	}{
		{"binary", contentProto, string(protoBody(t, "caller")), contentProto},
		{"json", contentJSON, `{"producer":"caller"}`, contentJSON},
	} {
		t.Run(c.name, func(t *testing.T) {
			inv := &fakeInvoker{fill: "answered"}
			h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}

			req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(c.body))
			req.Header.Set("Content-Type", c.contentType)
			w := call(t, h, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); ct != c.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, c.wantCT)
			}
			if inv.calls.Load() != 1 {
				t.Fatalf("the tool was invoked %d times, want once", inv.calls.Load())
			}
		})
	}

	// And the JSON answer is readable as JSON, not as proto bytes with a
	// JSON content type.
	inv := &fakeInvoker{fill: "answered"}
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}
	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"producer":"caller"}`))
	req.Header.Set("Content-Type", contentJSON)
	w := call(t, h, req)

	out := dynamicpb.NewMessage(message())
	if err := protojson.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("a JSON request was answered with something that is not JSON: %v", err)
	}
	if got := out.Get(message().Fields().ByName("producer")).String(); got != "answered" {
		t.Errorf("reply producer = %q, want answered", got)
	}
}

// TestARouteTheCatalogueDoesNotDeclareIsUnimplemented.
//
// "unimplemented" is NOT the "not_found" that authorization will return for a
// tool the caller may not see. Existence is itself information: if a probe
// could tell "there is no such tool" from "there is one and you may not see
// it", the second answer would leak the first. So these two must stay
// distinguishable to an operator reading garmd's own output and
// indistinguishable to anyone probing from outside — which is why this build
// answers about ITSELF ("this process does not serve that") and never about
// the caller.
func TestARouteTheCatalogueDoesNotDeclareIsUnimplemented(t *testing.T) {
	inv := &fakeInvoker{}
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}

	w := call(t, h, httptest.NewRequest(http.MethodPost, "/t.v1.S/NoSuchMethod", strings.NewReader("")))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
	}
	if code := decodeErr(t, w).Code; code != "unimplemented" {
		t.Errorf("code = %q, want unimplemented; not_found is authorization's answer "+
			"and the two must not be confused", code)
	}
	if inv.calls.Load() != 0 {
		t.Error("a route the catalogue does not declare was still sent over the hop")
	}
}

// TestADeclaredButUnreachableToolIsUnavailableNotAFailure: the catalogue
// declares it and nothing serves it, which is an operator's missing
// deployment. A 500 would send someone to read handler code that is working
// fine.
func TestADeclaredButUnreachableToolIsUnavailableNotAFailure(t *testing.T) {
	h := &Handler{
		Store:   &countingStore{c: aCatalogue()},
		Invoker: &fakeInvoker{err: fmt.Errorf("%w: %s", transport.ErrUnreachable, route)},
		// A logger so that the operator-facing lines are exercised too: they
		// are the only output an operator gets, and one that panics on a
		// nil field would take the process down on the first bad deployment.
		Log: discardLogger(),
	}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
	}
	e := decodeErr(t, w)
	if e.Code != "unavailable" {
		t.Errorf("code = %q, want unavailable", e.Code)
	}
	if !contains(e.Message, fqn) {
		t.Errorf("the message does not name the tool, so an operator cannot act: %q", e.Message)
	}
}

// A tool that ran and failed is the caller's problem, and must not be
// reported with the same code as one that is not deployed.
func TestAToolsOwnFailureIsInternalNotUnavailable(t *testing.T) {
	h := &Handler{
		Store:   &countingStore{c: aCatalogue()},
		Invoker: &fakeInvoker{err: errors.New("the account does not exist")},
		Log:     discardLogger(),
	}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	if code := decodeErr(t, w).Code; code != "internal" {
		t.Errorf("code = %q, want internal", code)
	}
}

// quarantine builds a reconciler that has already decided the package's
// service implements a different contract, by running a real sweep rather
// than by writing the verdict in. A test that set the map directly would keep
// passing if the sweep stopped producing one.
func quarantine(t *testing.T, store Catalogues) *Reconciler {
	t.Helper()
	r := &Reconciler{
		Store: store,
		Discoverer: &fakeDiscoverer{services: []transport.Service{
			{Name: "t_v1_S", Identity: drifted, Subjects: []string{"t.v1.S.Get"}},
		}},
	}
	r.sweep(context.Background())
	if _, bad := r.Quarantined(thePkg); !bad {
		t.Fatal("setup: the sweep produced no quarantine")
	}
	return r
}

// A tool whose service implements a different contract is unavailable, not
// broken: the deployment is wrong, and that is the same person's problem as a
// missing one. Same status as unreachable on purpose.
func TestAQuarantinedToolIsUnavailable(t *testing.T) {
	store := &countingStore{c: aCatalogue()}
	h := &Handler{
		Store:      store,
		Invoker:    &fakeInvoker{},
		Reconciler: quarantine(t, store),
		Log:        discardLogger(),
	}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
	}
	e := decodeErr(t, w)
	if e.Code != "unavailable" {
		t.Errorf("code = %q, want unavailable", e.Code)
	}
	if !contains(e.Message, "different contract") {
		t.Errorf("the message does not say why it is refused: %q", e.Message)
	}
}

// countingBody reports whether anything read the request.
type countingBody struct{ reads atomic.Int64 }

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return 0, io.EOF
}

// TestAQuarantinedToolIsRefusedBeforeItsRequestIsRead.
//
// A call that must not happen must also not look like it happened. Reading
// the body first would put the caller's arguments through this process and
// leave a request that is indistinguishable, from the outside, from one that
// was attempted and failed.
func TestAQuarantinedToolIsRefusedBeforeItsRequestIsRead(t *testing.T) {
	store := &countingStore{c: aCatalogue()}
	inv := &fakeInvoker{}
	h := &Handler{Store: store, Invoker: inv, Reconciler: quarantine(t, store)}

	body := &countingBody{}
	req := httptest.NewRequest(http.MethodPost, route, body)
	call(t, h, req)

	if body.reads.Load() != 0 {
		t.Errorf("the request body was read %d times before the call was refused",
			body.reads.Load())
	}
	if inv.calls.Load() != 0 {
		t.Error("a quarantined tool was still called")
	}
}

// A tool call is a POST. Anything else is refused before the catalogue is
// even consulted, so a crawler cannot enumerate routes with GETs.
func TestOnlyAPostIsAToolCall(t *testing.T) {
	store := &countingStore{c: aCatalogue()}
	inv := &fakeInvoker{}
	h := &Handler{Store: store, Invoker: inv}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead} {
		w := call(t, h, httptest.NewRequest(method, route, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, w.Code)
		}
	}
	if inv.calls.Load() != 0 {
		t.Error("a non-POST reached the hop")
	}
	if store.reads.Load() != 0 {
		t.Error("a non-POST consulted the catalogue, which tells a prober the route exists")
	}
}

// TestTheCatalogueIsReadOncePerRequest is what makes reload safe. Reading it
// twice is the one way a single call can see two generations — routing on one
// descriptor and decoding with another — which is exactly what immutable
// generations prevent.
func TestTheCatalogueIsReadOncePerRequest(t *testing.T) {
	store := &countingStore{c: aCatalogue()}
	h := &Handler{Store: store, Invoker: &fakeInvoker{fill: "x"}}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if n := store.reads.Load(); n != 1 {
		t.Errorf("the catalogue was read %d times in one request, want once", n)
	}
}

// A process with no catalogue serves nothing and says so. Answering 404 would
// claim the tool does not exist, when the truth is that this process does not
// yet know what exists.
func TestAProcessWithNoCatalogueIsUnavailable(t *testing.T) {
	h := &Handler{Store: &countingStore{}, Invoker: &fakeInvoker{}}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
	}
	if code := decodeErr(t, w).Code; code != "unavailable" {
		t.Errorf("code = %q, want unavailable", code)
	}
}

// A body that does not fit the declared input is the caller's mistake, and
// the message has to name the type it was checked against — otherwise the
// caller cannot tell which of the two encodings was misread.
func TestABodyThatDoesNotFitTheDeclaredInputIsRejected(t *testing.T) {
	inv := &fakeInvoker{}
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}

	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"producer": 7}`))
	req.Header.Set("Content-Type", contentJSON)
	w := call(t, h, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	e := decodeErr(t, w)
	if e.Code != "invalid_argument" {
		t.Errorf("code = %q, want invalid_argument", e.Code)
	}
	if !contains(e.Message, string(message().FullName())) {
		t.Errorf("the message does not name the declared input type: %q", e.Message)
	}
	if inv.calls.Load() != 0 {
		t.Error("a request that does not fit its declared input was sent over the hop anyway")
	}
}

// failingBody is a request whose bytes never fully arrive — a client that
// disconnected mid-upload, which is ordinary rather than exotic.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("the connection went away") }

// A body that could not be read is refused rather than passed on. Invoking a
// tool with the part of a request that did arrive would run it against
// arguments the caller never finished sending.
func TestARequestThatCouldNotBeReadIsNeverSentToTheTool(t *testing.T) {
	inv := &fakeInvoker{}
	h := &Handler{Store: &countingStore{c: aCatalogue()}, Invoker: inv}

	w := call(t, h, httptest.NewRequest(http.MethodPost, route, failingBody{}))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", w.Code, w.Body.String())
	}
	if inv.calls.Load() != 0 {
		t.Error("a truncated request was sent over the hop")
	}
}
