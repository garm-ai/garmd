package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/garm-ai/contracts/ledger"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/toolplane"
	"github.com/garm-ai/garmd/internal/transport"
)

// A tool that ran and answered with a code is a refusal the tool decided,
// not this daemon's failure. Before this a 404 from a fetcher reached the
// model as "internal server error", and it retried three times.

// toolMessage is what a tool says when it refuses — the kind of sentence
// that carries a URL, an account, a page. Tools promise it is page-free;
// nothing here relies on that, so it must never be on the wire.
const toolMessage = "https://intranet.example/finance/q3.pdf is off the allowlist"

type toolRefusedBody struct {
	Code     string `json:"code"`
	ToolCode string `json:"tool_code"`
	Message  string `json:"message"`
}

func TestAToolsCodedRefusalIsMappedNotInternal(t *testing.T) {
	for _, code := range []string{"400", "403", "404", "409", "415", "422", "429", "502", "504"} {
		t.Run(code, func(t *testing.T) {
			rec := &record.Memory{}
			h := chained(&Handler{
				Store:    &countingStore{c: aCatalogue()},
				Invoker:  &fakeInvoker{err: &transport.CodedError{Procedure: route, Code: code, Message: toolMessage}},
				Recorder: rec,
				Log:      discardLogger(),
			})

			w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

			want, _ := strconv.Atoi(code)
			if w.Code != want {
				t.Fatalf("status = %d, want %s: %s", w.Code, code, w.Body.String())
			}
			var b toolRefusedBody
			if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
				t.Fatalf("body is not the tool_refused shape: %v (%q)", err, w.Body.String())
			}
			if b.Code != "tool_refused" || b.ToolCode != code {
				t.Errorf("body = %+v, want code tool_refused and tool_code %s", b, code)
			}
			if b.Message == "" || b.Message != (&toolplane.ToolRefusal{Code: code}).Message() {
				t.Errorf("message = %q, want the static sentence for %s", b.Message, code)
			}
			if strings.Contains(w.Body.String(), "intranet") || strings.Contains(w.Body.String(), "allowlist") {
				t.Errorf("the tool's own message reached the wire: %s", w.Body.String())
			}
			if w.Header().Get(EventHeader) == "" {
				t.Error("no Garm-Event-Id: a refusal the chain decided has a row")
			}

			events := rec.Events()
			if len(events) != 1 {
				t.Fatalf("%d ledger rows, want 1", len(events))
			}
			ev := events[0]
			if ev.Outcome != ledger.OutcomeDenied {
				t.Errorf("outcome = %q, want denied: the tool decided this, nothing broke", ev.Outcome)
			}
			if ev.ErrorKind != toolplane.ErrorKindToolRefused {
				t.Errorf("error_kind = %q, want tool_refused", ev.ErrorKind)
			}
			if !strings.Contains(ev.ErrorDetail, toolMessage) || !strings.Contains(ev.ErrorDetail, code) {
				t.Errorf("error_detail = %q, want the tool's code and its own words", ev.ErrorDetail)
			}
		})
	}
}

// A code the chain does not understand — a 500, which is a tool that broke,
// or something nobody defined — is what it always was: internal, with the
// tool's words on the ledger and nothing on the wire.
func TestAnUnknownToolCodeStaysInternal(t *testing.T) {
	for _, code := range []string{"500", "418", "teapot", ""} {
		t.Run("code "+strconv.Quote(code), func(t *testing.T) {
			rec := &record.Memory{}
			h := chained(&Handler{
				Store:    &countingStore{c: aCatalogue()},
				Invoker:  &fakeInvoker{err: &transport.CodedError{Procedure: route, Code: code, Message: toolMessage}},
				Recorder: rec,
				Log:      discardLogger(),
			})

			w := call(t, h, httptest.NewRequest(http.MethodPost, route, strings.NewReader("")))

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
			}
			if got := decodeErr(t, w).Code; got != "internal" {
				t.Errorf("code = %q, want internal", got)
			}
			if strings.Contains(w.Body.String(), "intranet") {
				t.Errorf("the tool's own message reached the wire: %s", w.Body.String())
			}
			events := rec.Events()
			if len(events) != 1 || events[0].Outcome != ledger.OutcomeError ||
				!strings.Contains(events[0].ErrorDetail, toolMessage) {
				t.Errorf("ledger = %+v, want one error row carrying the tool's words", events)
			}
		})
	}
}
