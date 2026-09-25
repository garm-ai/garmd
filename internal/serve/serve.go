// Package serve is the agent-facing surface: it accepts a tool call, finds
// the tool in the catalogue, and routes it to whatever implements it.
//
// Everything here is dynamic. A request is unmarshalled into a message built
// from a descriptor the catalogue supplied, and the reply into another one —
// no generated types, nothing this binary was compiled against. That is the
// whole point: adding a tool is a catalogue rebuild, not a release.
//
// Every call goes through the chain and by no other route. The handler
// resolves a Principal, finds the tool, and hands both to toolplane.Invoke;
// the network hop is registered as the chain's resolver, so reaching a tool
// means passing steps 2 through 8 first. There is deliberately no path here
// that calls the Invoker directly — one would be an unpoliced door that
// looked like a feature.
//
// Not every step is implemented. Instance authorization, grants and notify
// are nil in this build and the chain treats a nil step as "not declared",
// which is why KNOWN-GAPS.md names them rather than this file pretending
// otherwise. What IS true is that the order is fixed, the ledger runs on
// every outcome, and a refusal is recorded with its cause.
package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garm/contracts/audit"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
	"github.com/garm-ai/garmd/internal/transport"
)

// Handler serves the tool plane over HTTP, in Connect's unary shape:
// POST /pkg.Service/Method, the message as the body.
// Catalogues is the slice of the store these need: the generation to serve
// this request with. Narrow on purpose — a handler that could reload, sweep
// or inspect history would eventually do one of them mid-request.
type Catalogues interface {
	Current() *catalogue.Catalogue
}

type Handler struct {
	Store   Catalogues
	Invoker transport.Invoker
	Log     *slog.Logger

	// Reconciler refuses tools whose service implements a different contract
	// from the catalogue. Optional only because a handler can be constructed
	// without one in a test; a deployment without one routes to whatever
	// answers, which is the failure that does not announce itself.
	Reconciler *Reconciler

	// Principals is step 1, and it is REQUIRED — ServeHTTP refuses every
	// request while it is nil rather than falling back to an anonymous
	// caller.
	//
	// It lives on the surface rather than in CoreConfig because what a
	// principal is derived FROM differs per front door: a bearer token here,
	// a session on MCP. The chain takes the Principal already built and does
	// not care where it came from, which is the seam that lets identity be
	// stubbed in a test and replaced in a bank without touching enforcement.
	Principals func(context.Context) (*toolplane.Principal, error)

	// HashKey keys hash redactions, and it must be STABLE across restarts and
	// identical across replicas. A key that changes means the same value
	// hashes to two different things, so the correlation those redactions
	// exist to preserve quietly stops working — without any error, and
	// without the values themselves ever being exposed.
	HashKey []byte

	// Recorder is step 9. Required: a Core cannot be built without one,
	// because a call that happened and left no row is the failure this whole
	// design is against.
	Recorder ledger.Recorder

	// FGA, Grants and Notifier are steps 4/7, 5 and 10. Nil means the step is
	// not available here, and AddTools then refuses to mount any tool that
	// declares it — so nil can never mean "declared but skipped".
	//
	// They are on the Handler rather than only on CoreConfig because the
	// plane is built per catalogue generation: a seam reachable only at
	// NewCore would be unreachable from the daemon entirely, which is what
	// they were until this existed.
	FGA      toolplane.FGAChecker
	Grants   toolplane.GrantVerifier
	Notifier toolplane.Notifier

	// Audit is the durable, separately-retained stream — the half of the
	// record that may REFUSE a call, for a tool declaring fail_closed.
	//
	// Optional, and nil is safe precisely because the mount refusal reads it:
	// a catalogue containing an audited tool will not mount without one, so
	// nil can never mean "audited tool served unaudited".
	Audit audit.Sink

	// The chain for the current generation. See plane.go.
	plane   atomic.Pointer[plane]
	buildMu sync.Mutex
}

const (
	contentProto = "application/proto"
	contentJSON  = "application/json"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "unimplemented",
			"a tool call is a POST")
		return
	}

	// One read of the catalogue, at the start, held for the whole request.
	// Reading it twice is the one way to see two generations in a single
	// call, which is exactly what the immutable-generation design prevents.
	cat := h.Store.Current()
	if cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable",
			"no catalogue is loaded")
		return
	}

	// The chain for this generation, before anything else looks at the
	// request. A generation whose chain will not build serves nothing: the
	// alternative is routing it ungoverned, which is the one outcome worth
	// refusing a whole deployment over.
	pl, err := h.planeFor(cat)
	if err != nil {
		if h.Log != nil {
			h.Log.Error("the chain could not be built for this catalogue",
				"digest", cat.Digest, "err", err)
		}
		writeErr(w, http.StatusServiceUnavailable, "unavailable",
			"this catalogue cannot be served")
		return
	}

	// Step 1, and it runs BEFORE the route is looked up.
	//
	// The order is the point. Answering "no such tool" to an unauthenticated
	// caller would let anyone with a socket enumerate which tools this
	// deployment serves, one path at a time — and the catalogue is exactly
	// the thing worth not disclosing. Nobody learns anything about what is
	// here until they have said who they are.
	//
	// The refusal is ledgered through the chain rather than written straight
	// out, because an unauthenticated attempt is a security-relevant event
	// and the row for it belongs in the same place as every other outcome.
	principal, err := h.principal(r)
	if err != nil {
		refuse(w, pl.core.Unauthenticated(r.Context(), r.URL.Path, err))
		return
	}

	def, ok := lookup(cat, r.URL.Path)
	if !ok {
		// "unimplemented" — this build does not serve it. Distinct from the
		// "not_found" that authorization will return for a tool the caller
		// may not see, because existence is itself information and those two
		// answers must not be distinguishable by anyone probing.
		writeErr(w, http.StatusNotFound, "unimplemented",
			fmt.Sprintf("no tool is served at %s", r.URL.Path))
		return
	}

	// Checked before the request is even read. A call to a tool whose service
	// implements a different contract must not happen, and must not look like
	// it happened — so it is refused here rather than attempted and reported.
	if h.Reconciler != nil {
		if why, bad := h.Reconciler.Quarantined(pkgOfFQN(def.FQN)); bad {
			if h.Log != nil {
				h.Log.Error("refused: contract mismatch", "fqn", def.FQN, "reason", why)
			}
			writeErr(w, http.StatusServiceUnavailable, "unavailable",
				fmt.Sprintf("%s is not being served: %s", def.FQN, why))
			return
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "invalid_argument",
			"request body is too large or could not be read")
		return
	}

	asJSON := strings.HasPrefix(r.Header.Get("Content-Type"), contentJSON)

	// Built from the catalogue's descriptor, not from a generated type. This
	// binary has never seen this message.
	req := dynamicpb.NewMessage(def.Input)
	if err := unmarshal(body, req, asJSON); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_argument",
			fmt.Sprintf("request does not match %s: %v", def.Input.FullName(), err))
		return
	}

	// Steps 2 through 10. The hop is registered as this chain's resolver, so
	// there is no way to reach the tool that does not pass through here.
	resp, err := pl.core.Invoke(r.Context(), principal, def.FullMethod, req)
	if err != nil {
		h.writeChainErr(w, def, err)
		return
	}

	out, err := marshal(resp, asJSON)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal",
			"the reply could not be encoded")
		return
	}
	ct := contentProto
	if asJSON {
		ct = contentJSON
	}
	w.Header().Set("Content-Type", ct)
	// The pair that answers "which tools is this process serving", on every
	// response rather than only at startup — so a caller debugging a
	// surprising answer can see which catalogue produced it.
	w.Header().Set("Garm-Catalogue-Digest", cat.Digest)
	_, _ = w.Write(out)
}

// maxRequestBytes is a guard, not a policy. Per-tool limits belong in the
// chain, where they can differ by tool and by caller; this only stops one
// request from exhausting the process before anything has looked at it.
const maxRequestBytes = 16 << 20

// principal is step 1: who is calling.
//
// A nil Principals is a refusal, not an anonymous caller. A governance daemon
// that cannot identify its callers can only make one honest decision, and it
// is not "allow".
func (h *Handler) principal(r *http.Request) (*toolplane.Principal, error) {
	if h.Principals == nil {
		return nil, errors.New("this build has no way to identify a caller")
	}
	p, err := h.Principals(r.Context())
	if err != nil {
		return nil, err
	}
	if p == nil {
		// A nil Principal and no error is a bug in the PrincipalFunc, and it
		// would otherwise reach the chain as a caller with no authority at
		// all — which some steps would read as "denied" and others as
		// "unset". Refuse it here where it is still legible.
		return nil, errors.New("the principal source returned no principal and no error")
	}
	return p, nil
}

// writeChainErr turns a chain refusal into a status line.
//
// The code comes from the chain and the text is scrubbed, because a resolver
// error routinely interpolates the value it was protecting — "user with email
// ada@corp.com not found" — and the sanitizer never sees it, since it only
// ever operates on successful responses. The detail is already on the ledger.
// The wire gets a code and a sentence.
func (h *Handler) writeChainErr(w http.ResponseWriter, def tool.Def, err error) {
	// Checked before the code mapping, because this one is not the caller's
	// fault and is the only failure here that names an operator's problem: the
	// catalogue declares a tool and nothing is serving it. Reporting it as a
	// tool failure sends someone to read handler code that is working fine.
	if errors.Is(err, transport.ErrUnreachable) {
		if h.Log != nil {
			h.Log.Warn("tool is declared but unreachable",
				"fqn", def.FQN, "service", def.Service())
		}
		writeErr(w, http.StatusServiceUnavailable, "unavailable",
			fmt.Sprintf("%s is declared but no service is serving it", def.FQN))
		return
	}

	if h.Log != nil && codeToAnswerWith(err) == connect.CodeInternal {
		// Only the internal ones. A permission denial is the system working,
		// and logging every one at error level trains people to ignore the
		// level that means something broke.
		h.Log.Error("tool call failed", "fqn", def.FQN, "err", err)
	}
	refuse(w, err)
}

// refuse writes a chain refusal: the code the chain assigned, the static text
// for that code, and none of the error's own words.
//
// Every refusal goes through here, step 1's included. Two paths formatting
// the same refusal two ways is how a surface ends up leaking down one of them
// — and the first version of this leaked the verifier's message out of the
// 401 while the 403 beside it was scrubbed.
func refuse(w http.ResponseWriter, err error) {
	code := codeToAnswerWith(err)
	// Scrubbed against the code being ANSWERED with, so the text and the code
	// cannot disagree. A raw sentinel carries no connect code of its own
	// until CodeOf assigns one, so scrubbing the bare error would produce
	// "unknown: request failed" for a perfectly well-classified refusal.
	writeErr(w, httpStatusFor(code), code.String(),
		scrubbedMessage(connect.NewError(code, err)))
}

func codeToAnswerWith(err error) connect.Code {
	code := toolplane.CodeOf(err)
	if code == connect.CodeUnknown {
		// A resolver error carrying no code of its own. "Unknown" is accurate
		// about our knowledge and useless to the caller, who cannot act
		// differently on it than on any other failure that is not theirs —
		// and it advertises that this daemon did not understand its own
		// downstream. The cause is on the ledger either way.
		return connect.CodeInternal
	}
	return code
}

// httpStatusFor maps a connect code onto the status Connect itself uses, so a
// Connect client reads these without being told anything special.
func httpStatusFor(code connect.Code) int {
	switch code {
	case connect.CodeInvalidArgument:
		return http.StatusBadRequest
	case connect.CodeUnauthenticated:
		return http.StatusUnauthorized
	case connect.CodePermissionDenied:
		return http.StatusForbidden
	case connect.CodeNotFound, connect.CodeUnimplemented:
		// Both 404, and deliberately indistinguishable. "Not found" is what
		// authorization answers for a tool this caller may not see, and
		// "unimplemented" is what the catalogue answers for one that is not
		// here. If those two differed, the difference would tell a prober
		// which tools exist but are denied to them — and existence is itself
		// information.
		return http.StatusNotFound
	case connect.CodeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// scrubbedMessage is the static text for an error's code, never the error's
// own words.
func scrubbedMessage(err error) string {
	scrubbed := toolplane.ScrubError(err)
	var ce *connect.Error
	if errors.As(scrubbed, &ce) {
		return ce.Message()
	}
	return scrubbed.Error()
}

// lookup finds a tool by route. The path IS the FullMethod, so there is no
// mapping table here to disagree with the one on the other side of the hop.
func lookup(cat *catalogue.Catalogue, path string) (tool.Def, bool) {
	for _, d := range cat.Defs {
		if d.FullMethod == path {
			return d, true
		}
	}
	return tool.Def{}, false
}

func unmarshal(b []byte, m proto.Message, asJSON bool) error {
	if asJSON {
		return protojson.Unmarshal(b, m)
	}
	return proto.Unmarshal(b, m)
}

func marshal(m proto.Message, asJSON bool) ([]byte, error) {
	if asJSON {
		return protojson.Marshal(m)
	}
	return proto.Marshal(m)
}

// writeErr replies in Connect's error shape, which is what a Connect client
// will read without being told anything special.
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", contentJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}
