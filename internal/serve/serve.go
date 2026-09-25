// Package serve is the agent-facing surface: it accepts a tool call, finds
// the tool in the catalogue, and routes it to whatever implements it.
//
// Everything here is dynamic. A request is unmarshalled into a message built
// from a descriptor the catalogue supplied, and the reply into another one —
// no generated types, nothing this binary was compiled against. That is the
// whole point: adding a tool is a catalogue rebuild, not a release.
//
// THIS DOES NOT GOVERN ANYTHING YET. The ten steps are not here: no
// authentication, no authorization, no input checking, no redaction, no
// ledger. It routes. Deploying it as-is would be an ungoverned proxy wearing
// the name of a governed one, which is worse than no proxy at all.
package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/transport"
)

// Handler serves the tool plane over HTTP, in Connect's unary shape:
// POST /pkg.Service/Method, the message as the body.
type Handler struct {
	Store   *catalogue.Store
	Invoker transport.Invoker
	Log     *slog.Logger
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

	resp := dynamicpb.NewMessage(def.Output)
	if err := h.Invoker.Invoke(r.Context(), def.FullMethod, req, resp); err != nil {
		h.write502(w, def, err)
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

func (h *Handler) write502(w http.ResponseWriter, def tool.Def, err error) {
	if errors.Is(err, transport.ErrUnreachable) {
		// The catalogue declares this tool and nothing serves it. An
		// operator's problem, not the caller's — and reporting it as a tool
		// failure sends someone to read handler code that is working fine.
		if h.Log != nil {
			h.Log.Warn("tool is declared but unreachable", "fqn", def.FQN, "service", def.Service())
		}
		writeErr(w, http.StatusServiceUnavailable, "unavailable",
			fmt.Sprintf("%s is declared but no service is serving it", def.FQN))
		return
	}
	if h.Log != nil {
		h.Log.Error("tool call failed", "fqn", def.FQN, "err", err)
	}
	writeErr(w, http.StatusInternalServerError, "internal", err.Error())
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
