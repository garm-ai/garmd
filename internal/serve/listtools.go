package serve

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/garm-ai/garmd/internal/tool"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// ListToolsPath is where a caller asks what it may call.
//
// It is NOT a tool. It carries no ToolPolicy, mounts nothing, crosses no hop,
// and writes no ledger row on success — a catalogue that produced a row per
// listing would bury the calls under the polling. What it is instead is a
// projection of the decision the chain has already made: Core.Catalog is the
// same predicate step 2 denies with, so this endpoint cannot list a tool the
// chain would refuse, structurally rather than by convention.
const ListToolsPath = "/garm.v1.ToolCatalogService/ListTools"

// jsonSchemaDraft is the dialect ProjectInput emits and MCP's inputSchema
// expects.
const jsonSchemaDraft = "https://json-schema.org/draft/2020-12/schema"

// The response shape is program plan §3.7, field for field. Track D builds a
// model's tool list from it and the acceptance test asserts on it, so the JSON
// names are a contract and not a serialisation detail — which is why they are
// spelled here rather than derived from Go names by the marshaller's defaults.
type listToolsResponse struct {
	CatalogueDigest string         `json:"catalogue_digest"`
	Tools           []listToolItem `json:"tools"`
}

// listToolsRequest is the body. Every field is optional and `{}` is the
// ordinary case; an empty body is `{}`.
type listToolsRequest struct {
	// Audience is what the caller is asking ON BEHALF OF: PERSON, AGENT or
	// RUNNER (cards-and-tasks design §2.5). Absent means AGENT, which is why
	// a model's listing is unchanged by this field existing — the caller that
	// never asks gets exactly what it got before.
	//
	// It is not a claim and it is not narrowing: a caller may ask for any
	// audience, and asking for PERSON gets them the person-facing tools THEIR
	// OWN claims already reach and not one more. What it selects is which
	// question is being asked — "what may I call" and "what may I put in
	// front of somebody" have different answers over the same entitlements.
	Audience string `json:"audience"`
}

type listToolItem struct {
	FQN         string `json:"fqn"`
	Method      string `json:"method"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Verb        string `json:"verb"`

	// Sets is the tool sets this tool declares membership of — who HOLDS it —
	// and Audience is what it is FOR. Both are published because a client
	// that has to group a listing (Studio listing agents apart from tools)
	// otherwise keeps its own copy of the catalogue's vocabulary, which is
	// the hard-coded list this field exists to delete.
	//
	// Audience is what the author DECLARED, empty when they declared nothing
	// — the same distinction approval_mode keeps between MODE_UNSPECIFIED and
	// MODE_NONE. An empty audience reads as AGENT wherever it is applied, and
	// a consumer that needs the effective value applies that rule; a row that
	// asserted AGENT would be this endpoint putting words in an author's
	// mouth.
	Sets     []string `json:"sets"`
	Audience []string `json:"audience"`

	// ApprovalMode and MaterialFields are what a caller needs to ask for an
	// approval before it calls. Without them it must copy the annotation by
	// hand, which is a second place the material fields are written down.
	ApprovalMode   string   `json:"approval_mode"`
	MaterialFields []string `json:"material_fields"`

	Guidance    listToolGuidance `json:"guidance"`
	InputSchema toolplane.Schema `json:"input_schema"`
}

type listToolGuidance struct {
	WhenToUse    string `json:"when_to_use"`
	WhenNotToUse string `json:"when_not_to_use"`
	OnError      string `json:"on_error"`
}

// listTools answers the projection for one principal.
//
// Step 1 has already run — ServeHTTP routes here only after it — so an
// unauthenticated caller was refused, and ledgered, by the same path the tool
// route uses. Nobody learns what is here until they have said who they are.
//
// Everything it reads comes from the plane the request pinned, never from a
// second Store.Current(): a listing assembled from two generations would name
// one digest and carry another's tools, and both halves would look valid.
func (h *Handler) listTools(
	w http.ResponseWriter, r *http.Request, pl *plane, p *toolplane.Principal,
) {
	want, err := audienceAsked(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}

	defs := pl.core.Catalog(p, toolplane.CatalogFilter{Audience: want})

	// Non-nil, so `tools` marshals as [] and never as null. A caller cleared
	// for nothing gets an empty list, which is an answer; null is a shape the
	// consumer has to special-case.
	out := listToolsResponse{
		CatalogueDigest: pl.cat.Digest,
		Tools:           make([]listToolItem, 0, len(defs)),
	}
	for _, d := range defs {
		// Three returns: the input projection and the output one. Only the
		// input is published — what a caller may SEND. The output schema is
		// what step 8 will let it read back, which is a different question and
		// not one a tool list answers.
		in, _, err := pl.core.SchemaFor(d, p)
		if err != nil {
			// A tool the chain considers visible whose input cannot be
			// projected is this process's problem, not the caller's, and a
			// partial listing would be worse than none: a model shown a
			// catalogue with a tool missing concludes it does not exist.
			if h.Log != nil {
				h.Log.Error("a visible tool has no projectable input schema",
					"fqn", d.FQN, "err", err)
			}
			writeErr(w, http.StatusInternalServerError, "internal",
				"the catalogue could not be projected")
			return
		}
		out.Tools = append(out.Tools, listToolItem{
			FQN:         d.FQN,
			Method:      d.FullMethod,
			Title:       d.Title,
			Description: d.Description,
			// The enum NAMES, which is what protojson emits and what every
			// other surface in this system spells. Numbers here would make a
			// consumer keep its own copy of the enum.
			Verb:           d.Verb.String(),
			Sets:           orEmpty(d.Sets),
			Audience:       orEmpty(d.Audience),
			ApprovalMode:   d.ApprovalMode.String(),
			MaterialFields: orEmpty(d.MaterialFields),
			Guidance: listToolGuidance{
				WhenToUse:    d.WhenToUse,
				WhenNotToUse: d.WhenNotToUse,
				OnError:      d.OnError,
			},
			InputSchema: withDraft(in),
		})
	}

	w.Header().Set("Content-Type", contentJSON)
	// The same pair as every tool answer: which catalogue produced this, so a
	// caller debugging a listing that disagrees with a call can see whether the
	// two came from one generation.
	w.Header().Set("Garm-Catalogue-Digest", pl.cat.Digest)
	_ = json.NewEncoder(w).Encode(out)
}

// withDraft names the JSON Schema dialect without touching the projection.
//
// Core.SchemaFor's maps are SHARED: one object per (descriptor, shape,
// dimension) across every principal of that shape, which is what makes
// discovery affordable. Writing "$schema" into one would corrupt the
// projection for every caller that shape covers — and it would do it
// invisibly, because the value written is correct. So this copies the top
// level and leaves the nested maps alone: nothing below the root is ever
// written, here or anywhere else, and a shallow copy is exactly the amount of
// copying that buys the one key this adds.
func withDraft(s toolplane.Schema) toolplane.Schema {
	out := make(toolplane.Schema, len(s)+1)
	for k, v := range s {
		out[k] = v
	}
	out["$schema"] = jsonSchemaDraft
	return out
}

// audienceAsked reads the audience from the request body.
//
// A missing body, an empty one and `{}` are all "the default", because this
// endpoint has been callable with all three since before it took a body at
// all and a listing that started 400-ing on one of them would break a caller
// that was never wrong. A body that is not JSON, or names an audience that is
// not one, is a 400: a client asking for "PERSONS" means to ask for something
// and must not be quietly handed the model's list instead.
func audienceAsked(r *http.Request) (string, error) {
	if r == nil || r.Body == nil {
		return "", nil
	}
	// Bounded like every other body this surface reads. A listing request is
	// a few dozen bytes; anything larger is not one.
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil || len(body) == 0 {
		return "", nil //nolint:nilerr // an unreadable listing body asks the default
	}
	var req listToolsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", errBadListBody
	}
	name, ok := tool.NormaliseAudience(req.Audience)
	if !ok {
		return "", errBadAudience
	}
	return name, nil
}

// The two refusals, as values so the text is written once and says nothing
// about the catalogue: a malformed listing request must not be a way to
// learn what is in one.
var (
	errBadListBody = listErr("the request body is not a JSON object")
	errBadAudience = listErr("audience must be one of PERSON, AGENT, RUNNER")
)

type listErr string

func (e listErr) Error() string { return string(e) }

// orEmpty keeps a JSON array an array. A consumer handed null for a field
// documented as a list has to special-case it, and the one that forgets
// discovers it on the one tool that declares no material fields.
func orEmpty(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
