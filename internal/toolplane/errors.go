package toolplane

import (
	"errors"

	"connectrpc.com/connect"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
)

// The refusals the chain itself produces.
//
// They are transport-neutral on purpose: Core has no connect in it, and MCP
// and the catalogue will map the same set into their own vocabularies. Each
// is paired with a connect code by codeFor below, and with the static text
// for that code by staticMessages — so what a caller sees is a code and a
// sentence, while the reason travels to the ledger as ErrorDetail and
// nowhere else.
//
// They carry no detail themselves. Everything a human needs is already on
// the event; a second copy here would only be a second thing to leak.
var (
	errNotFound         = errors.New("not found")
	errPermissionDenied = errors.New("permission denied")
	errUnauthenticated  = errors.New("unauthenticated")
	errUnimplemented    = errors.New("unimplemented")
	errInternal         = errors.New("internal error")
	errInvalidArgument  = errors.New("invalid argument")

	// errUnavailable is step 6's own refusal (core.go's checkAvailability):
	// a tool's service is missing, unimplemented, or contract-incompatible
	// right now. It is deliberately distinct from errNotFound — the tool
	// stays LISTED (Visible is never consulted here), because existence is
	// information and availability is not authorization (design spec's
	// stack B).
	errUnavailable = errors.New("unavailable")
)

// ToolRefusal is a tool that ran and answered with one of the codes a tool
// may answer with (toolRefusals). It is a refusal the TOOL decided, and the
// chain carries it to the caller as such — status = the code, a static
// sentence for it — rather than as this daemon's own internal error, which
// is what a model reads as "retry".
//
// Code is the transport's spelling ("404"). The tool's message is not here:
// it went to the ledger's error_detail, as every other refusal's reason
// does, and the wire gets Message() — a sentence this package wrote.
type ToolRefusal struct {
	Code string
}

func (e *ToolRefusal) Error() string { return "the tool refused the call with " + e.Code }

// Message is the static sentence for this code, safe for any caller.
func (e *ToolRefusal) Message() string { return toolRefusals[e.Code].message }

// ErrorKindToolRefused is the ledger's error_kind for a ToolRefusal row.
const ErrorKindToolRefused = "tool_refused"

// toolRefusals is every code a tool may answer with and be understood — the
// codes tool-go's toolbind.CodedError can carry — with the connect code the
// chain classifies it as and the sentence the wire gets. A code not here
// (500, a typo, a code someone invents) stays what it always was: internal,
// with the tool's words on the ledger.
//
// The sentences say what KIND of answer this was and nothing the tool said.
// A tool's message is page content by another route — a fetcher that says
// "https://intranet/… is off the allowlist" has just disclosed the URL — so
// it is never on the wire, whatever the tool promised.
var toolRefusals = map[string]struct {
	code    connect.Code
	message string
}{
	"400": {connect.CodeInvalidArgument, "the tool rejected the request as malformed"},
	"403": {connect.CodePermissionDenied, "the tool refused this request"},
	"404": {connect.CodeNotFound, "the tool found nothing for this request"},
	"409": {connect.CodeAborted, "the tool reports a conflict with its current state"},
	"415": {connect.CodeInvalidArgument, "the tool does not accept the media type it was given"},
	"422": {connect.CodeInvalidArgument, "the tool could not process the request as given"},
	"429": {connect.CodeResourceExhausted, "the tool is limiting its rate; retry later"},
	"502": {connect.CodeUnavailable, "the tool's upstream answered with an error"},
	"504": {connect.CodeDeadlineExceeded, "the tool's upstream did not answer in time"},
}

// codedAnswer is what the chain asks a resolver error for: did the tool
// answer with a code. transport.CodedError satisfies it; the chain does not
// import transport to know that, because a resolver is a function and the
// chain has no business knowing which hop it wraps.
type codedAnswer interface {
	error
	ToolCode() string
	ToolMessage() string
}

// toolRefusalOf reports whether err is a tool's coded answer with a code the
// chain understands, and returns the tool's message for the ledger.
func toolRefusalOf(err error) (code, message string, ok bool) {
	var coded codedAnswer
	if !errors.As(err, &coded) {
		return "", "", false
	}
	if _, known := toolRefusals[coded.ToolCode()]; !known {
		return "", "", false
	}
	return coded.ToolCode(), coded.ToolMessage(), true
}

// codeFor maps a chain refusal to the connect code the connect surface
// answers with, and reports whether err was one of them.
//
// An error that is NOT the chain's own — a resolver's, most of all — keeps
// its own code, which is what makes a resolver's NOT_FOUND survive scrubbing
// as a NOT_FOUND.
func codeFor(err error) (connect.Code, bool) {
	var refused *ToolRefusal
	if errors.As(err, &refused) {
		if r, known := toolRefusals[refused.Code]; known {
			return r.code, true
		}
		return connect.CodeInternal, true
	}
	switch {
	case errors.Is(err, errNotFound):
		return connect.CodeNotFound, true
	case errors.Is(err, errPermissionDenied):
		return connect.CodePermissionDenied, true
	case errors.Is(err, errUnauthenticated):
		return connect.CodeUnauthenticated, true
	case errors.Is(err, errUnimplemented):
		return connect.CodeUnimplemented, true
	case errors.Is(err, errInternal):
		return connect.CodeInternal, true
	case errors.Is(err, errInvalidArgument):
		return connect.CodeInvalidArgument, true
	case errors.Is(err, errUnavailable):
		return connect.CodeUnavailable, true
	}
	return 0, false
}

// CodeOf reports the connect code a chain refusal carries.
//
// A surface needs this to answer at all: the chain's refusals are
// transport-neutral sentinels, and something has to decide that errNotFound
// is a 404 before a status line can be written. Pairing it with ScrubError
// gives a surface the whole answer — the code from here, the text from
// there, and the reason left on the ledger where it belongs.
//
// An error that is NOT the chain's own keeps whatever code it already
// carries, which is what lets a resolver's NOT_FOUND survive as a NOT_FOUND.
func CodeOf(err error) connect.Code {
	return connect.CodeOf(asConnectError(err))
}

// CodeOfForTest is CodeOf as connect's own lowercase wire spelling
// ("unavailable", "not_found"), for a test that wants to assert on a code
// without importing connect-rpc or restating its String() spellings.
//
// It survives CodeOf being exported because the two answer different
// questions: a surface needs the typed Code to choose a status, and a test
// needs the string it will see on the wire. Both go through asConnectError
// first, and that is the part worth knowing — a raw chain refusal is a
// transport-neutral sentinel with no code of its own until something assigns
// one, so a test calling Invoke directly would otherwise see CodeUnknown
// whichever refusal actually fired.
func CodeOfForTest(err error) string {
	return CodeOf(err).String()
}

// asConnectError gives a chain refusal its connect code, and leaves anything
// else for connect.CodeOf to classify. Its result still goes through
// ScrubError: the code is decided here, the text there.
func asConnectError(err error) error {
	if err == nil {
		return nil
	}
	if code, ok := codeFor(err); ok {
		return connect.NewError(code, err)
	}
	return err
}

// staticMessages map a connect code to text safe to return to any caller.
var staticMessages = map[connect.Code]string{
	connect.CodeNotFound:         "not found",
	connect.CodePermissionDenied: "permission denied",
	connect.CodeInvalidArgument:  "invalid argument",
	connect.CodeInternal:         "internal error",
	connect.CodeUnavailable:      "unavailable",
	connect.CodeUnauthenticated:  "unauthenticated",
	connect.CodeUnimplemented:    "unimplemented",
	// The codes a ToolRefusal can classify as, so a surface that scrubs one
	// without reading the refusal still has a sentence for it.
	connect.CodeAborted:           "aborted",
	connect.CodeResourceExhausted: "resource exhausted",
	connect.CodeDeadlineExceeded:  "deadline exceeded",
}

// ScrubError replaces an error's message with a static one, preserving the code
// and any typed ErrorInfo detail.
//
// Resolver errors routinely interpolate the value they were protecting —
// "user with email ada@corp.com not found" — and the sanitizer never sees them,
// because it operates on response messages. Detailed text belongs in the
// ledger; the wire gets a code.
func ScrubError(err error) error {
	if err == nil {
		return nil
	}
	code := connect.CodeOf(err)
	msg, ok := staticMessages[code]
	if !ok {
		msg = "request failed"
	}
	out := connect.NewError(code, errStatic(msg))

	var ce *connect.Error
	if errors.As(err, &ce) {
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if _, isInfo := v.(*toolv1.ErrorInfo); isInfo {
					out.AddDetail(d)
				}
			}
		}
	}
	return out
}

type errStatic string

func (e errStatic) Error() string { return string(e) }
