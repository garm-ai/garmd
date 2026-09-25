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

// codeFor maps a chain refusal to the connect code the connect surface
// answers with, and reports whether err was one of them.
//
// An error that is NOT the chain's own — a resolver's, most of all — keeps
// its own code, which is what makes a resolver's NOT_FOUND survive scrubbing
// as a NOT_FOUND.
func codeFor(err error) (connect.Code, bool) {
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
