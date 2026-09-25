package authn

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/garm-ai/garmd/internal/toolplane"
)

// tokenKey is unexported so nothing outside this package can put a token into
// a context. A caller who could would be able to hand the verifier a token
// the transport never carried.
type tokenKey struct{}

// Middleware lifts the bearer token off the request and into the context.
//
// It does NOT verify it, and that split is the point. Verification happens in
// PrincipalFunc, which the governance chain calls as step 1 — so a bad token
// is refused by the chain, which ledgers the refusal with its cause and
// answers with the sentinel error. A middleware that returned 401 itself
// would deny the call before the chain ever saw it, and the ledger would have
// no row for a request that was definitely made.
//
// It is also why this is ordinary net/http middleware rather than a connect
// interceptor: MCP and, later, other front doors put their credential in the
// same place, and the transport should not have to be taught twice.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := bearer(r.Header.Get("Authorization")); ok {
			r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok))
		}
		next.ServeHTTP(w, r)
	})
}

// bearer extracts the token from an Authorization header value.
//
// The scheme comparison is case-insensitive because RFC 7235 says the scheme
// is; the token itself is not touched.
func bearer(header string) (string, bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(rest)
	if tok == "" {
		return "", false
	}
	return tok, true
}

// PrincipalFunc adapts a Verifier to toolplane.Config.PrincipalFunc.
//
// logger may be nil. When it is not, compartment names the token asserted
// that this build does not declare are logged once per call: Fold drops them
// rather than refusing the token — an IdP-side typo should cost access, not
// availability — and dropping authority silently is how a typo becomes an
// unexplained permission denial nobody can trace.
//
// The token is never logged, at any level.
func PrincipalFunc(v *Verifier, logger *slog.Logger) func(context.Context) (*toolplane.Principal, error) {
	return func(ctx context.Context) (*toolplane.Principal, error) {
		tok, ok := ctx.Value(tokenKey{}).(string)
		if !ok || tok == "" {
			// No credential is not an error about the credential: say what
			// is missing, not what was wrong with it.
			return nil, fmt.Errorf("authn: no bearer token on the request")
		}
		p, dropped, err := v.Verify(ctx, tok)
		if err != nil {
			return nil, err
		}
		if len(dropped) > 0 && logger != nil {
			logger.Warn("token asserted compartments this build does not declare; "+
				"they were dropped and the caller's authority is narrower than its token claims",
				"subject", p.Subject,
				"dropped", dropped)
		}
		return p, nil
	}
}
