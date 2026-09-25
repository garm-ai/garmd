package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/garm-ai/garmd/internal/authn"
)

func TestPrincipalFuncVerifiesTheTokenTheMiddlewareCarried(t *testing.T) {
	now := time.Now()
	v, key, _ := harness(t, now)
	token := sign(t, key, "k1", goodBody(now))

	pf := authn.PrincipalFunc(v, nil)
	var gotErr error
	var gotSubject string

	h := authn.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := pf(r.Context())
		gotErr = err
		if p != nil {
			gotSubject = p.Subject
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotErr != nil {
		t.Fatalf("PrincipalFunc returned %v for a valid token", gotErr)
	}
	if gotSubject != "user-1" {
		t.Errorf("Subject = %q, want user-1", gotSubject)
	}
}

func TestPrincipalFuncRefusesWhenThereIsNoToken(t *testing.T) {
	now := time.Now()
	v, _, _ := harness(t, now)
	pf := authn.PrincipalFunc(v, nil)

	if _, err := pf(context.Background()); err == nil {
		t.Error("PrincipalFunc returned a principal with no token in the context; " +
			"an unauthenticated call must not acquire an identity by default")
	}
}

func TestPrincipalFuncRefusesAMalformedAuthorizationHeader(t *testing.T) {
	now := time.Now()
	v, _, _ := harness(t, now)
	pf := authn.PrincipalFunc(v, nil)

	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "token-without-scheme"} {
		var err error
		h := authn.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err = pf(r.Context())
		}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if err == nil {
			t.Errorf("Authorization %q produced a principal", header)
		}
	}
}

// The middleware carries the token; it does NOT verify it. That split is
// deliberate and worth a test: verification happens inside PrincipalFunc, so
// a bad token is refused by the governance chain's step 1, which ledgers the
// refusal with its cause. A middleware that 401'd here instead would deny the
// call before the chain ever saw it, and the ledger would have no row for it.
func TestMiddlewareDoesNotRejectBadTokensItself(t *testing.T) {
	now := time.Now()
	v, _, _ := harness(t, now)
	pf := authn.PrincipalFunc(v, nil)

	reached := false
	h := authn.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if _, err := pf(r.Context()); err == nil {
			t.Error("a garbage token verified")
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("the middleware refused a bad token itself; verification belongs to " +
			"PrincipalFunc so the refusal is ledgered by the chain")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("the middleware wrote status %d; it must not answer the request", rec.Code)
	}
}
