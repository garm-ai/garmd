package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/garm-ai/garmd/internal/authn"
)

// metaServer stands in for an issuer publishing RFC 8414 metadata.
func metaServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const stsMeta = `{"issuer":"https://sts.example","garm_audience":"garm://garmd",
  "token_endpoint_auth_signing_alg_values_supported":["ES256"]}`

// The trap, caught. Both defaults are reasonable in isolation; together they
// refuse every token at runtime with a message about the token.
func TestAnAudienceMismatchIsAStartupFailure(t *testing.T) {
	srv := metaServer(t, http.StatusOK, stsMeta)

	err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://sts.example", "garm")
	if err == nil {
		t.Fatal("a deployment configured with --audience garm against an issuer " +
			"minting garm://garmd started cleanly; every token it ever sees will " +
			"be refused")
	}
	// The message has to name both sides, or it replaces one mystery with
	// another.
	for _, want := range []string{"garm://garmd", "--audience"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

func TestAnIssuerMismatchIsAStartupFailure(t *testing.T) {
	srv := metaServer(t, http.StatusOK, stsMeta)
	err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://wrong.example", "garm://garmd")
	if err == nil {
		t.Fatal("an issuer mismatch started cleanly")
	}
	if !strings.Contains(err.Error(), "https://sts.example") {
		t.Errorf("the error does not say what the issuer actually mints: %v", err)
	}
}

func TestAgreementIsSilent(t *testing.T) {
	srv := metaServer(t, http.StatusOK, stsMeta)
	if err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://sts.example", "garm://garmd"); err != nil {
		t.Errorf("a correctly configured deployment was refused: %v", err)
	}
}

// Absent metadata is not disagreement.
//
// The dev IdP publishes none, and neither does a stock enterprise IdP.
// Refusing to start against one would turn a safety net into a deployment
// obstacle, and every deployment before this check existed was unchecked.
func TestAnIssuerThatPublishesNothingIsAccepted(t *testing.T) {
	srv := metaServer(t, http.StatusNotFound, "")
	if err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://anything", "garm"); err != nil {
		t.Errorf("a 404 was treated as a disagreement: %v", err)
	}
}

// Neither is unreachable. The JWKS fetch is lazy and reports its own failure
// with a better message; failing startup here would make this check the thing
// that takes a deployment down when an unrelated endpoint is slow.
func TestAnUnreachableIssuerDoesNotBlockStartup(t *testing.T) {
	if err := authn.CheckIssuerMetadata(context.Background(),
		"http://127.0.0.1:1/.well-known/jwks.json", "https://anything", "garm"); err != nil {
		t.Errorf("an unreachable metadata endpoint failed startup: %v", err)
	}
}

// Garbage is not disagreement either. Something that is not this document
// should not be read as one.
func TestAnUnparseableDocumentIsIgnored(t *testing.T) {
	srv := metaServer(t, http.StatusOK, "<html>nope</html>")
	if err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://anything", "garm"); err != nil {
		t.Errorf("unparseable metadata failed startup: %v", err)
	}
}

// An issuer signing with something this build will never accept is a
// disagreement worth catching at startup rather than per token.
func TestAnUnacceptableSigningAlgorithmIsRefused(t *testing.T) {
	srv := metaServer(t, http.StatusOK,
		`{"issuer":"https://i","garm_audience":"a",
		  "token_endpoint_auth_signing_alg_values_supported":["EdDSA"]}`)
	err := authn.CheckIssuerMetadata(context.Background(),
		srv.URL+"/.well-known/jwks.json", "https://i", "a")
	if err == nil {
		t.Fatal("an issuer signing only EdDSA was accepted; this build rejects " +
			"every token it mints")
	}
	if !strings.Contains(err.Error(), "EdDSA") {
		t.Errorf("the error does not name the algorithm: %v", err)
	}
}

// A malformed jwks url is the operator's problem and worth saying so.
func TestAMalformedJWKSURLIsReported(t *testing.T) {
	if err := authn.CheckIssuerMetadata(context.Background(), "not-a-url", "i", "a"); err == nil {
		t.Error("a jwks url with no scheme or host was accepted")
	}
}
