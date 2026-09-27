package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/garm-ai/garmd/internal/conformance"
)

// newFormMinterKey returns a fresh EC key and its PKCS#8 PEM encoding, the
// shape ParseECPrivateKeyPEM must accept.
func newFormMinterKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, pemBytes
}

// decodeAssertionPayload reads the unverified claims out of a compact JWS.
// Verifying the signature is not the point of these tests — the STS under
// test does that; here we only need to see what FormMinter put in the
// payload.
func decodeAssertionPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion is not a compact JWS (want 3 parts, got %d): %q", len(parts), compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding client_assertion payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshalling client_assertion payload: %v", err)
	}
	return claims
}

func TestParseECPrivateKeyPEMAcceptsPKCS8(t *testing.T) {
	key, pemBytes := newFormMinterKey(t)
	got, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Fatal("parsed key does not match the original")
	}
}

func TestParseECPrivateKeyPEMAcceptsSEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	got, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Fatal("parsed key does not match the original")
	}
}

// TestFormMinterToken pins the response contract: a 200 with a JSON body
// yields the access_token, and a non-200 is a *RefusalError carrying the
// status — the same distinction HTTPMinter's own tests pin for its shape.
func TestFormMinterToken(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantToken  string
		wantRefuse bool

		// wantErr covers the two edge paths that are neither a success nor a
		// RefusalError: a 200 whose body will not decode as JSON, and a 200
		// that decodes but carries no access_token. Both must produce an
		// ordinary error (never a *RefusalError — the suite's mintError
		// assertion depends on that split holding here too) and an empty
		// token.
		wantErr bool
		// wantErrBodyPart, when set, pins that the error names the response
		// body — Finding 1: the malformed-JSON path used to drop it.
		wantErrBodyPart string
	}{
		{
			name:      "200 with a JSON body returns access_token",
			status:    http.StatusOK,
			body:      `{"access_token":"header.payload.signature","issued_token_type":"urn:ietf:params:oauth:token-type:jwt","token_type":"N_A"}`,
			wantToken: "header.payload.signature",
		},
		{
			name:       "non-200 is a refusal carrying the status and body",
			status:     http.StatusForbidden,
			body:       `{"error":"invalid_client","error_description":"unknown client id"}`,
			wantRefuse: true,
		},
		{
			name:            "200 with a body that will not decode as JSON is an error naming the body, not a refusal",
			status:          http.StatusOK,
			body:            `<html><body>502 Bad Gateway</body></html>`,
			wantErr:         true,
			wantErrBodyPart: "502 Bad Gateway",
		},
		{
			name:    "200 with valid JSON but no access_token is an error, not a refusal",
			status:  http.StatusOK,
			body:    `{"issued_token_type":"urn:ietf:params:oauth:token-type:jwt","token_type":"N_A"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			t.Cleanup(srv.Close)

			_, pemBytes := newFormMinterKey(t)
			key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
			if err != nil {
				t.Fatal(err)
			}
			m := conformance.FormMinter{
				BaseURL: srv.URL, ClientID: "client-1", Audience: "https://sts.test/token", Key: key,
			}

			tok, err := m.Token(context.Background(), map[string]string{"user": "alice"})
			switch {
			case tt.wantRefuse:
				if err == nil {
					t.Fatalf("status %d produced no error", tt.status)
				}
				var refusal *conformance.RefusalError
				if !errors.As(err, &refusal) {
					t.Fatalf("a non-200 must be a *RefusalError, got %T: %v", err, err)
				}
				if refusal.Status != tt.status {
					t.Fatalf("refusal must carry the status, got %d want %d", refusal.Status, tt.status)
				}
				if !strings.Contains(refusal.Body, "invalid_client") {
					t.Fatalf("refusal must carry the minter's reason, got %q", refusal.Body)
				}
			case tt.wantErr:
				if err == nil {
					t.Fatalf("body %q produced no error; a later change that treated this as success "+
						"would pass this suite and only fail downstream, in verification", tt.body)
				}
				var refusal *conformance.RefusalError
				if errors.As(err, &refusal) {
					t.Fatalf("a malformed 200 response was reported as a refusal, got %T: %v", err, err)
				}
				if tok != "" {
					t.Fatalf("got token %q on an error path, want empty", tok)
				}
				if tt.wantErrBodyPart != "" && !strings.Contains(err.Error(), tt.wantErrBodyPart) {
					t.Fatalf("error must name the response body (want it to contain %q), got: %v",
						tt.wantErrBodyPart, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if tok != tt.wantToken {
					t.Fatalf("got token %q want %q", tok, tt.wantToken)
				}
			}
		})
	}
}

// TestFormMinterDoesNotReportAConnectionFailureAsARefusal is the case that
// makes `mintError` trustworthy for this minter too: an unreachable STS must
// stay an ordinary error, never a *RefusalError, or a suite of nothing but
// refusal cases pointed at a dead port would report ok.
func TestFormMinterDoesNotReportAConnectionFailureAsARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing is listening on that port any more

	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{BaseURL: base, ClientID: "client-1", Audience: "https://sts.test/token", Key: key}

	_, err = m.Token(context.Background(), map[string]string{"user": "alice"})
	if err == nil {
		t.Fatal("a dead port produced no error")
	}
	var refusal *conformance.RefusalError
	if errors.As(err, &refusal) {
		t.Fatalf("a minter that could not be reached was reported as a refusal: %v", err)
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("the error must say the minter was unreachable, got: %v", err)
	}
}

// TestFormMinterPostsFormEncodedParamsAndClientAssertion is the request-shape
// contract: POST, form-encoded (not query string, not JSON), every mint
// param present, and a client_assertion whose iss/sub is the client id and
// whose aud is the token endpoint.
func TestFormMinterPostsFormEncodedParamsAndClientAssertion(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotForm        url.Values
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("request body was not form-encoded: %v", err)
		}
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok"}`)
	}))
	t.Cleanup(srv.Close)

	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{
		BaseURL: srv.URL, ClientID: "client-42", Audience: "https://sts.test/token", Key: key,
	}

	if _, err := m.Token(context.Background(), map[string]string{
		"user": "alice", "as": "triage-bot",
	}); err != nil {
		t.Fatal(err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("got method %q want POST", gotMethod)
	}
	if !strings.HasPrefix(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("got Content-Type %q want application/x-www-form-urlencoded", gotContentType)
	}
	if gotForm.Get("user") != "alice" || gotForm.Get("as") != "triage-bot" {
		t.Fatalf("mint params were not carried through, got %v", gotForm)
	}
	assertion := gotForm.Get("client_assertion")
	if assertion == "" {
		t.Fatal("no client_assertion was posted")
	}
	claims := decodeAssertionPayload(t, assertion)
	if claims["iss"] != "client-42" {
		t.Fatalf("client_assertion iss = %v, want client-42", claims["iss"])
	}
	if claims["sub"] != "client-42" {
		t.Fatalf("client_assertion sub = %v, want client-42", claims["sub"])
	}
	if claims["aud"] != "https://sts.test/token" {
		t.Fatalf("client_assertion aud = %v, want https://sts.test/token", claims["aud"])
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Fatal("client_assertion has no jti")
	}
	if claims["exp"] == nil {
		t.Fatal("client_assertion has no exp")
	}
}

// TestFormMinterUsesAFreshJTIPerCall is the test that matters most: the STS
// under test refuses a replayed jti, so if two calls ever shared one, every
// case after the first would fail for a reason having nothing to do with
// the case being tested. Verified by decoding the assertion the wire
// actually carried on each call, not by inspecting FormMinter's internals.
func TestFormMinterUsesAFreshJTIPerCall(t *testing.T) {
	var assertions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("request body was not form-encoded: %v", err)
		}
		assertions = append(assertions, r.Form.Get("client_assertion"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok"}`)
	}))
	t.Cleanup(srv.Close)

	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{
		BaseURL: srv.URL, ClientID: "client-1", Audience: "https://sts.test/token", Key: key,
	}

	for i := 0; i < 2; i++ {
		if _, err := m.Token(context.Background(), map[string]string{"user": "alice"}); err != nil {
			t.Fatal(err)
		}
	}

	if len(assertions) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(assertions))
	}
	jti1 := decodeAssertionPayload(t, assertions[0])["jti"]
	jti2 := decodeAssertionPayload(t, assertions[1])["jti"]
	if jti1 == "" || jti1 == nil || jti2 == "" || jti2 == nil {
		t.Fatalf("a jti was empty: first=%v second=%v", jti1, jti2)
	}
	if jti1 == jti2 {
		t.Fatalf("two successive calls carried the same jti (%v); a replayed jti is refused by the service under test", jti1)
	}
}
