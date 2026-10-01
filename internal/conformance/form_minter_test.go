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

// TestFormMinterFetchesSubjectTokenFromUpstream pins the two-step: a case
// carrying subject_user causes a GET to UpstreamURL first, and the raw body
// that comes back is sent to the STS as subject_token — never as
// subject_user, and never as subject_tenant, which name nothing the STS's
// exchange reads.
func TestFormMinterFetchesSubjectTokenFromUpstream(t *testing.T) {
	var upstreamRequest *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequest = r
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "upstream-issued-subject-token\n") // devkit trims a trailing newline too
	}))
	t.Cleanup(upstream.Close)

	var stsForm url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("request body was not form-encoded: %v", err)
		}
		stsForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"delegation-token"}`)
	}))
	t.Cleanup(sts.Close)

	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{
		BaseURL: sts.URL, ClientID: "client-1", Audience: "https://sts.test/token", Key: key,
		UpstreamURL: upstream.URL,
	}

	tok, err := m.Token(context.Background(), map[string]string{
		"grant_type":     "urn:ietf:params:oauth:grant-type:token-exchange",
		"agent":          "order-assistant",
		"subject_user":   "C",
		"subject_tenant": "acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "delegation-token" {
		t.Fatalf("got token %q want %q", tok, "delegation-token")
	}

	if upstreamRequest == nil {
		t.Fatal("no request reached the upstream IdP")
	}
	if upstreamRequest.Method != http.MethodGet {
		t.Fatalf("upstream fetch used %s, want GET", upstreamRequest.Method)
	}
	if got := upstreamRequest.URL.Query().Get("sub"); got != "C" {
		t.Fatalf("upstream fetch sub = %q, want %q", got, "C")
	}
	if got := upstreamRequest.URL.Query().Get("tenant"); got != "acme" {
		t.Fatalf("upstream fetch tenant = %q, want %q", got, "acme")
	}

	if got := stsForm.Get("subject_token"); got != "upstream-issued-subject-token" {
		t.Fatalf("subject_token posted to the STS = %q, want the upstream's raw body", got)
	}
	if stsForm.Get("subject_user") != "" {
		t.Fatal("subject_user was forwarded to the STS as a form field; it must be consumed, not sent")
	}
	if stsForm.Get("subject_tenant") != "" {
		t.Fatal("subject_tenant was forwarded to the STS as a form field; it must be consumed, not sent")
	}
	if stsForm.Get("agent") != "order-assistant" {
		t.Fatalf("an ordinary mint param (agent) was not carried through, got form %v", stsForm)
	}
}

// TestFormMinterSubjectUserWithoutUpstreamURLFails is the fail-outright
// contract: a case that asks for the two-step gets one, or an error — never
// a silent one-step degrade that would forward subject_user itself and let
// the STS refuse for a reason that has nothing to do with the case.
func TestFormMinterSubjectUserWithoutUpstreamURLFails(t *testing.T) {
	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{BaseURL: "http://127.0.0.1:1", ClientID: "client-1", Audience: "https://sts.test/token", Key: key}

	_, err = m.Token(context.Background(), map[string]string{"subject_user": "C"})
	if err == nil {
		t.Fatal("subject_user with no UpstreamURL configured produced no error")
	}
	if !strings.Contains(err.Error(), "UpstreamURL") {
		t.Fatalf("error must say UpstreamURL is missing, got: %v", err)
	}
}

// TestFormMinterSubjectTokenFetchFailureIsNotARefusal is the same contract
// TestFormMinterDoesNotReportAConnectionFailureAsARefusal pins for the STS
// itself, one hop earlier: a subject-token fetch that fails — here, the
// upstream IdP answering with an error — must never surface as a
// *RefusalError, or a suite of nothing but mintError cases pointed at a
// broken upstream would report ok while checking nothing.
func TestFormMinterSubjectTokenFetchFailureIsNotARefusal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such persona", http.StatusNotFound)
	}))
	t.Cleanup(upstream.Close)

	_, pemBytes := newFormMinterKey(t)
	key, err := conformance.ParseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	m := conformance.FormMinter{
		BaseURL: "http://127.0.0.1:1", ClientID: "client-1", Audience: "https://sts.test/token", Key: key,
		UpstreamURL: upstream.URL,
	}

	_, err = m.Token(context.Background(), map[string]string{"subject_user": "nobody"})
	if err == nil {
		t.Fatal("a 404 from the upstream IdP produced no error")
	}
	var refusal *conformance.RefusalError
	if errors.As(err, &refusal) {
		t.Fatalf("an upstream IdP failure was reported as a *RefusalError, which must mean the STS refused: %v", err)
	}
}

// approveServers stands in for the two services a grant case touches: the
// upstream IdP that mints the APPROVER's own bearer, and the STS's approval
// endpoint. Both in process, because garmd may not import either.
type approveServers struct {
	upstream *httptest.Server
	sts      *httptest.Server

	upstreamQuery url.Values // what the approver's token was asked for
	authHeader    string     // what /approve saw in Authorization
	contentType   string
	method        string
	body          map[string]any
}

func startApproveServers(t *testing.T, approveStatus int, approveBody string, upstreamStatus int) *approveServers {
	t.Helper()
	s := &approveServers{}
	s.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.upstreamQuery = r.URL.Query()
		if upstreamStatus != http.StatusOK {
			http.Error(w, "upstream is unwell", upstreamStatus)
			return
		}
		fmt.Fprintln(w, "approver.bearer.token")
	}))
	t.Cleanup(s.upstream.Close)
	s.sts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.method = r.Method
		s.authHeader = r.Header.Get("Authorization")
		s.contentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&s.body)
		if approveStatus != http.StatusOK {
			http.Error(w, "denied", approveStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, approveBody)
	}))
	t.Cleanup(s.sts.Close)
	return s
}

func grantCase() conformance.Grant {
	return conformance.Grant{
		Approver: "jdoe", ApproverTenant: "acme", ApproverClearance: "RESTRICTED",
		ApproverCompartments: []string{"financial", "pii-contact"},
		Tool:                 "payments.v1.initiate_payment",
		Subject:              "employee:jdoe",
		Material:             map[string]string{"amount_minor_units": "25000"},
		ExpectApprover:       "employee:jdoe",
	}
}

// The approval request is the one place the calling service and the human
// are BOTH authenticated, and by different credentials: the service by its
// client_assertion in the body, the human by their own bearer in the header.
// Sending the human's token as the service's credential, or the reverse,
// would be an approval attributed to the wrong party.
func TestFormMinterGrantPostsTheApprovalRequest(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusOK, `{"grant":"g.r.t","expires_in":900}`, http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "conformance-client",
		Audience: "https://sts.example/token", Key: key, UpstreamURL: s.upstream.URL,
	}

	got, err := m.Approve(context.Background(), grantCase().Request())
	if err != nil {
		t.Fatal(err)
	}
	if got != "g.r.t" {
		t.Fatalf("grant = %q, want the token from the response envelope", got)
	}
	if s.method != http.MethodPost {
		t.Errorf("method = %s, want POST", s.method)
	}
	if !strings.HasPrefix(s.contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", s.contentType)
	}
	if s.authHeader != "Bearer approver.bearer.token" {
		t.Errorf("Authorization = %q; the APPROVER's own bearer belongs here, "+
			"not the calling service's assertion", s.authHeader)
	}
	if s.body["tool"] != "payments.v1.initiate_payment" || s.body["subject"] != "employee:jdoe" {
		t.Errorf("tool/subject: %+v", s.body)
	}
	material, _ := s.body["material"].(map[string]any)
	if material["amount_minor_units"] != "25000" {
		t.Errorf("material = %+v; the issuer digests what it is GIVEN, so the "+
			"values must arrive verbatim", s.body["material"])
	}
	assertion, _ := s.body["client_assertion"].(string)
	if assertion == "" {
		t.Fatal("no client_assertion in the approval request; the calling service must authenticate")
	}
	if claims := decodeAssertionPayload(t, assertion); claims["aud"] != "https://sts.example/token" {
		t.Errorf("client_assertion aud = %v, want the token endpoint's own name", claims["aud"])
	}
	if s.body["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %v", s.body["client_assertion_type"])
	}
}

// The issuer RECORDS the approver's authority rather than resolving it, so
// the case's declared clearance and compartments have to reach the upstream
// IdP that mints the approver's token — there is nowhere else to put them,
// and a grant recording no authority is one this daemon refuses for a reason
// that names the wrong system.
func TestFormMinterGrantAsksUpstreamForTheApproversAuthority(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusOK, `{"grant":"g.r.t","expires_in":900}`, http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "conformance-client",
		Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	if _, err := m.Approve(context.Background(), grantCase().Request()); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"sub": "jdoe", "tenant": "acme", "clearance": "RESTRICTED",
		"compartments": "financial,pii-contact",
	} {
		if got := s.upstreamQuery.Get(k); got != want {
			t.Errorf("upstream ?%s= %q, want %q", k, got, want)
		}
	}
}

// Same contract as Token's: the service under test answered and said no.
func TestFormMinterGrantReportsARefusalAsARefusalError(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusForbidden, "", http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	_, err := m.Approve(context.Background(), grantCase().Request())
	var refusal *conformance.RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a *RefusalError", err)
	}
	if refusal.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", refusal.Status)
	}
}

// And the mirror: an upstream IdP that never answered says nothing at all
// about the approval endpoint, so it must never read as a refusal.
func TestFormMinterGrantUpstreamFailureIsNotARefusal(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusOK, `{"grant":"g"}`, http.StatusInternalServerError)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	_, err := m.Approve(context.Background(), grantCase().Request())
	if err == nil {
		t.Fatal("an upstream IdP that refused the approver's token produced no error")
	}
	var refusal *conformance.RefusalError
	if errors.As(err, &refusal) {
		t.Fatal("an upstream failure was reported as a refusal by the service under test")
	}
}

func TestFormMinterGrantWithoutUpstreamURLFails(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusOK, `{"grant":"g"}`, http.StatusOK)
	m := conformance.FormMinter{BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key}
	if _, err := m.Approve(context.Background(), grantCase().Request()); err == nil {
		t.Fatal("a grant case ran without an upstream IdP to mint the approver's token")
	}
}

// An approval response with no grant in it is a 200 that granted nothing.
func TestFormMinterGrantRejectsAnEmptyEnvelope(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusOK, `{"expires_in":900}`, http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	if _, err := m.Approve(context.Background(), grantCase().Request()); err == nil {
		t.Fatal("a 200 carrying no grant was accepted")
	}
}

// F12a. A refusal case that omits the calling service's credential must
// actually omit it: the request goes out with no client_assertion key at
// all, and the type field stays so the refusal is about the missing
// assertion rather than about a missing type.
func TestFormMinterApproveOmitsTheClientAssertionWhenAsked(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusBadRequest, "", http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	req := grantCase().Request()
	req.OmitClientAssertion = true
	_, err := m.Approve(context.Background(), req)
	var refusal *conformance.RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a *RefusalError", err)
	}
	if _, present := s.body["client_assertion"]; present {
		t.Fatalf("client_assertion was sent (%v); the case asked for it to be omitted", s.body["client_assertion"])
	}
	if s.body["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %v; it must still be sent so the refusal is about the assertion", s.body["client_assertion_type"])
	}
	if s.authHeader != "Bearer approver.bearer.token" {
		t.Errorf("Authorization = %q; the approver's bearer is still presented", s.authHeader)
	}
}

// A delegated approver is minted by the upstream IdP with an `act` chain:
// the case names the actor and it becomes devkit's ?act= parameter. Without
// it the upstream mints a direct token, the STS accepts, and the case fails
// for a reason that has nothing to do with delegation.
func TestFormMinterApproveAsksUpstreamForADelegatedApprover(t *testing.T) {
	key, _ := newFormMinterKey(t)
	s := startApproveServers(t, http.StatusBadRequest, "", http.StatusOK)
	m := conformance.FormMinter{
		BaseURL: s.sts.URL, ClientID: "c", Audience: "aud", Key: key, UpstreamURL: s.upstream.URL,
	}
	req := grantCase().Request()
	req.ApproverActor = "agent:order-assistant"
	if _, err := m.Approve(context.Background(), req); err == nil {
		t.Fatal("a 400 produced no error")
	}
	if got := s.upstreamQuery.Get("act"); got != "agent:order-assistant" {
		t.Fatalf("upstream ?act= %q, want agent:order-assistant", got)
	}

	// And a direct approver asks for no chain at all.
	if _, err := m.Approve(context.Background(), grantCase().Request()); err == nil {
		t.Fatal("a 400 produced no error")
	}
	if _, present := s.upstreamQuery["act"]; present {
		t.Fatalf("upstream ?act= was sent for a direct approver: %v", s.upstreamQuery)
	}
}
