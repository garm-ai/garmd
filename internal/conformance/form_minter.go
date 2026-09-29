package conformance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// FormMinter drives an RFC 8693 security token service: POST /token as
// application/x-www-form-urlencoded, authenticated with a signed
// client_assertion, answering with a JSON envelope.
//
// It exists alongside HTTPMinter because a second minter shape appeared that
// HTTPMinter cannot drive — a GET whose entire body is the token, versus a
// POST whose body is a form and whose response is JSON. Minter is the
// interface that lets Run stay ignorant of the difference; this is simply
// the second implementation of it.
//
// # The subject-token problem
//
// The STS's exchange requires a live, signed subject_token from a trusted
// upstream issuer (see exchange.go's step 2). A suite file is static and
// cannot hold one: it would expire within minutes, and committing a signed
// credential to a repository is wrong regardless.
//
// FormMinter closes that gap with an optional two-step, gated entirely on
// UpstreamURL being set. A case that carries the reserved mint param
// subjectUserParam ("subject_user") is asking FormMinter to fetch a fresh
// subject token for that identity from the upstream IdP first, then send it
// as subject_token — never both a caller-supplied subject_token and a
// subject_user in the same case; that would be an ambiguous request about
// which one wins.
//
// devkit plays the role of that upstream IdP in this codebase's own
// conformance run. Its *persona* endpoint (?user=) is not used for the STS
// suite: a case there names its own subject, tenant and claims, and the
// persona form would substitute the personas file's (devkit v0.1.0 attaches
// that file's tenant; the STS refuses a subject token with none). FormMinter
// therefore drives devkit's ad-hoc form —
// GET <upstream>/token?sub=<identity>&tenant=<tenant> — which attaches
// one. subjectUserParam's value becomes that request's sub, and the
// reserved subjectTenantParam ("subject_tenant") becomes its tenant. Both
// are consumed here and never forwarded to the STS's own POST body: neither
// is part of RFC 8693, and the STS has no field that would read them.
//
// # Two endpoints
//
// FormMinter drives both halves of the STS a suite can assert about: POST
// /token via Token, and POST /approve via Grant. Both hang off the same
// BaseURL and both authenticate with the same client_assertion — one
// registered client id and one key pair, not two — because they are two
// endpoints of one service and a second credential would be a second thing
// to rotate. Grant additionally carries the APPROVER'S own bearer in the
// Authorization header: the calling service says who it is in the body, and
// the human says who they are in the header.
type FormMinter struct {
	// BaseURL is the STS's origin. Requests go to BaseURL+"/token".
	BaseURL string

	// ClientID identifies this caller to the STS. It is both the issuer and
	// the subject of the client_assertion, per RFC 7523.
	ClientID string

	// Audience is the token endpoint's own name — the aud the STS expects
	// the assertion to carry. It is not the audience of the token being
	// requested.
	Audience string

	// Key signs the client_assertion with ES256.
	Key *ecdsa.PrivateKey

	Client *http.Client

	// UpstreamURL, when non-empty, is the base URL of an upstream IdP
	// FormMinter fetches a subject token from before calling the STS. See
	// the type doc comment. Left empty, a case carrying subject_user fails
	// outright rather than silently forwarding it to the STS as an
	// ordinary form field — the fold, not the mint request, is the STS's
	// contract to check, so a suite that expects a two-step must never be
	// able to pass by degrading into a one-step it did not ask for.
	UpstreamURL string
}

// subjectUserParam is the reserved mint param that asks FormMinter to fetch
// a subject token for this identity from UpstreamURL before minting. It is
// opaque like every other mint param — LoadSuite never inspects it — which
// is exactly what lets one suite format serve minters with different
// request shapes.
const subjectUserParam = "subject_user"

// subjectTenantParam is the reserved mint param naming the tenant to ask
// the upstream IdP for alongside subjectUserParam. Optional: an upstream
// that mints without a tenant claim (or a case that does not need one) may
// omit it.
const subjectTenantParam = "subject_tenant"

// subjectTokenParam is the RFC 8693 form field the fetched upstream token is
// sent to the STS under.
const subjectTokenParam = "subject_token"

// clientAssertionTypeJWTBearer is the RFC 7521 §4.2 name for the only kind
// of assertion either endpoint accepts. Sent on both, from one constant: two
// spellings of this string is a call authenticated at one endpoint and
// refused at the other for a reason that reads as a key problem.
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// tokenResponse is the STS's JSON envelope. Only AccessToken is consumed by
// Token; the rest is decoded anyway because a caller inspecting the raw
// response wants a struct, not a guess at the schema.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
}

// ParseECPrivateKeyPEM parses a PEM-encoded EC private key, accepting either
// PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) encoding — both are
// common output shapes for `openssl ecparam -genkey`.
func ParseECPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("conformance: no PEM block found in client key")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("conformance: parsing client key: %w", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("conformance: client key is a %T, not an EC private key", parsed)
	}
	return ecKey, nil
}

// clientAssertion signs one short-lived, single-use JWT: iss and sub are
// both the client id (RFC 7523's private_key_jwt shape), aud names the
// token endpoint, and jti is freshly random.
//
// A fresh jti EVERY call is not an optimization: the service under test
// refuses a replayed one, so reusing it would fail every case after the
// first for a reason that has nothing to do with the case.
func (m FormMinter) clientAssertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("conformance: generating a fresh jti: %w", err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": m.ClientID,
		"sub": m.ClientID,
		"aud": m.Audience,
		"jti": hex.EncodeToString(jti),
		"iat": now.Unix(),
		// Bounded and short: this assertion authenticates one call, not a
		// session.
		"exp": now.Add(60 * time.Second).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("conformance: encoding client_assertion claims: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: m.Key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("conformance: building the client_assertion signer: %w", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("conformance: signing client_assertion: %w", err)
	}
	return obj.CompactSerialize()
}

// Token asks the STS for a token. A non-200 is a *RefusalError carrying the
// status and body, exactly as HTTPMinter's contract requires; a transport
// failure stays an ordinary wrapped error so the two can never be confused
// by a case asserting mintError.
//
// If params carries subjectUserParam, Token first fetches a subject token
// from UpstreamURL (see the type doc comment) and sends it as subject_token
// instead. That fetch is never the STS's own answer, so a failure there —
// upstream unreachable, upstream refused, upstream returned garbage — is
// always an ordinary wrapped error, never a *RefusalError: mintError on a
// case asserts that the STS itself refused the exchange, and an upstream
// that never even got asked would make that assertion true for the wrong
// reason.
func (m FormMinter) Token(ctx context.Context, params map[string]string) (string, error) {
	assertion, err := m.clientAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	if subjectUser := form.Get(subjectUserParam); subjectUser != "" {
		if m.UpstreamURL == "" {
			return "", fmt.Errorf("conformance: case asks for a subject token (subject_user=%q) "+
				"but FormMinter has no UpstreamURL configured", subjectUser)
		}
		tenant := form.Get(subjectTenantParam)
		form.Del(subjectUserParam)
		form.Del(subjectTenantParam)

		subjectToken, err := m.fetchSubjectToken(ctx, subjectUser, tenant)
		if err != nil {
			// Deliberately an ordinary error, not a *RefusalError — see the
			// doc comment above.
			return "", fmt.Errorf("conformance: fetching a subject token from the upstream IdP: %w", err)
		}
		form.Set(subjectTokenParam, subjectToken)
	}

	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", clientAssertionTypeJWTBearer)

	u := strings.TrimSuffix(m.BaseURL, "/") + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c := m.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("minter unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// A refusal: the minter was reached and declined. Transport
		// failures above stay ordinary wrapped errors, so the two can
		// never be confused by a case asserting mintError. Same contract
		// as HTTPMinter, deliberately.
		return "", &RefusalError{
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(b)),
		}
	}

	var tr tokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return "", fmt.Errorf("conformance: decoding token response: %w (body: %s)", err, truncateBody(b))
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("conformance: token response has no access_token (body: %s)", truncateBody(b))
	}
	return tr.AccessToken, nil
}

// fetchSubjectToken asks the upstream IdP for a fresh token to present as
// subject_token. See fetchUpstreamToken for the shape and for why a failure
// here is never a *RefusalError.
func (m FormMinter) fetchSubjectToken(ctx context.Context, user, tenant string) (string, error) {
	q := url.Values{}
	q.Set("sub", user)
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	return m.fetchUpstreamToken(ctx, q)
}

// fetchUpstreamToken is a GET whose raw body IS the token — the same shape
// HTTPMinter itself drives against devkit — because the upstream IdP in this
// codebase's own conformance run is devkit, and this is the form of its
// /token endpoint that attaches the claims these cases need: a tenant for
// the exchange (see the type doc comment for why the persona ?user= form
// cannot be used here), and a garm claim carrying clearance and compartments
// for an approver.
//
// A non-200 here is never a *RefusalError: that type means specifically
// "the service under test was reached and declined," and the upstream IdP is
// a different service entirely. See Token's doc comment.
func (m FormMinter) fetchUpstreamToken(ctx context.Context, q url.Values) (string, error) {
	u := strings.TrimSuffix(m.UpstreamURL, "/") + "/token?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	c := m.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("upstream IdP unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream IdP returned %d: %s", resp.StatusCode, truncateBody(b))
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("upstream IdP returned an empty token")
	}
	return tok, nil
}

// grantResponse is the approval endpoint's JSON envelope.
type grantResponse struct {
	Grant     string `json:"grant"`
	ExpiresIn int64  `json:"expires_in"`
}

// Approve drives POST /approve: a JSON body carrying the calling service's
// client_assertion and the approval request, and the APPROVER'S own bearer
// in the Authorization header. Both a grant case and a grantError case go
// through here; the request says which it is.
//
// The approver's token is fetched from the upstream IdP first, with the
// clearance and compartments the case declares, because the issuer RECORDS
// the approver's authority rather than resolving it — so the case has to
// say what that authority is, and the only place to put it is the token. A
// case naming an ApproverActor asks the upstream for a token carrying an
// `act` chain (devkit's ?act= form), which is how a refusal case presents a
// delegated identity as the approver.
//
// A non-200 from the approval endpoint is a *RefusalError, exactly as
// Token's contract requires; a failure fetching the approver's token is an
// ordinary wrapped error, because a case that never reached the service
// under test asserts nothing about it.
func (m FormMinter) Approve(ctx context.Context, g ApprovalRequest) (string, error) {
	if m.UpstreamURL == "" {
		return "", fmt.Errorf("conformance: an approval case needs an approver's token and " +
			"FormMinter has no UpstreamURL configured")
	}
	q := url.Values{}
	q.Set("sub", g.Approver)
	if g.ApproverTenant != "" {
		q.Set("tenant", g.ApproverTenant)
	}
	if g.ApproverClearance != "" {
		q.Set("clearance", g.ApproverClearance)
	}
	if len(g.ApproverCompartments) > 0 {
		q.Set("compartments", strings.Join(g.ApproverCompartments, ","))
	}
	if g.ApproverActor != "" {
		q.Set("act", g.ApproverActor)
	}
	bearer, err := m.fetchUpstreamToken(ctx, q)
	if err != nil {
		return "", fmt.Errorf("conformance: fetching the approver's token from the upstream IdP: %w", err)
	}

	// Never nil: the approval endpoint digests what it is given, and `null`
	// where an object belongs is a request shape nothing on either side has
	// a reason to accept.
	material := g.Material
	if material == nil {
		material = map[string]string{}
	}
	fields := map[string]any{
		"client_assertion_type": clientAssertionTypeJWTBearer,
		"tool":                  g.Tool,
		"subject":               g.Subject,
		"material":              material,
	}
	// Omitted means ABSENT — no key at all — not an empty string. The type
	// field stays, so the refusal such a case earns is about the missing
	// assertion and not about a missing type.
	if !g.OmitClientAssertion {
		assertion, err := m.clientAssertion()
		if err != nil {
			return "", err
		}
		fields["client_assertion"] = assertion
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("conformance: encoding the approval request: %w", err)
	}

	u := strings.TrimSuffix(m.BaseURL, "/") + "/approve"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	c := m.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("approval endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &RefusalError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	var gr grantResponse
	if err := json.Unmarshal(b, &gr); err != nil {
		return "", fmt.Errorf("conformance: decoding the approval response: %w (body: %s)", err, truncateBody(b))
	}
	if gr.Grant == "" {
		return "", fmt.Errorf("conformance: approval response has no grant (body: %s)", truncateBody(b))
	}
	return gr.Grant, nil
}

var _ GrantMinter = FormMinter{}

// truncateBody bounds a response body for inclusion in an error message. A
// 200 that fails to decode is exactly the case where an operator needs to
// see what actually came back — an HTML error page from a misconfigured
// proxy, a gateway message, an empty body — and a conformance job is
// normally read at a distance, from CI output, with no chance to reproduce
// locally. A few hundred bytes is plenty to recognise any of those; it says
// so explicitly when it cuts something off, rather than leaving a truncated
// blob that reads as the whole answer.
func truncateBody(b []byte) string {
	const max = 500
	s := strings.TrimSpace(string(b))
	if len(s) <= max {
		return s
	}
	return s[:max] + "... (truncated)"
}
