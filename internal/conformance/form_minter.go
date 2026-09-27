package conformance

import (
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
}

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
func (m FormMinter) Token(ctx context.Context, params map[string]string) (string, error) {
	assertion, err := m.clientAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

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
		return "", fmt.Errorf("conformance: decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("conformance: token response has no access_token: %s", strings.TrimSpace(string(b)))
	}
	return tr.AccessToken, nil
}
