package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CheckIssuerMetadata asks the issuer what it mints, and refuses if this
// deployment was configured to expect something else.
//
// The failure it prevents is cheap to cause and expensive to diagnose. An
// issuer mints `aud: garm://garmd`; this daemon defaults to `garm`; nothing
// compares them, so every token is refused for audience mismatch — correctly,
// with a message about the token rather than about the configuration that was
// wrong. Somebody loses an afternoon and learns nothing transferable.
//
// So the check is the same move garm already makes with the descriptor hash:
// the far side advertises what it is serving, the near side compares, and a
// disagreement is a startup refusal rather than a mystery at the first call.
//
// A 404 is NOT a failure. Not every issuer publishes metadata — the dev IdP
// does not, and neither does a stock enterprise IdP — and refusing to start
// against one would make this check a deployment obstacle rather than a
// safety net. Absent means unchecked, and unchecked is where every deployment
// was before this existed.
func CheckIssuerMetadata(ctx context.Context, jwksURL, issuer, audience string) error {
	metaURL, err := metadataURLFor(jwksURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return fmt.Errorf("building the metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Unreachable is not disagreement. The JWKS fetch is lazy and will
		// report its own failure with a better message when the first token
		// arrives; failing startup here would make this check the thing that
		// takes a deployment down when an unrelated endpoint is slow.
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var meta struct {
		Issuer       string   `json:"issuer"`
		GarmAudience string   `json:"garm_audience"`
		Algs         []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil
	}

	var bad []string
	if meta.Issuer != "" && meta.Issuer != issuer {
		bad = append(bad, fmt.Sprintf(
			"--issuer is %q and the issuer says it mints %q", issuer, meta.Issuer))
	}
	// The one that actually bites. Both defaults are reasonable in isolation
	// and they do not match.
	if meta.GarmAudience != "" && meta.GarmAudience != audience {
		bad = append(bad, fmt.Sprintf(
			"--audience is %q and the issuer mints %q into every token",
			audience, meta.GarmAudience))
	}
	if len(meta.Algs) > 0 && !anyPermitted(meta.Algs) {
		bad = append(bad, fmt.Sprintf(
			"the issuer signs with %s and this build accepts none of them",
			strings.Join(meta.Algs, ", ")))
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("this deployment and its issuer disagree, so every token "+
		"would be refused at runtime for a reason that reads like a bad token:\n  %s\n"+
		"(read from %s)", strings.Join(bad, "\n  "), metaURL)
}

// metadataURLFor derives the RFC 8414 location from the JWKS URL's origin.
//
// Derived rather than configured, because a flag nobody sets is a check
// nobody gets — and the trap this exists to catch is precisely the one a
// careful operator has already fallen into by the time they would think to
// set it.
func metadataURLFor(jwksURL string) (string, error) {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return "", fmt.Errorf("parsing the jwks url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("the jwks url %q has no scheme or host", jwksURL)
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server", nil
}

func anyPermitted(algs []string) bool {
	for _, a := range algs {
		for _, p := range permittedAlgorithms {
			if string(p) == a {
				return true
			}
		}
	}
	return false
}
