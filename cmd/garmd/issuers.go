package main

import (
	"fmt"

	"github.com/garm-ai/garmd/internal/authn"
)

// trustedIssuers pairs --issuer with --jwks by index.
//
// By index rather than by discovery, because discovery would mean fetching
// each issuer's metadata to learn its JWKS URL — a network call at startup
// whose failure mode is a daemon that will not start because an IdP is slow,
// and whose success mode is trusting whatever that document says. An operator
// writes the two flags next to each other; the pairing is that order.
//
// A mismatch REFUSES rather than pairing what there is. Silently pairing the
// shorter list leaves an issuer with no keys, and every token from it is then
// refused at runtime with a message about the token — which sends whoever is
// paged to look at the IdP.
func trustedIssuers(issuers, jwks []string) ([]authn.TrustedIssuer, error) {
	if len(issuers) == 0 || len(jwks) == 0 {
		return nil, fmt.Errorf("--jwks and --issuer are both required: garmd decides what a " +
			"caller may do, which it cannot do without knowing who they are.\n" +
			"For a laptop: `go run github.com/garm-ai/devkit/cmd/garmdev idp` then\n" +
			"  --jwks http://127.0.0.1:7450/.well-known/jwks.json \\\n" +
			"  --issuer https://garmdev.invalid/idp")
	}
	if len(issuers) != len(jwks) {
		return nil, fmt.Errorf("%d --issuer and %d --jwks: they are paired by position, "+
			"first with first, so there must be exactly one key set per issuer. An "+
			"issuer with no key set refuses every token it mints, at runtime, with a "+
			"message about the token rather than about this",
			len(issuers), len(jwks))
	}

	seen := map[string]bool{}
	out := make([]authn.TrustedIssuer, 0, len(issuers))
	for i, iss := range issuers {
		if seen[iss] {
			// The first entry would win every lookup and the second's key set
			// would never be consulted, so tokens signed by it are refused
			// with a message about the key. Refuse where it is still legible.
			return nil, fmt.Errorf("--issuer %s is given twice; each issuer has one key "+
				"set and the second would never be consulted", iss)
		}
		seen[iss] = true
		out = append(out, authn.TrustedIssuer{
			Issuer: iss,
			// One KeySet per issuer, never shared: a shared one means whoever
			// can answer that URL may sign for every issuer on the list.
			KeySet: authn.NewKeySet(authn.KeySetConfig{URL: jwks[i]}),
			// Carried on the pair, so this index is the LAST one: everything
			// downstream that has to name the endpoint reads it from here
			// rather than indexing back into the flag it came from.
			JWKS: jwks[i],
		})
	}
	return out, nil
}
