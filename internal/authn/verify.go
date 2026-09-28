package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// permittedAlgorithms is the allowlist, and it lives here rather than in
// configuration on purpose.
//
// An operator cannot widen it, which means no deployment can be talked into
// accepting `none`, an HMAC algorithm (where the "key" is the public key an
// attacker already has), or whatever the next confusion attack uses. Adding
// an algorithm is a source change, reviewed like anything else — the same
// friction the governance chain itself applies to adding a step.
// PermittedAlgorithms is exported so the grant verifier shares this exact
// list rather than keeping its own. Two allowlists is two things to widen,
// and the second one is the one nobody remembers to look at.
var PermittedAlgorithms = permittedAlgorithms

var permittedAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
}

// Config configures a Verifier.
type Config struct {
	// KeySet supplies the public keys. Required.
	KeySet *KeySet

	// Issuers is the allowlist of acceptable `iss` values. Required and
	// deliberately not optional: a verifier that accepts any issuer accepts
	// any IdP that can produce a key under a kid it has seen.
	Issuers []string

	// Audience is the `aud` this deployment answers to. Required. A token
	// minted for another service is a VALID token — the audience check is
	// the only thing that stops it being replayed here.
	Audience string

	// Compartments is the taxonomy the token's compartment names resolve
	// against. Required unless CompartmentSource is set.
	Compartments *policy.Registry

	// CompartmentSource is Compartments for a caller whose taxonomy changes:
	// it is read once per verification, so a catalogue reload that declares a
	// new compartment reaches the next token rather than the next restart.
	//
	// Exactly one of the two must be set. Both exist because most callers
	// have one fixed taxonomy (every test here, the conformance runner) and
	// only the daemon reloads; a Config naming both is refused, because
	// picking one silently would leave an operator believing something untrue
	// about which declarations are deciding.
	//
	// Neither outranks a registry pinned on the request by WithRegistry. A
	// surface that has read a catalogue generation knows which taxonomy will
	// INTERPRET the bitset this fold produces, and that one wins.
	CompartmentSource Compartments

	// Skew tolerated on exp/nbf/iat. Clocks disagree; without it a token
	// minted a second in the future by a fast IdP is refused for no reason.
	Skew time.Duration

	Now func() time.Time
}

// Verifier turns a signed token into a Principal.
type Verifier struct {
	cfg Config
	// cfgErr is a Config that cannot be served, detected at construction and
	// returned by every Verify.
	//
	// It is held rather than returned because NewVerifier has never had an
	// error to return and every embedder's call site would change to add one.
	// The refusal itself is not softened: Verify is the only thing a Verifier
	// does, and it refuses on the first call rather than on some later
	// condition, so the misconfiguration surfaces at the first request rather
	// than being resolved behind the operator's back.
	cfgErr error
}

// DefaultSkew is the clock tolerance applied to a token's time claims, and it
// is exported because the GRANT path has to use the same number.
//
// Two tolerances in one process that differ is how a caller ends up holding a
// token that verifies and an approval that does not, with nothing in either
// refusal to say the clocks are what disagreed. Naming it once makes them the
// same value by construction rather than by two literals that happen to match.
const DefaultSkew = 60 * time.Second

func NewVerifier(cfg Config) *Verifier {
	if cfg.Skew == 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	v := &Verifier{cfg: cfg}
	if cfg.Compartments != nil && cfg.CompartmentSource != nil {
		v.cfgErr = fmt.Errorf("authn: Config sets both Compartments and " +
			"CompartmentSource; set one, because two taxonomies is two answers " +
			"to which compartments exist")
	}
	return v
}

// Verify checks a token's signature and registered claims, then folds the
// delegation chain into one Principal.
//
// The order is not arbitrary: NOTHING in the payload is trusted until the
// signature verifies. The `act` chain in particular is read only afterwards,
// which is what makes delegation unforgeable — an attacker who alters the
// chain alters the signed payload, and the signature is checked against a key
// only the IdP holds.
//
// The second return value is the compartment names the token asserted that
// this build does not declare. They are dropped rather than refused (see
// Fold), and returned so the caller can log what was dropped: a token naming
// a compartment garm has never heard of is usually an IdP-side typo, and
// silently narrowing the caller's authority without saying so turns that typo
// into an unexplained permission denial.
func (v *Verifier) Verify(ctx context.Context, token string) (*toolplane.Principal, []string, error) {
	if v.cfgErr != nil {
		return nil, nil, v.cfgErr
	}
	reg := v.compartments(ctx)
	if v.cfg.KeySet == nil || reg == nil ||
		len(v.cfg.Issuers) == 0 || v.cfg.Audience == "" {
		return nil, nil, fmt.Errorf("authn: verifier is not configured")
	}

	// ParseSigned takes the allowlist, so an `alg` outside it is refused
	// during parsing — before any key lookup, and with no code path that
	// could be persuaded to treat `none` as a signature.
	sig, err := jose.ParseSigned(token, permittedAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: %w", err)
	}
	if len(sig.Signatures) != 1 {
		// Multiple signatures mean multiple answers to "who signed this",
		// and picking one is exactly the ambiguity to refuse.
		return nil, nil, fmt.Errorf("authn: token carries %d signatures, want 1", len(sig.Signatures))
	}
	kid := sig.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, nil, fmt.Errorf("authn: token has no kid")
	}

	key, err := v.cfg.KeySet.Key(ctx, kid)
	if err != nil {
		return nil, nil, err
	}
	payload, err := sig.Verify(key)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: signature: %w", err)
	}

	// Everything below this line is verified content.
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, nil, fmt.Errorf("authn: token body: %w", err)
	}

	claims, err := ParseClaims(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: %w", err)
	}
	if err := v.checkRegistered(claims, raw); err != nil {
		return nil, nil, err
	}

	p, dropped, err := Fold(claims, reg)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: %w", err)
	}
	return p, dropped, nil
}

// compartments is the taxonomy for THIS verification, read once.
//
// Once, and held for the whole fold: reading it twice would let a reload
// between two levels of one delegation chain intersect authority across two
// generations, which is the mixed-generation failure immutability exists to
// prevent.
//
// The request wins over the Config. A compartment bitset is only meaningful
// against the registry that produced it (see Compartments), so the taxonomy
// that matters is the one the CHAIN will read the answer with — and a surface
// that has pinned its generation on the context is telling us exactly which
// that is. Falling back to the Config is for callers with no plane: the
// conformance runner, embedders, and every test in this package.
func (v *Verifier) compartments(ctx context.Context) *policy.Registry {
	if reg := registryFrom(ctx); reg != nil {
		return reg
	}
	if v.cfg.CompartmentSource != nil {
		return v.cfg.CompartmentSource.Registry()
	}
	return v.cfg.Compartments
}

// checkRegistered validates iss, aud and the time window.
//
// These are checked on the OUTERMOST claims only. An `act` entry names who is
// acting, not a second token with its own lifetime — Fold intersects its
// authority, and a nested actor cannot extend validity it never carried.
func (v *Verifier) checkRegistered(c *Claims, raw map[string]any) error {
	if !slices.Contains(v.cfg.Issuers, c.Issuer) {
		return fmt.Errorf("authn: issuer %q is not allowed", c.Issuer)
	}
	if !slices.Contains(c.Audience, v.cfg.Audience) {
		return fmt.Errorf("authn: token audience %q does not include %q",
			c.Audience, v.cfg.Audience)
	}

	now := v.cfg.Now()
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(v.cfg.Skew)) {
		return fmt.Errorf("authn: token expired at %s", c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if c.ExpiresAt.IsZero() {
		// A token with no expiry never stops being valid, which makes
		// revocation impossible. Refuse rather than pick a default.
		return fmt.Errorf("authn: token has no exp")
	}
	// nbf is optional and ParseClaims does not carry it, so it is read here
	// from the verified body.
	if nbf, ok := raw["nbf"]; ok {
		if f, ok := nbf.(float64); ok {
			if start := time.Unix(int64(f), 0); now.Add(v.cfg.Skew).Before(start) {
				return fmt.Errorf("authn: token is not valid until %s",
					start.UTC().Format(time.RFC3339))
			}
		}
	}
	return nil
}
