package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/garm-ai/contracts/policy"
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

// TrustedIssuer is one issuer and the key set that signs for it.
//
// A PAIR, because the two are one fact. A verifier holding several issuers and
// one key set trusts whoever can answer that URL to sign for every issuer on
// the list — which is fine while there is one IdP and wrong the moment there
// are two, since the STS could then mint tokens claiming the enterprise IdP's
// name and this daemon would verify them.
//
// It is also where a rule that applies to ONE issuer's tokens belongs. The
// runner's token from the STS carries an `exec` claim the human's token from
// the IdP does not, and Verify knows which entry's keys verified a token
// before it reads the body — so the per-issuer requirement has somewhere to
// attach when there is one. There is none here yet.
type TrustedIssuer struct {
	// Issuer is the exact `iss` value. Compared, never parsed.
	Issuer string

	// KeySet supplies the public keys for THIS issuer, and only this one.
	KeySet *KeySet

	// JWKS is where KeySet reads those keys from, carried so that a caller
	// holding the pair does not have to re-derive it by index from the flags
	// it was built out of. Optional, and never read for verification — a
	// KeySet already knows its own URL. It is here for the things that have
	// to NAME the endpoint: the startup line an operator checks the pairing
	// in, and the issuer-metadata check.
	//
	// Two parallel slices indexed in three places is one off-by-one away from
	// telling an operator that an issuer is verified against a key set that
	// is not the one it was given.
	JWKS string
}

// Config configures a Verifier.
type Config struct {
	// Trusted is the issuers this deployment accepts, each with its own keys.
	// Required, unless the single-pair KeySet/Issuers form below is used.
	Trusted []TrustedIssuer

	// KeySet and Issuers are the single-key-set form, kept because it is what
	// every embedder, every other test here and the conformance runner build.
	// NewVerifier folds them into Trusted; nothing below reads them directly.
	//
	// It is not a deprecated alias: one key set for one issuer is the ordinary
	// deployment, and making it spell a slice would be churn for its own sake.
	// Several issuers against one key set still means exactly what it meant —
	// they share an IdP — which is why this form is not simply removed. A
	// Config setting both forms is refused rather than merged, because which
	// key set signs for a repeated issuer would then depend on the order the
	// fold happened to run in.
	KeySet *KeySet

	// Issuers is the allowlist of acceptable `iss` values for KeySet.
	// Required with it and deliberately not optional: a verifier that accepts
	// any issuer accepts any IdP that can produce a key under a kid it has
	// seen.
	//
	// One behaviour change: an issuer listed TWICE here used to be harmless,
	// and is now refused on the first Verify along with the rest of an
	// unservable list, because after the fold it is two entries claiming the
	// same name and the second is unreachable.
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
	// Folded once, here, so Verify has one shape to read. An entry per issuer
	// sharing the one key set is exactly what the old behaviour was.
	bothForms := len(cfg.Trusted) > 0 && (cfg.KeySet != nil || len(cfg.Issuers) > 0)
	if len(cfg.Trusted) == 0 && cfg.KeySet != nil {
		for _, iss := range cfg.Issuers {
			cfg.Trusted = append(cfg.Trusted, TrustedIssuer{Issuer: iss, KeySet: cfg.KeySet})
		}
	}

	v := &Verifier{cfg: cfg}
	if cfg.Compartments != nil && cfg.CompartmentSource != nil {
		v.cfgErr = fmt.Errorf("authn: Config sets both Compartments and " +
			"CompartmentSource; set one, because two taxonomies is two answers " +
			"to which compartments exist")
		return v
	}
	if bothForms {
		v.cfgErr = fmt.Errorf("authn: Config sets both Trusted and the single-pair " +
			"KeySet/Issuers form; set one, because an issuer named by both would " +
			"be signed for by whichever key set the fold reached first")
		return v
	}
	v.cfgErr = checkTrusted(cfg.Trusted)
	return v
}

// checkTrusted refuses a list that cannot be served, in the shape Verify will
// read it.
//
// Each of these is a configuration fault that would otherwise surface as a
// TOKEN fault at runtime: an entry with no key set is skipped by selection and
// reported as "that issuer is not allowed", and a repeated issuer means the
// second entry's key set is never consulted, so tokens signed by it are
// refused with a message about the key. Both send whoever is paged to look at
// an IdP that is working.
func checkTrusted(trusted []TrustedIssuer) error {
	seen := make(map[string]bool, len(trusted))
	for _, t := range trusted {
		if t.Issuer == "" {
			return fmt.Errorf("authn: a trusted entry names no issuer; a key set with " +
				"nothing to match against signs for nobody")
		}
		if t.KeySet == nil {
			return fmt.Errorf("authn: the trusted entry for issuer %q has no key set, so "+
				"every token it mints would be refused as though the issuer were not "+
				"allowed", t.Issuer)
		}
		if seen[t.Issuer] {
			return fmt.Errorf("authn: issuer %q is trusted twice; the first entry wins "+
				"every lookup and the second's key set would never be consulted",
				t.Issuer)
		}
		seen[t.Issuer] = true
	}
	return nil
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
	if len(v.cfg.Trusted) == 0 || reg == nil || v.cfg.Audience == "" {
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

	// Which key set to try. This reads the payload BEFORE the signature has
	// been checked, and it has to: a key set cannot be chosen after the
	// verification it is needed for. Nothing is trusted on the strength of it
	// — it selects a candidate and nothing else — and the loop is closed
	// below, where the VERIFIED issuer is required to be the one whose keys
	// worked. Without that second check, a token signed by one trusted issuer
	// while claiming another's name would pass, because both are allowlisted.
	//
	// The alternative, trying every key set until one verifies, is worse: two
	// IdPs may publish the same kid, and "some trusted party signed this"
	// is not the question.
	trusted, ok := v.trustedFor(sig.UnsafePayloadWithoutVerification())
	if !ok {
		// Deliberately the same refusal as an issuer outside the allowlist: a
		// caller must not be able to tell "not configured here" from "not
		// trusted here" by the message.
		return nil, nil, fmt.Errorf("authn: the token's issuer is not allowed")
	}

	// The error is returned as it comes, so the distinction Key draws survives:
	// ErrNoSuchKey is the caller's fault and everything else — a refused fetch,
	// a set too stale to serve — means this process could not find out, which
	// is the operator's. Wrapping them into one message here is how a garbage
	// kid and an unreachable IdP become the same page.
	key, err := trusted.KeySet.Key(ctx, kid)
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
	// The loop closed. The signature verified under the key set chosen from an
	// UNVERIFIED claim, so the verified claim must be the same one — otherwise
	// issuer A's key has just authenticated a token bearing issuer B's name.
	//
	// This is also the point at which the issuer a token was actually signed
	// for is known, which is where a per-issuer claim requirement would go.
	if claims.Issuer != trusted.Issuer {
		return nil, nil, fmt.Errorf("authn: the token was signed for issuer %q and "+
			"claims to be from %q", trusted.Issuer, claims.Issuer)
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

// trustedFor selects the issuer entry an unverified payload names.
//
// Unmarshalled leniently and read for exactly one field: a payload that is not
// an object, or names no issuer, selects nothing. Selecting nothing must be a
// refusal rather than a fallback to the first entry, or the first-listed
// issuer becomes the default signer for every token that forgot to say.
func (v *Verifier) trustedFor(payload []byte) (TrustedIssuer, bool) {
	var body struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || body.Issuer == "" {
		return TrustedIssuer{}, false
	}
	for _, t := range v.cfg.Trusted {
		if t.Issuer == body.Issuer && t.KeySet != nil {
			return t, true
		}
	}
	return TrustedIssuer{}, false
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
	// Kept as well as the equality against the selected entry in Verify. Two
	// checks of the same fact, because they fail for different reasons: this
	// one catches an entry list that drifted, and that one catches a token
	// verified under the wrong issuer's key.
	if !v.allowed(c.Issuer) {
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

func (v *Verifier) allowed(issuer string) bool {
	for _, t := range v.cfg.Trusted {
		if t.Issuer == issuer {
			return true
		}
	}
	return false
}
