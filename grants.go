package garmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/contracts/garm/tool/v1"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/replay"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// grantVerifier builds step 5, or reports that this deployment does not have
// one.
//
// It returns the INTERFACE, and nil means nil. Returning a typed nil pointer
// would satisfy `!= nil` on the Handler's field, and that field is what the
// mount refusal reads to decide whether an approval-gated tool may be served —
// so the typed nil would mount exactly the tool this refusal exists to stop,
// against a verifier that cannot verify anything.
//
// The ISSUER is what turns it on, not a boolean. A verifier needs someone to
// trust, and there is no sensible default for who signs a human's approval.
func grantVerifier(
	ctx context.Context, nc *nats.Conn, cat *catalogue.Catalogue, cfg Config,
) (toolplane.GrantVerifier, func(*catalogue.Catalogue) error, error) {
	// Before the early return, so two of the three flags given without the
	// third is an error rather than a value that does nothing.
	if err := checkGrantFlags(cfg); err != nil {
		return nil, nil, err
	}
	if cfg.GrantIssuer == "" {
		return nil, nil, nil
	}

	// Before the bucket, because this is the check that makes the bucket's
	// size mean anything: a gated tool with no ceiling has no age this plane
	// can enforce and no number the cache can be sized from.
	if err := checkGrantCeilings(cat); err != nil {
		return nil, nil, err
	}

	// The cache must outlast the longest approval the catalogue declares, and
	// after checkGrantCeilings that number is always positive when the
	// catalogue declares a gated tool at all.
	// A guard, not a case anyone configures: Serve always has a live
	// connection here. It exists because the JetStream client dereferences a
	// nil connection rather than returning an error, so without this a
	// misordered construction is a panic at startup instead of a sentence.
	if nc == nil {
		return nil, nil, fmt.Errorf("--grant-issuer is set and there is no NATS "+
			"connection to hold the %s replay cache", replay.BucketName)
	}

	// The bucket must outlast the oldest approval the verifier will still
	// accept, and the verifier accepts an approval up to Skew past its
	// ceiling (claims.go). Without the margin a grant spent promptly has its
	// spent-record expire at `longest` while the grant itself stays
	// acceptable until `longest + Skew` — a replay window exactly one skew
	// wide, at the tail of every ceiling.
	longest := longestGrantAge(cat)
	var covers time.Duration
	if longest > 0 {
		covers = longest + authn.DefaultSkew
	}
	ttl := covers
	if ttl <= 0 {
		ttl = bucketFloorTTL
	}
	spent, err := replay.NewJetStream(ctx, nc, ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("the replay cache for spent grants (%s): %w",
			replay.BucketName, err)
	}
	// Against what the bucket ACTUALLY keeps, which an older deployment may
	// have created differently — NewJetStream reads its TTL back rather than
	// trusting the request. A cache that forgets before a grant expires is
	// replayable in the gap, and nothing about that is visible at the moment
	// it is configured.
	if err := replay.CheckRetention(spent, covers); err != nil {
		return nil, nil, fmt.Errorf("this deployment cannot verify grants: %w", err)
	}

	return &grants.Verifier{
		Keys:     authn.NewKeySet(authn.KeySetConfig{URL: grantJWKS(cfg)}),
		Issuers:  []string{cfg.GrantIssuer},
		Audience: grantAudience(cfg),
		Spent:    spent,
		// The token path's tolerance, by NAME rather than by a literal that
		// happens to match it. Zero here would mean an approval one second
		// past its expiry is refused on a deployment whose bearer token is
		// still accepted, and the caller has nothing in either refusal to tell
		// them the clocks are what disagreed.
		Skew: authn.DefaultSkew,
	}, reloadGuard(spent), nil
}

// reloadGuard is the question a reload has to ask that the mount check cannot.
//
// The replay bucket's expiry is derived ONCE, at startup, from the boot
// catalogue's longest ceiling — a JetStream bucket's TTL is a property of the
// bucket and this process is not the only one using it, so a reload cannot
// simply widen it. A generation that raises the ceiling past what the bucket
// keeps mounts perfectly happily: nothing in the chain knows about the cache's
// retention, so the failure would be an approval still valid after its
// spent-record had expired, replayable in the gap, with nothing to see.
//
// So the reload refuses it, and the operator restarts — which is the one
// action that DOES re-derive the bucket. That is a real limitation stated as a
// refusal rather than left as a hole; see KNOWN-GAPS.md.
//
// It is built against the cache the verifier actually got, whose retention was
// read back from the bucket rather than assumed from what this process asked
// for: an older deployment may have created it with a different expiry.
func reloadGuard(spent replay.Cache) func(*catalogue.Catalogue) error {
	return func(next *catalogue.Catalogue) error {
		// The same refusal startup makes, for the same reason: a gated tool
		// with no ceiling has no age to enforce and no number to size a cache
		// from. Arriving by reload does not make it acceptable.
		if err := checkGrantCeilings(next); err != nil {
			return err
		}
		longest := longestGrantAge(next)
		if longest <= 0 {
			return nil
		}
		// The same margin the bucket was sized with: the verifier accepts an
		// approval up to Skew past its ceiling, so the record of it being
		// spent has to survive that long too.
		return replay.CheckRetention(spent, longest+authn.DefaultSkew)
	}
}

// bucketFloorTTL is the expiry given to the replay bucket when the catalogue
// declares NO approval-gated tool.
//
// It bounds no grant. checkGrantCeilings has already refused a gated tool
// without a ceiling, so any catalogue that has one produces a real number
// above; this value is reached only when nothing in this generation can spend
// a grant at all, and it exists because a JetStream bucket cannot be created
// without an expiry.
//
// Generous rather than minimal, and deliberately: the one way it can ever meet
// a real approval is a reload that introduces the first gated tool into a
// process started without one, and a reload does not re-derive the bucket.
// reloadGuard is what keeps that honest — a generation whose ceiling does not
// fit inside this hour is refused rather than served against a cache that
// would forget first. An hour is enough for the ordinary approval, so the
// refusal is rare and the restart that lifts it is a real one. See
// KNOWN-GAPS.md.
const bucketFloorTTL = time.Hour

// checkGrantCeilings refuses a MODE_GRANT tool that declares no
// max_grant_age_seconds.
//
// Without a ceiling the tool has said nothing about how stale an approval may
// be, so the age check is skipped entirely and the grant's validity is whatever
// `exp` the issuer chose — a day, a week, or unbounded if it minted no `exp` at
// all. Two things follow and both are silent: a tool's author cannot cap an
// issuer they do not control, and there is no number to size the replay cache
// from, so the approval outlives its own spent-record and is replayable in the
// gap.
//
// Refused at startup rather than sized around, because the fix is one field in
// the tool's schema and the alternative is a replay window nobody can see. The
// message names the tool: "some tool is missing a ceiling" sends an operator to
// read a whole catalogue.
func checkGrantCeilings(cat *catalogue.Catalogue) error {
	if cat == nil {
		return nil
	}
	for _, d := range cat.Defs {
		if d.ApprovalMode == toolv1.Approval_MODE_GRANT && d.MaxGrantAge <= 0 {
			return fmt.Errorf("%s declares MODE_GRANT and no max_grant_age_seconds: "+
				"its approvals would be valid for however long the issuer minted them, "+
				"which this plane cannot cap and cannot size the %s replay cache to "+
				"outlast — so a grant would be replayable after its spent-record "+
				"expired. Declare max_grant_age_seconds on the tool",
				d.FQN, replay.BucketName)
		}
	}
	return nil
}

// checkGrantFlags refuses a half-given grant configuration.
//
// --grant-jwks and --grant-audience do nothing without --grant-issuer: step 5
// stays off and a MODE_GRANT catalogue still will not mount. An operator who
// typed two of the three has said what they meant, and silently ignoring it is
// how they find out from a failed deploy instead of from this line.
//
// The other direction matters more. --grant-issuer with nothing to verify
// against — no --grant-jwks and no single --jwks to default to — builds a
// verifier that refuses every approval with a message about the key set, which
// reads like an STS fault rather than a flag nobody set.
//
// And --grant-issuer against a REPEATED --jwks is refused separately, because
// that one does not refuse anything at runtime: it would verify approvals
// against whichever key set happened to be written first, which is a hole
// rather than an outage.
func checkGrantFlags(cfg Config) error {
	if cfg.GrantIssuer == "" {
		var given []string
		if cfg.GrantJWKS != "" {
			given = append(given, "--grant-jwks")
		}
		if cfg.GrantAudience != "" {
			given = append(given, "--grant-audience")
		}
		if len(given) > 0 {
			return fmt.Errorf("%s given without --grant-issuer, so step 5 is off and "+
				"the value does nothing: a catalogue declaring a MODE_GRANT tool will "+
				"still refuse to mount. Set --grant-issuer, or drop %s",
				strings.Join(given, " and "), strings.Join(given, " and "))
		}
		return nil
	}
	// Distinct from the refusal below, because the operator gave a key set and
	// the problem is that they gave several. Picking one silently is the
	// failure that does not look like one: an approval claiming the STS's name
	// would be verified against whichever --jwks was written first, and the
	// grant verifier cannot tell — it checks the issuer against its allowlist
	// and the signature against the key set it was handed, so a first entry
	// able to answer that URL signs approvals for every issuer on the list.
	if cfg.GrantJWKS == "" && len(cfg.JWKSURLs) > 1 {
		return fmt.Errorf("--grant-issuer is set and --jwks is given %d times: a repeated "+
			"--jwks has no unambiguous default for --grant-jwks, and taking the first "+
			"would verify approvals against a key set that may not be the grant "+
			"issuer's. Name it: --grant-jwks <the key set that signs approvals>",
			len(cfg.JWKSURLs))
	}
	if grantJWKS(cfg) == "" {
		return fmt.Errorf("--grant-issuer is set and there is no key set to verify its " +
			"approvals against: give --grant-jwks, or a single --jwks for it to default to")
	}
	if grantAudience(cfg) == "" {
		return fmt.Errorf("--grant-issuer is set and there is no audience an approval " +
			"must name: give --grant-audience, or --audience for it to default to. A " +
			"grant minted for another deployment is a VALID grant, and the audience is " +
			"the only thing that stops it being spent here")
	}
	return nil
}

// grantJWKS and grantAudience default to the token ones.
//
// An STS that issues both delegation tokens and approvals is the ordinary
// deployment, and making an operator type the same two values twice is how the
// two end up disagreeing — at which point every approval is refused with a
// message about the audience rather than about the configuration.
//
// The JWKS default holds only while there is ONE --jwks. An audience is a
// single value however many issuers there are, so grantAudience has nothing to
// choose between; a key set does, and choosing wrong is not a refusal.
func grantJWKS(cfg Config) string {
	if cfg.GrantJWKS != "" {
		return cfg.GrantJWKS
	}
	// Exactly one --jwks, or nothing. One is the pair the operator wrote and
	// there is nothing to guess. Several and the first is a GUESS, and the
	// wrong guess is not a misconfiguration that refuses: it verifies an
	// approval claiming the STS's name against the IdP's keys, because the
	// grant verifier checks the issuer against its own allowlist and the
	// signature against whatever key set it was handed. That is the
	// cross-signing hole the token path closes, reopened one flag over — and
	// approvals come from the STS, which is rarely the first --jwks written.
	// checkGrantFlags refuses the ambiguity instead.
	if len(cfg.JWKSURLs) == 1 {
		return cfg.JWKSURLs[0]
	}
	return ""
}

func grantAudience(cfg Config) string {
	if cfg.GrantAudience != "" {
		return cfg.GrantAudience
	}
	return cfg.Audience
}

// longestGrantAge is the largest max_grant_age any GATED tool declares.
//
// From the artifact rather than from a flag: the tools say how stale an
// approval may be for what they do, so the cache's floor is computable at
// startup and does not have to be guessed. An ungated tool is skipped — it
// spends no grants, and a stray annotation on one must not size the cache.
func longestGrantAge(cat *catalogue.Catalogue) time.Duration {
	var longest time.Duration
	if cat == nil {
		return 0
	}
	for _, d := range cat.Defs {
		if d.ApprovalMode == toolv1.Approval_MODE_GRANT && d.MaxGrantAge > longest {
			longest = d.MaxGrantAge
		}
	}
	return longest
}

// chainBanner is what an operator reads at startup about what this process
// will and will not enforce.
//
// It states the MOUNT POLICY, because the previous wording — "a tool declaring
// them is mounted as though it had not" — was false: AddTools refuses, and the
// process does not start. An operator who believed it would deploy an
// approval-gated catalogue expecting degraded service and get a crash loop
// with a message about a step they had been told was optional.
func chainBanner(grantsOn bool, issuer string) string {
	step5 := "  Step 5: grants are NOT verified here. A catalogue declaring a\n" +
		"  MODE_GRANT tool WILL NOT MOUNT — set --grant-issuer.\n"
	if grantsOn {
		step5 = fmt.Sprintf("  Step 5: approvals are verified against %s, single-use\n"+
			"  through the %s bucket.\n", issuer, replay.BucketName)
	}
	return "\n" +
		"  Every call goes through the chain. Steps 1, 2, 3, 6, 8 and 9 are\n" +
		"  implemented.\n" +
		step5 +
		"  Instance authorization (steps 4 and 7) and notify (step 10) are not\n" +
		"  implemented here, and a catalogue declaring either WILL NOT MOUNT:\n" +
		"  this process refuses to start rather than serve a tool ungated while\n" +
		"  its schema says it is supervised. See KNOWN-GAPS.md.\n\n"
}
