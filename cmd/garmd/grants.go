package main

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
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
	ctx context.Context, nc *nats.Conn, cat *catalogue.Catalogue, o serveOpts,
) (toolplane.GrantVerifier, error) {
	if o.grantIssuer == "" {
		return nil, nil
	}

	// The cache must outlast the longest approval the catalogue declares. A
	// catalogue with no gated tool still gets a cache — the flag was set, so
	// the operator intends to serve one — sized by an hour, which is longer
	// than any default anyone mints.
	longest := longestGrantAge(cat)
	ttl := longest
	if ttl <= 0 {
		ttl = time.Hour
	}
	spent, err := replay.NewJetStream(ctx, nc, ttl)
	if err != nil {
		return nil, fmt.Errorf("the replay cache for spent grants (%s): %w",
			replay.BucketName, err)
	}
	// Against what the bucket ACTUALLY keeps, which an older deployment may
	// have created differently — NewJetStream reads its TTL back rather than
	// trusting the request. A cache that forgets before a grant expires is
	// replayable in the gap, and nothing about that is visible at the moment
	// it is configured.
	if err := replay.CheckRetention(spent, longest); err != nil {
		return nil, fmt.Errorf("this deployment cannot verify grants: %w", err)
	}

	return &grants.Verifier{
		Keys:     authn.NewKeySet(authn.KeySetConfig{URL: grantJWKS(o)}),
		Issuers:  []string{o.grantIssuer},
		Audience: grantAudience(o),
		Spent:    spent,
	}, nil
}

// grantJWKS and grantAudience default to the token ones.
//
// An STS that issues both delegation tokens and approvals is the ordinary
// deployment, and making an operator type the same two values twice is how the
// two end up disagreeing — at which point every approval is refused with a
// message about the audience rather than about the configuration.
func grantJWKS(o serveOpts) string {
	if o.grantJWKS != "" {
		return o.grantJWKS
	}
	return o.jwksURL
}

func grantAudience(o serveOpts) string {
	if o.grantAudience != "" {
		return o.grantAudience
	}
	return o.audience
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
