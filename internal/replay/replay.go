// Package replay records that a single-use credential has been spent.
//
// An approval token is single-use by specification: its `jti` enters a replay
// cache so one approval authorises one call. The cache has to live HERE, in
// the verifier, and not in the service that issued the token — an issuer
// cannot know whether a grant was spent, because it never sees it being used.
//
// Two properties make this harder than a map, and both are the difference
// between a control and a decoration.
//
// It must be ATOMIC. "Look it up, then write it" is a race: two replicas both
// find nothing, both write, both allow, and one approval has authorised two
// payments. The test and the set have to be one operation that exactly one
// caller can win.
//
// It must be SHARED. garmd runs more than one instance, and a per-process map
// means a grant can be spent once against each of them. That is not a
// degraded version of the property; for an irreversible tool it is the whole
// failure, arriving in proportion to how well the service scaled.
package replay

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrAlreadySpent means this identifier has been recorded before.
var ErrAlreadySpent = errors.New("already spent")

// Cache records single-use identifiers.
type Cache interface {
	// Spend records id, and reports ErrAlreadySpent if it was already there.
	//
	// Any OTHER error means the question could not be answered, and a caller
	// must treat that as a refusal. "We could not check" is not "it is fine":
	// a replay cache that fails open during an outage is a replay cache that
	// an attacker only has to wait for.
	Spend(ctx context.Context, id string) error

	// Retention is how long an entry survives.
	//
	// Declared so a caller can refuse a credential that could outlive its own
	// record. A grant valid for fifteen minutes against a cache that forgets
	// after five is replayable in the last ten, and nothing about that is
	// visible at the moment it is configured.
	Retention() time.Duration
}

// CheckRetention refuses a cache that forgets faster than the credentials it
// guards.
//
// longest is the largest max_grant_age a mounted catalogue declares, so this
// is computable at startup from the artifact rather than guessed: the tools
// say how long their approvals live, and the cache must outlast the longest
// of them.
func CheckRetention(c Cache, longest time.Duration) error {
	if c == nil || longest <= 0 {
		return nil
	}
	if r := c.Retention(); r > 0 && r < longest {
		return fmt.Errorf("the replay cache keeps an entry for %s and a tool declares "+
			"grants valid for %s — an approval spent in the last %s would be "+
			"forgotten while it is still valid, and replayable",
			r, longest, longest-r)
	}
	return nil
}
