package grants

// contains is the only reader left over a decoded token body.
//
// The claim reading that used to be here — str, strSlice, unix, and a
// normaliseClearance that had to agree with the one the STS and the tasks
// service use — is [github.com/garm-ai/contracts/grants]'s now. It was the
// tolerant half of this package, and tolerance is exactly what let two
// readers of one credential drift apart without anything noticing.
//
// This one stays because what it is used for is not claim reading: it answers
// whether an issuer is on THIS deployment's allowlist and whether this
// deployment is in the token's audience, and both of those are configuration
// rather than format.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
