package grants

import (
	"strings"
	"time"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
)

// Small readers over a decoded token body.
//
// Deliberately tolerant of shape and intolerant of meaning: an absent claim
// reads as its zero and the check above decides whether that is fatal, which
// keeps "the claim was missing" and "the claim said something wrong" as two
// different errors rather than one parse failure.

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// strSlice tolerates a single string where a list is expected, because
// issuers differ on single-element `aud`, and drops non-strings rather than
// failing the whole token for one bad entry.
func strSlice(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func unix(m map[string]any, k string) time.Time {
	switch v := m[k].(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	}
	return time.Time{}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// normaliseClearance accepts the bare and prefixed spellings, as the token
// verifier does — sts mints CONFIDENTIAL, devkit mints CLEARANCE_CONFIDENTIAL,
// and an approval refused over a prefix would be maddening.
func normaliseClearance(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "CLEARANCE_") {
		s = "CLEARANCE_" + s
	}
	if _, ok := toolv1.Clearance_value[s]; !ok {
		return ""
	}
	return s
}
