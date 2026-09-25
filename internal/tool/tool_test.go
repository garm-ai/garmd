package tool_test

import (
	"testing"

	"github.com/garm-ai/garmd/internal/tool"
)

// Service() is the one piece of parsing in an otherwise inert package, and
// what it returns is the NATS queue group a deployment balances over. Get it
// wrong and calls go to a group nothing joined — which looks like an outage
// rather than like a parsing mistake, so it is worth pinning by example.
func TestTheServiceIsTheRoutesMiddleSegment(t *testing.T) {
	for _, c := range []struct{ route, want string }{
		{"/t.v1.S/Get", "t.v1.S"},
		{"/acme.accounts.v1.AccountsService/GetBalance", "acme.accounts.v1.AccountsService"},
		// A service name is not required to contain a dot.
		{"/S/Get", "S"},
	} {
		if got := (tool.Def{FullMethod: c.route}).Service(); got != c.want {
			t.Errorf("Service(%q) = %q, want %q", c.route, got, c.want)
		}
	}
}

// A route that is not a route yields nothing rather than a guess. Returning
// half of a malformed string would put that half in a subject and produce a
// call that goes somewhere nobody meant; returning nothing fails visibly.
//
// The empty Def is here because a Def is a value type that other packages
// construct directly, and a method on an inert struct that panics on its zero
// value is a crash waiting for the first caller who has not filled it in yet.
func TestAMalformedRouteYieldsNoServiceRatherThanHalfOfOne(t *testing.T) {
	for _, route := range []string{"", "/", "/OnlyOneSegment", "no-slashes-at-all"} {
		if got := (tool.Def{FullMethod: route}).Service(); got != "" {
			t.Errorf("Service(%q) = %q, want an empty string", route, got)
		}
	}
}
