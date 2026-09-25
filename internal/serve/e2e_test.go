package serve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/garm-ai/garm/contracts/wire"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/record"
	garmnats "github.com/garm-ai/garmd/internal/transport/nats"
)

// The whole stack, with nothing faked that governs.
//
// A real NATS server, a real service answering on the wire subject, the real
// NATS transport, a real JWKS, the real verifier, and the real chain. The
// only stand-in is the tool's own body, which is the one part that is
// supposed to be somebody else's code.
//
// Every other test in this package can be satisfied by a handler that holds
// the right shape. This one cannot: it either produces a governed answer to a
// signed token or it does not.

const e2eIssuer = "https://e2e.invalid/idp"

type idp struct {
	*httptest.Server
	key *ecdsa.PrivateKey
	kid string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "e2e-1"
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return &idp{Server: srv, key: key, kid: kid}
}

// mint produces a token asserting whatever it is given. Shaped exactly like
// the dev IdP's body, because that is the body the verifier has to read — and
// devkit cannot be imported here: a module that can assert any identity must
// never be in the dependency graph of one that decides what an identity may
// do.
func (i *idp) mint(t *testing.T, clearance string, verbs []string, exp time.Duration) string {
	t.Helper()
	now := time.Now()
	body := map[string]any{
		"iss": e2eIssuer,
		"sub": "user:e2e",
		"aud": "garm",
		"iat": now.Unix(),
		"exp": now.Add(exp).Unix(),
		"garm": map[string]any{
			"clearance": clearance,
			"kind":      "USER",
			"verbs":     verbs,
		},
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// startNATS runs an embedded server on a kernel-picked port, so a developer
// with their own broker on 4222 does not have this test talking to it.
func startNATS(t *testing.T) string {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("the embedded NATS server never became ready")
	}
	t.Cleanup(s.Shutdown)
	return s.ClientURL()
}

// startTool answers on the subject the transport will publish to, and reports
// how many times it was called. A plain subscriber rather than the tool-go
// runtime, because garmd must not depend on a tool repository — CI asserts it.
func startTool(t *testing.T, url string, calls *int32Counter) {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)

	sub, err := nc.Subscribe(wire.Subject(route), func(m *nats.Msg) {
		calls.add()
		out := dynamicpb.NewMessage(message())
		out.Set(message().Fields().ByName("producer"),
			protoreflect.ValueOfString("the tool answered"))
		body, err := proto.Marshal(out)
		if err != nil {
			return
		}
		_ = m.Respond(body)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	// Flush so the subscription is registered before the first call: an
	// unregistered subject answers ErrNoResponders, which this test would
	// then report as an unreachable tool rather than a race in its own setup.
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func e2eHandler(t *testing.T, natsURL string, i *idp) (http.Handler, *record.Memory) {
	t.Helper()
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)

	rec := &record.Memory{}
	// The taxonomy the token's compartment names resolve against. Empty here
	// because the fixture tool declares no compartments — but not NIL: the
	// verifier refuses to run without one rather than treating "unconfigured"
	// as "no restrictions", which is the right way round.
	reg, err := policy.NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier := authn.NewVerifier(authn.Config{
		KeySet:       authn.NewKeySet(authn.KeySetConfig{URL: i.URL}),
		Issuers:      []string{e2eIssuer},
		Audience:     "garm",
		Compartments: reg,
	})
	h := &Handler{
		Store:      &countingStore{c: aCatalogue()},
		Invoker:    garmnats.New(nc),
		Log:        discardLogger(),
		Principals: authn.PrincipalFunc(verifier, nil),
		HashKey:    []byte("an e2e hash key, long enough"),
		Recorder:   rec,
	}
	return authn.Middleware(h), rec
}

func e2eCall(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(""))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestASignedTokenReachesTheToolOverARealHop(t *testing.T) {
	url := startNATS(t)
	calls := &int32Counter{}
	startTool(t, url, calls)
	i := newIDP(t)
	h, rec := e2eHandler(t, url, i)

	token := i.mint(t, "CLEARANCE_INTERNAL", []string{"VERB_READ"}, time.Hour)
	w := e2eCall(t, h, token)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if n := calls.load(); n != 1 {
		t.Errorf("the tool was called %d times, want once", n)
	}
	out := dynamicpb.NewMessage(message())
	if err := proto.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("the reply did not decode: %v", err)
	}
	if got := out.Get(message().Fields().ByName("producer")).String(); got != "the tool answered" {
		t.Errorf("producer = %q; the answer did not come from the tool", got)
	}
	if len(rec.Events()) == 0 {
		t.Error("a call crossed the whole stack and left no ledger row")
	}
}

// The same stack, with no credential. The distinction that matters is not the
// 401 — it is that the tool on the other side of a real broker was never
// asked.
func TestWithoutATokenTheToolIsNeverCalled(t *testing.T) {
	url := startNATS(t)
	calls := &int32Counter{}
	startTool(t, url, calls)
	i := newIDP(t)
	h, _ := e2eHandler(t, url, i)

	w := e2eCall(t, h, "")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if n := calls.load(); n != 0 {
		t.Errorf("the tool was called %d times for a request carrying no credential", n)
	}
}

func TestAnExpiredTokenIsRefusedAndTheToolIsNeverCalled(t *testing.T) {
	url := startNATS(t)
	calls := &int32Counter{}
	startTool(t, url, calls)
	i := newIDP(t)
	h, _ := e2eHandler(t, url, i)

	expired := i.mint(t, "CLEARANCE_INTERNAL", []string{"VERB_READ"}, -time.Hour)
	w := e2eCall(t, h, expired)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if n := calls.load(); n != 0 {
		t.Errorf("the tool was called %d times for an expired token", n)
	}
}

// A real, valid, correctly signed identity that is simply not cleared for
// this tool. The ordinary case, and the one worth proving over a real hop:
// the refusal must happen on this side of the broker.
func TestAnUnderClearedButValidTokenNeverReachesTheTool(t *testing.T) {
	url := startNATS(t)
	calls := &int32Counter{}
	startTool(t, url, calls)
	i := newIDP(t)
	h, rec := e2eHandler(t, url, i)

	token := i.mint(t, "CLEARANCE_PUBLIC", []string{"VERB_READ"}, time.Hour)
	w := e2eCall(t, h, token)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404: a tool the caller may not see must answer "+
			"exactly as one that is not here: %s", w.Code, w.Body.String())
	}
	if n := calls.load(); n != 0 {
		t.Errorf("the tool was called %d times for a caller below its clearance", n)
	}
	if len(rec.Events()) == 0 {
		t.Error("a refusal left no ledger row; the refused calls are the ones an " +
			"auditor most wants to see")
	}
}

// int32Counter counts tool invocations across goroutines. The subscriber runs
// on nats.go's own goroutine while the test reads the count on its own, so a
// plain int here is a race that -race would find and a reader would not.
type int32Counter struct{ n atomic.Int64 }

func (c *int32Counter) add()        { c.n.Add(1) }
func (c *int32Counter) load() int64 { return c.n.Load() }
