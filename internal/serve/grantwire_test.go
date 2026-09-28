package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/contracts/grant"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/grants"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/replay"
)

// Step 5 through the surface, with the real verifier rather than a stand-in.
//
// The unit tests in internal/grants prove each refusal; what only this level
// can show is which of them a CALLER sees — and the difference matters,
// because "grant_required" tells a caller to go and fetch an approval while
// "permission denied" tells it to stop. A caller that changed one material
// value and was told to fetch another approval would do exactly that.

const (
	grantIssuer   = "https://sts.test"
	grantAudience = "garm://garmd"
)

type grantIDP struct {
	url string
	key *ecdsa.PrivateKey
}

func newGrantIDP(t *testing.T) *grantIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: "g1", Algorithm: string(jose.ES256), Use: "sig",
	}}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return &grantIDP{url: srv.URL, key: key}
}

// mintGrant signs an approval for the fixture tool, binding whatever the
// approver is said to have seen.
func (i *grantIDP) mintGrant(t *testing.T, subject string, saw map[string]string) string {
	t.Helper()
	now := time.Now()
	body := map[string]any{
		"iss": grantIssuer,
		"aud": grantAudience,
		"jti": "g-" + now.Format("150405.000000000"),
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"garm_grant": map[string]any{
			"tool":               fqn,
			"subject":            subject,
			"material":           grant.Digest(saw),
			"approver":           "employee:amir",
			"approver_clearance": "RESTRICTED",
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "g1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// spentCache is a real JetStream KV, because the single-use property is the
// one thing a map cannot stand in for: the test and the set have to be one
// operation exactly one caller can win.
func spentCache(t *testing.T) replay.Cache {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("the embedded NATS server never became ready")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	c, err := replay.NewJetStream(context.Background(), nc, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// gatedCatalogue is the fixture tool with an approval gate bound to the one
// field its message has.
func gatedCatalogue() *catalogue.Catalogue {
	cat := aCatalogue()
	cat.Defs[0].ApprovalMode = toolv1.Approval_MODE_GRANT
	cat.Defs[0].MaxGrantAge = 15 * time.Minute
	cat.Defs[0].MaterialFields = []string{"producer"}
	return cat
}

func gatedHandler(t *testing.T, i *grantIDP, inv *fakeInvoker, rec *record.Memory) *Handler {
	t.Helper()
	return chained(&Handler{
		Store:    &countingStore{c: gatedCatalogue()},
		Invoker:  inv,
		Log:      discardLogger(),
		Recorder: rec,
		Grants: &grants.Verifier{
			Keys:     authn.NewKeySet(authn.KeySetConfig{URL: i.url}),
			Issuers:  []string{grantIssuer},
			Audience: grantAudience,
			Spent:    spentCache(t),
			Skew:     30 * time.Second,
		},
	})
}

// A grant that matches what is being sent is spent and the tool runs. Without
// this the refusals below would all pass against a verifier that refused
// everything.
func TestAGrantThatMatchesTheRequestLetsTheCallThrough(t *testing.T) {
	i := newGrantIDP(t)
	inv := &fakeInvoker{fill: "x"}
	rec := &record.Memory{}
	h := gatedHandler(t, i, inv, rec)

	r := httptest.NewRequest(http.MethodPost, route,
		strings.NewReader(string(protoBody(t, "approved"))))
	r.Header.Set("Content-Type", contentProto)
	r.Header.Set(GrantHeader, i.mintGrant(t, "user:test", map[string]string{"producer": "approved"}))
	w := call(t, h, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if n := inv.calls.Load(); n != 1 {
		t.Errorf("the tool ran %d times, want once", n)
	}
}

// (Review Focus 3) One material value changed after the human approved.
//
// The grant is otherwise perfect: right issuer, right audience, right tool,
// right subject, minutes old. This is the tampering case, and the answer has
// to be a denial — not a 500, which pages an operator for a caller's own
// mistake, and not grant_required, which tells the tamperer to fetch another
// approval and try again.
func TestAGrantWhoseMaterialWasTamperedWithIsADenialNotAnInternalError(t *testing.T) {
	i := newGrantIDP(t)
	inv := &fakeInvoker{fill: "x"}
	rec := &record.Memory{}
	h := gatedHandler(t, i, inv, rec)

	r := httptest.NewRequest(http.MethodPost, route,
		strings.NewReader(string(protoBody(t, "tampered"))))
	r.Header.Set("Content-Type", contentProto)
	// The human saw "approved". The request says "tampered".
	r.Header.Set(GrantHeader, i.mintGrant(t, "user:test", map[string]string{"producer": "approved"}))
	w := call(t, h, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
	body := decodeErr(t, w)
	if body.Code != "permission_denied" {
		t.Errorf("code = %q, want permission_denied: grant_required would send a "+
			"tampering caller to fetch another approval", body.Code)
	}
	if strings.Contains(body.Message, "tampered") || strings.Contains(body.Message, "approved") {
		t.Errorf("the refusal echoes request content: %q", body.Message)
	}
	if n := inv.calls.Load(); n != 0 {
		t.Errorf("the tool ran %d times on a grant that did not match the request", n)
	}

	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("%d ledger rows, want exactly 1", len(events))
	}
	if !strings.Contains(events[0].ErrorDetail, "does not match what was approved") {
		t.Errorf("the row does not say why it was refused: %q", events[0].ErrorDetail)
	}
	if got := w.Header().Get(EventHeader); got != events[0].ID {
		t.Errorf("Garm-Event-Id = %q, want %q", got, events[0].ID)
	}
}

// An approval is one call. The second attempt with the same grant is refused,
// and as a denial rather than as an invitation to retry.
func TestTheSameGrantCannotBeSpentTwiceThroughTheSurface(t *testing.T) {
	i := newGrantIDP(t)
	inv := &fakeInvoker{fill: "x"}
	h := gatedHandler(t, i, inv, &record.Memory{})
	token := i.mintGrant(t, "user:test", map[string]string{"producer": "approved"})

	send := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, route,
			strings.NewReader(string(protoBody(t, "approved"))))
		r.Header.Set("Content-Type", contentProto)
		r.Header.Set(GrantHeader, token)
		return call(t, h, r)
	}

	if w := send(); w.Code != http.StatusOK {
		t.Fatalf("the first call: status = %d, want 200: %s", w.Code, w.Body.String())
	}
	w := send()
	if w.Code != http.StatusForbidden {
		t.Fatalf("the second call: status = %d, want 403: %s", w.Code, w.Body.String())
	}
	if got := decodeErr(t, w).Code; got != "permission_denied" {
		t.Errorf("code = %q, want permission_denied", got)
	}
	if n := inv.calls.Load(); n != 1 {
		t.Errorf("the tool ran %d times for one approval", n)
	}
}

// No grant at all is still the one refusal with a next move, and it must not
// have been swept into the denial above.
func TestNoGrantIsStillGrantRequired(t *testing.T) {
	i := newGrantIDP(t)
	inv := &fakeInvoker{fill: "x"}
	h := gatedHandler(t, i, inv, &record.Memory{})

	r := httptest.NewRequest(http.MethodPost, route,
		strings.NewReader(string(protoBody(t, "approved"))))
	r.Header.Set("Content-Type", contentProto)
	w := call(t, h, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if got["code"] != "grant_required" {
		t.Errorf("code = %v, want grant_required: a caller with no approval has a "+
			"next move and must be told what it is", got["code"])
	}
}

// A catalogue that could not be served before this deployment had a verifier
// mounts once it does. The refusal is about capability, not a permanent ban.
func TestAGrantGatedCatalogueMountsWhenAVerifierIsConfigured(t *testing.T) {
	i := newGrantIDP(t)
	h := gatedHandler(t, i, &fakeInvoker{fill: "x"}, &record.Memory{})
	if err := h.Prepare(gatedCatalogue()); err != nil {
		t.Fatalf("a grant-gated catalogue would not mount against a configured "+
			"verifier: %v", err)
	}
}
