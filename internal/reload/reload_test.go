package reload_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/reload"
)

// A reload is the one operation that can take a working deployment down
// without anybody deploying anything: the object is writable by whoever holds
// a key, and the process is already serving.
//
// So every test here is about what happens when the new generation is NOT
// good, and the property under test is always the same one — the generation
// that is serving keeps serving, and the log says which two artifacts are
// involved.

// catalogueBytes builds a real artifact in process. No dependency on the garm
// binary: a fixture that shelled out and SKIPPED when it was not on PATH would
// make every test here pass by doing nothing.
//
// The compartments are set on the catalogue MESSAGE rather than as a file
// option, because that is the half Load reads (catalogue.go's
// `msg.GetCompartments()`). A fixture declaring them the other way would leave
// every generation here with an empty taxonomy, and the registry test would
// then pass against two catalogues that both declare nothing.
func catalogueBytes(t *testing.T, toolName string, compartments ...string) []byte {
	t.Helper()

	src := fmt.Sprintf(`syntax = "proto3";
package t.v1;
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/t_v1;x";
message In {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string id = 1;
}
message Out {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string status = 1;
}
service S {
  rpc Get(In) returns (Out) {
    option (garm.tool.v1.tool) = {
      name: %q title: "T" description: "A tool."
      verb: VERB_READ min_clearance: CLEARANCE_PUBLIC
    };
  }
}
`, toolName)

	// The annotations resolve from the LINKED registry rather than from
	// source, so the fixture is one file and says only what it is about.
	res := protocompile.WithStandardImports(protocompile.CompositeResolver{
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, protoregistry.NotFound
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}),
		&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(
			map[string]string{"t/v1/t.proto": src})},
	})
	files, err := (&protocompile.Compiler{Resolver: res}).
		Compile(context.Background(), "t/v1/t.proto")
	if err != nil {
		t.Fatalf("compiling the fixture: %v", err)
	}

	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var collect func(fd protoreflect.FileDescriptor)
	collect = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imps := fd.Imports()
		for i := 0; i < imps.Len(); i++ {
			collect(imps.Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
	}
	for _, f := range files {
		collect(f)
	}

	// protocompile leaves options as dynamic messages, so they must be
	// re-parsed against the linked extension types or GetExtension sees a
	// *dynamicpb.Message where the loader wants a *toolv1.ToolPolicy. The same
	// round trip the real producer does.
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	set = &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(raw, set); err != nil {
		t.Fatal(err)
	}

	decls := make([]*toolv1.Decl, 0, len(compartments))
	for _, c := range compartments {
		decls = append(decls, &toolv1.Decl{Name: c})
	}
	body, err := proto.Marshal(&cataloguev1.Catalogue{
		AnnotationSchemaVersion: 1,
		Files:                   set,
		Compartments:            decls,
		Provenance:              &cataloguev1.Provenance{Producer: "reload_test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// store is the object, and a test can replace what it holds under a running
// poller — which is the whole point.
type store struct {
	mu   sync.Mutex
	body []byte
	etag string
	code int
	head int
	gets int
}

func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code != 0 {
		w.WriteHeader(s.code)
		return
	}
	w.Header().Set("ETag", s.etag)
	if r.Method == http.MethodHead {
		s.head++
		w.WriteHeader(http.StatusOK)
		return
	}
	s.gets++
	_, _ = w.Write(s.body)
}

func (s *store) put(body []byte, etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.etag, s.code = body, etag, 0
}

func (s *store) fail(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
}

func (s *store) heads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

func (s *store) reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

// prepared records what the handler was asked about, and can refuse.
//
// Two methods rather than one, because the daemon's handler has two: Check
// builds a candidate's chain and throws it away, Prepare publishes one for the
// generation now current. A poller that pre-flighted through Prepare would
// publish the chain of a generation nothing is serving yet.
type prepared struct {
	mu       sync.Mutex
	checked  []string
	prepared []string
	refuse   bool
}

func (p *prepared) Check(cat *catalogue.Catalogue) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refuse {
		return fmt.Errorf("this deployment cannot govern %s", cat.Digest)
	}
	p.checked = append(p.checked, cat.Digest)
	return nil
}

func (p *prepared) Prepare(cat *catalogue.Catalogue) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refuse {
		return fmt.Errorf("this deployment cannot govern %s", cat.Digest)
	}
	p.prepared = append(p.prepared, cat.Digest)
	return nil
}

func (p *prepared) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.prepared...)
}

type fixture struct {
	obj    *store
	poller *reload.Poller
	store  *catalogue.Store
	handle *prepared
	regs   *authn.Swappable
	log    *bytes.Buffer
}

func newFixture(t *testing.T, first []byte) *fixture {
	t.Helper()
	obj := &store{body: first, etag: `"v1"`}
	srv := httptest.NewServer(obj)
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("t", "t", ""),
		// The failure test makes every request fail; without this the SDK
		// spends several seconds retrying a store that was never going to
		// answer differently.
		Retryer: aws.NopRetryer{},
	})
	src := &catalogue.S3Source{Bucket: "garm", Key: "catalogue.binpb", Client: client}

	st := catalogue.NewStore(catalogue.Options{})
	boot, err := st.Reload(context.Background(), src)
	if err != nil {
		t.Fatalf("the boot catalogue: %v", err)
	}
	reg, err := policy.NewRegistry(boot.Compartments)
	if err != nil {
		t.Fatal(err)
	}
	regs := authn.NewSwappable(reg)
	handle := &prepared{}
	if err := handle.Prepare(boot); err != nil {
		t.Fatal(err)
	}

	log := &bytes.Buffer{}
	return &fixture{
		obj:    obj,
		store:  st,
		handle: handle,
		regs:   regs,
		log:    log,
		poller: &reload.Poller{
			Source:       src,
			Store:        st,
			Handler:      handle,
			Compartments: regs,
			Log:          slog.New(slog.NewTextHandler(log, nil)),
			Interval:     10 * time.Millisecond,
		},
	}
}

// The ordinary case, and the one everything else is measured against.
func TestANewGenerationIsSwappedInWhenTheETagChanges(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current().Digest

	f.obj.put(catalogueBytes(t, "get_balance"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Swapped {
		t.Fatalf("outcome = %v, want Swapped. Log:\n%s", got, f.log)
	}

	now := f.store.Current()
	if now.Digest == was {
		t.Fatal("the store still holds the previous generation")
	}
	if len(now.Defs) != 1 || now.Defs[0].Name != "get_balance" {
		t.Errorf("the current generation declares %v, want get_balance", now.Defs)
	}
	// The generation that is actually current was prepared, not only the
	// pre-flight copy: the first request after a reload must not be the one
	// that discovers a chain it cannot build.
	seen := f.handle.seen()
	if seen[len(seen)-1] != now.Digest {
		t.Errorf("the prepared digest is %q and the current one is %q",
			seen[len(seen)-1], now.Digest)
	}
}

// An unchanged ETag costs one HEAD and nothing else. A poller that re-read the
// object every thirty seconds would download the catalogue 2,880 times a day
// to learn nothing.
func TestAnUnchangedETagDoesNotReRead(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()

	for i := 0; i < 3; i++ {
		if got := f.poller.Once(context.Background()); got != reload.Unchanged {
			t.Fatalf("outcome = %v, want Unchanged", got)
		}
	}
	if f.store.Current() != was {
		t.Error("the generation was replaced although the object had not changed")
	}
	if f.obj.heads() != 3 {
		t.Errorf("%d HEADs for three polls", f.obj.heads())
	}
	// One GET at boot, and one on the first poll — which is the poll that
	// learns the ETag of the object boot had already read. After that the
	// header alone answers, and the artifact is not transferred again.
	if got := f.obj.reads(); got != 2 {
		t.Errorf("%d GETs for a boot and three polls of an unchanged object, want 2", got)
	}
}

// A poller boots without knowing the object's ETag — the store read the bytes,
// not the header — so its first poll reads once and must then recognise its
// own generation rather than swap a fresh copy of it in. The same line covers
// a re-upload of identical bytes, which changes the ETag and nothing else.
func TestReUploadedIdenticalBytesAreNotANewGeneration(t *testing.T) {
	body := catalogueBytes(t, "get_status")
	f := newFixture(t, body)
	was := f.store.Current()

	f.obj.put(body, `"v2-same-bytes"`)
	if got := f.poller.Once(context.Background()); got != reload.Unchanged {
		t.Fatalf("outcome = %v, want Unchanged. Log:\n%s", got, f.log)
	}
	if f.store.Current() != was {
		t.Error("identical bytes under a new ETag replaced the generation")
	}
	// And the ETag it has now been told about is remembered, so the next poll
	// costs a HEAD rather than another download.
	reads := f.obj.reads()
	if got := f.poller.Once(context.Background()); got != reload.Unchanged {
		t.Fatalf("outcome = %v on the second poll, want Unchanged", got)
	}
	if f.obj.reads() != reads {
		t.Error("the object was downloaded again for an ETag already seen")
	}
}

// (Review Focus 4) Bytes that do not load.
//
// The object is writable by whoever holds a key, and a truncated upload is the
// likeliest way this arrives. The previous generation keeps serving, and the
// line names BOTH artifacts — without the refused digest an operator is
// comparing timestamps against a bucket's version history.
func TestBytesThatDoNotLoadLeaveThePreviousGenerationServing(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()

	bad := []byte("this is not a catalogue at all, not even slightly")
	f.obj.put(bad, `"v2"`)

	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	if f.store.Current() != was {
		t.Fatal("a catalogue that does not load became the one being served")
	}
	log := f.log.String()
	for _, want := range []string{was.Digest, catalogue.DigestOf(bad)} {
		if !strings.Contains(log, want) {
			t.Errorf("the log does not name %s:\n%s", want, log)
		}
	}
}

// (Review Focus 4) A generation that loads and cannot be governed.
//
// This is the sharper half: the artifact is a valid catalogue, and this
// deployment has not been given a step it declares. Mounting it would serve a
// tool ungated while its schema says it is supervised, so the pre-flight has to
// happen BEFORE the store swaps — there is no way to put a generation back.
func TestAGenerationThisDeploymentCannotGovernIsNeverSwappedIn(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()
	next := catalogueBytes(t, "get_balance")

	f.handle.refuse = true
	f.obj.put(next, `"v2"`)

	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	if f.store.Current() != was {
		t.Fatal("a generation the handler refused became the one being served")
	}
	log := f.log.String()
	for _, want := range []string{was.Digest, catalogue.DigestOf(next)} {
		if !strings.Contains(log, want) {
			t.Errorf("the log does not name %s:\n%s", want, log)
		}
	}

	// And the refusal is not permanent: the same object, once the deployment
	// can govern it, is taken.
	f.handle.refuse = false
	if got := f.poller.Once(context.Background()); got != reload.Swapped {
		t.Fatalf("outcome = %v after the refusal was lifted, want Swapped", got)
	}
}

// A refusal this deployment's CONFIGURATION makes rather than its chain.
//
// The one that forced this seam: the replay bucket's expiry is derived at
// startup from the boot catalogue's longest max_grant_age, and a reload does
// not re-derive it. A generation raising that ceiling past what the bucket
// keeps would make an approval replayable in the gap — silently, since the
// chain mounts it perfectly happily. So the daemon supplies the check, and the
// poller treats it exactly like the others: refuse, keep, name both digests.
func TestAGenerationThisDeploymentCannotCoverIsRefused(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()
	next := catalogueBytes(t, "get_balance")

	var asked []string
	f.poller.Admit = func(cat *catalogue.Catalogue) error {
		asked = append(asked, cat.Digest)
		return fmt.Errorf("the replay cache keeps an entry for 1h and a tool declares " +
			"grants valid for 2h")
	}
	f.obj.put(next, `"v2"`)

	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	if f.store.Current() != was {
		t.Fatal("a generation this deployment cannot cover became the one being served")
	}
	if len(asked) != 1 || asked[0] != catalogue.DigestOf(next) {
		t.Errorf("the check was asked about %v, want the candidate %s",
			asked, catalogue.DigestOf(next))
	}
	log := f.log.String()
	for _, want := range []string{was.Digest, catalogue.DigestOf(next), "replay cache"} {
		if !strings.Contains(log, want) {
			t.Errorf("the log does not name %s:\n%s", want, log)
		}
	}
	// And the chain was never built for it: a generation already refused must
	// not pay for a mount check nobody will use.
	if len(f.handle.checked) != 0 {
		t.Errorf("the chain was built for a generation already refused: %v", f.handle.checked)
	}
}

// (Review Focus 5) The store answers 500, or stops answering.
//
// A bucket that cannot be reached is not evidence that what is serving is
// wrong, and a poller that died on the first transient failure would stop
// reloading with nothing to see until the next deploy.
func TestATransientStoreFailureNeitherSwapsNorStopsThePoller(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()

	f.obj.fail(http.StatusInternalServerError)
	for i := 0; i < 3; i++ {
		if got := f.poller.Once(context.Background()); got != reload.Kept {
			t.Fatalf("outcome = %v, want Kept", got)
		}
	}
	if f.store.Current() != was {
		t.Error("a generation changed while the store was failing")
	}
	if !strings.Contains(f.log.String(), "s3://garm/catalogue.binpb") {
		t.Errorf("the warning does not name the source:\n%s", f.log)
	}

	// The store comes back. The poller must still be able to take a new
	// generation — this is the assertion that a failure did not leave it stuck.
	f.obj.put(catalogueBytes(t, "get_balance"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Swapped {
		t.Fatalf("outcome = %v after the store recovered, want Swapped", got)
	}
}

// The gap KNOWN-GAPS named: a reload that adds a compartment must reach the
// verifier. The token-level half of this is in internal/authn's Swappable
// tests; this is the half that proves the reload actually calls Set.
func TestASuccessfulReloadRebuildsTheCompartmentRegistry(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status", "financial"))

	if _, err := f.regs.Registry().Set([]string{"pii-contact"}); err == nil {
		t.Fatal("the boot registry already declares pii-contact; the fixture proves nothing")
	}

	f.obj.put(catalogueBytes(t, "get_status", "financial", "pii-contact"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Swapped {
		t.Fatalf("outcome = %v, want Swapped. Log:\n%s", got, f.log)
	}

	if _, err := f.regs.Registry().Set([]string{"pii-contact"}); err != nil {
		t.Errorf("a compartment the new generation declares is still unknown to the "+
			"verifier: %v", err)
	}
	if _, err := f.regs.Registry().Set([]string{"financial"}); err != nil {
		t.Errorf("a compartment both generations declare was lost: %v", err)
	}
}

// A refused generation must not leave the verifier holding its taxonomy: a
// registry swapped for a catalogue nobody is serving would widen or narrow
// every token against a document that is not in force.
func TestARefusedGenerationDoesNotRebuildTheRegistry(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status", "financial"))
	f.handle.refuse = true

	f.obj.put(catalogueBytes(t, "get_status", "financial", "pii-contact"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	if _, err := f.regs.Registry().Set([]string{"pii-contact"}); err == nil {
		t.Error("the taxonomy of a generation nobody is serving reached the verifier")
	}
}

// Run polls until its context is done, and returns. A poller that outlived
// shutdown would hold the process open past SIGTERM.
func TestRunPollsUntilItsContextIsDone(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.poller.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for f.obj.heads() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the poller never polled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// (Fix round 1, item 1) A refused object is examined again on every poll —
// that is what lets a refusal lift without the object changing — but it is not
// FETCHED again. Some refusals cannot lift in process at all: a generation
// whose approvals outlive the replay cache is refused until someone restarts,
// and re-downloading up to 256 MiB every thirty seconds to reach the same
// sentence is a cost nobody asked for and an egress bill nobody predicted.
func TestARefusedObjectIsNotDownloadedAgainWhileItsETagIsUnchanged(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	was := f.store.Current()
	f.poller.Admit = func(*catalogue.Catalogue) error {
		return fmt.Errorf("the replay cache keeps an entry for 1h and a tool declares " +
			"grants valid for 2h")
	}

	f.obj.put(catalogueBytes(t, "get_balance"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	after := f.obj.reads()

	for i := 0; i < 3; i++ {
		if got := f.poller.Once(context.Background()); got != reload.Kept {
			t.Fatalf("poll %d: outcome = %v, want Kept", i, got)
		}
	}
	if f.obj.reads() != after {
		t.Errorf("the refused object was downloaded %d more times while its ETag was "+
			"unchanged", f.obj.reads()-after)
	}
	if f.store.Current() != was {
		t.Error("the generation changed while every poll was refusing")
	}
	// And it is stated ONCE. On a thirty-second poll an unchanged refusal
	// would otherwise be 2,880 identical error lines a day, which is how the
	// line that matters gets missed.
	if n := strings.Count(f.log.String(), "not covered by this deployment"); n != 1 {
		t.Errorf("the same refusal was logged %d times over four polls, want once:\n%s",
			n, f.log)
	}
}

// (Fix round 1, item 1) The cache must not swallow a change. A new object
// under a new ETag is fetched, whatever was refused before it.
func TestAChangedETagAfterARefusalIsReadAgain(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	f.handle.refuse = true

	f.obj.put(catalogueBytes(t, "get_balance"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	after := f.obj.reads()

	// A different object, and one this deployment can govern.
	f.handle.refuse = false
	f.obj.put(catalogueBytes(t, "get_ledger"), `"v3"`)
	if got := f.poller.Once(context.Background()); got != reload.Swapped {
		t.Fatalf("outcome = %v after the object changed, want Swapped. Log:\n%s", got, f.log)
	}
	if f.obj.reads() <= after {
		t.Error("a changed object was served out of the refused-object cache")
	}
	if now := f.store.Current(); len(now.Defs) != 1 || now.Defs[0].Name != "get_ledger" {
		t.Errorf("the current generation declares %v, want get_ledger", now.Defs)
	}
}

// unreadable is an object that answers its ETag and then refuses to be read,
// deterministically — the shape of an artifact past the byte ceiling. A real
// one would be 256 MiB, and building that here would make the suite pay the
// cost this test exists to stop the DAEMON paying.
type unreadable struct {
	etag  string
	reads int
}

func (u *unreadable) ETag(context.Context) (string, error) { return u.etag, nil }
func (u *unreadable) String() string                       { return "s3://garm/huge.binpb" }

func (u *unreadable) Read(context.Context) ([]byte, error) {
	u.reads++
	return nil, fmt.Errorf("%s is %w: the ceiling is %d bytes",
		u, catalogue.ErrTooLarge, catalogue.MaxBytes)
}

// (Fix round 1, item 2) An object too large to read is a REFUSAL of an
// artifact, not a store that could not be reached, so it is logged at error
// and names the generation still serving. And it is deterministic: fetching it
// again would transfer the ceiling a second time to reach the same sentence,
// so it is not fetched again until it changes.
func TestAnObjectTooLargeToReadIsRefusedLoudlyAndNotFetchedAgain(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	serving := f.store.Current()
	obj := &unreadable{etag: `"huge"`}
	f.poller.Source = obj

	for i := 0; i < 3; i++ {
		if got := f.poller.Once(context.Background()); got != reload.Kept {
			t.Fatalf("poll %d: outcome = %v, want Kept", i, got)
		}
	}
	if obj.reads != 1 {
		t.Errorf("the object was read %d times; an object past the ceiling is read "+
			"once until it changes", obj.reads)
	}
	log := f.log.String()
	if !strings.Contains(log, "level=ERROR") {
		t.Errorf("an artifact this process refused was logged below error:\n%s", log)
	}
	for _, want := range []string{"s3://garm/huge.binpb", serving.Digest} {
		if !strings.Contains(log, want) {
			t.Errorf("the refusal does not name %s:\n%s", want, log)
		}
	}

	// A new object under a new ETag is read, however large the last one was.
	obj.etag = `"huge-2"`
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	if obj.reads != 2 {
		t.Errorf("a changed object was not read: %d reads", obj.reads)
	}
}

// The restatement throttle keys on the reason, not only on the object: one
// object whose coverage refusal lifts, only for the chain build to refuse it,
// is two different facts, and an operator hears both — now, not in an hour.
func TestAChangedRefusalReasonForTheSameObjectIsLoggedAtOnce(t *testing.T) {
	f := newFixture(t, catalogueBytes(t, "get_status"))
	f.poller.Admit = func(*catalogue.Catalogue) error {
		return fmt.Errorf("the replay cache keeps an entry for 1h and a tool declares " +
			"grants valid for 2h")
	}
	f.obj.put(catalogueBytes(t, "get_balance"), `"v2"`)
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}

	// Same object, same ETag; the coverage refusal lifts and the chain refuses.
	f.poller.Admit = nil
	f.handle.refuse = true
	if got := f.poller.Once(context.Background()); got != reload.Kept {
		t.Fatalf("outcome = %v, want Kept", got)
	}
	log := f.log.String()
	if !strings.Contains(log, "not covered by this deployment") {
		t.Errorf("the first refusal was not logged:\n%s", log)
	}
	if !strings.Contains(log, "cannot be governed by this deployment") {
		t.Errorf("the changed refusal reason was swallowed by the throttle:\n%s", log)
	}
}
