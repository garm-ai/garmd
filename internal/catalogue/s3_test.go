package catalogue_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/garm-ai/garmd/internal/catalogue"
)

// A real S3 client against an httptest server, rather than a mocked client.
//
// What is worth asserting here is the REQUEST this code builds — the bucket,
// the key, path-style addressing against an endpoint that is an address rather
// than a virtual host — and a mock would be this file asserting its own
// opinion of that. What it deliberately does not cover is any specific store's
// behaviour: SeaweedFS, MinIO and S3 itself differ on ETag quoting, and the
// reload path treats the value as opaque for exactly that reason.
type fakeS3 struct {
	mu   sync.Mutex
	body []byte
	etag string
	// emptyETag sends an ETag header whose value is "", which the SDK
	// deserialises as a non-nil pointer to "" — a different state from an
	// omitted header, and one the source must refuse just the same.
	emptyETag bool
	code      int // when non-zero, every request gets this status
	gets int
	head int
}

func newFakeS3(t *testing.T, body []byte, etag string) (*fakeS3, *s3.Client) {
	t.Helper()
	f := &fakeS3{body: body, etag: etag}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		// Path style, because a dev endpoint is an address and not a name: a
		// virtual-host request would resolve bucket.127.0.0.1, which is not a
		// host anything answers on.
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		// The failure test deliberately makes every request fail; without
		// this the SDK's default retry policy spends several seconds
		// retrying a 500 from a store that was never going to answer
		// differently.
		Retryer: aws.NopRetryer{},
	})
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.code != 0 {
		w.WriteHeader(f.code)
		return
	}
	if r.URL.Path != "/garm/catalogue/catalogue.binpb" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.etag != "" || f.emptyETag {
		w.Header().Set("ETag", f.etag)
	}
	switch r.Method {
	case http.MethodHead:
		f.head++
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		f.gets++
		_, _ = w.Write(f.body)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) set(body []byte, etag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body, f.etag = body, etag
}

func (f *fakeS3) fail(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.code = code
}

func source(c *s3.Client) *catalogue.S3Source {
	return &catalogue.S3Source{
		Bucket: "garm", Key: "catalogue/catalogue.binpb", Client: c,
	}
}

func TestAnObjectIsReadFromItsBucketAndKey(t *testing.T) {
	fake, client := newFakeS3(t, []byte("the artifact"), `"abc"`)

	got, err := source(client).Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "the artifact" {
		t.Errorf("read %q, want %q", got, "the artifact")
	}
	if fake.gets != 1 {
		t.Errorf("%d GETs, want 1", fake.gets)
	}
}

// A bucket somebody can write is not a bucket that only ever holds what was
// meant to be there, so Read enforces the same ceiling Load does — refusing
// an oversized object here, with a sentence naming it, rather than handing
// MaxBytes+1 bytes to Load to refuse a second time.
func TestReadRefusesAnObjectOverTheCeiling(t *testing.T) {
	body := make([]byte, catalogue.MaxBytes+1)
	fake, client := newFakeS3(t, body, `"abc"`)

	_, err := source(client).Read(context.Background())
	if err == nil {
		t.Fatal("Read accepted an object one byte over the ceiling")
	}
	if !strings.Contains(err.Error(), "s3://garm/catalogue/catalogue.binpb") {
		t.Errorf("the error does not name the object: %v", err)
	}
	if fake.gets != 1 {
		t.Errorf("%d GETs, want 1", fake.gets)
	}
}

// The ETag is the change signal, and it is OPAQUE: quoted by S3, sometimes
// unquoted elsewhere, a multipart suffix on a large object. Nothing here
// interprets it — a poller compares it with the last one, and that is all it
// has to mean.
func TestTheETagComesBackFromAHeadWithoutReadingTheObject(t *testing.T) {
	fake, client := newFakeS3(t, []byte("the artifact"), `"abc"`)

	got, err := source(client).ETag(context.Background())
	if err != nil {
		t.Fatalf("ETag: %v", err)
	}
	if got != `"abc"` {
		t.Errorf("ETag = %q, want %q verbatim", got, `"abc"`)
	}
	if fake.gets != 0 {
		t.Errorf("%d GETs for a HEAD; polling would download the catalogue every "+
			"30 seconds", fake.gets)
	}
	if fake.head != 1 {
		t.Errorf("%d HEADs, want 1", fake.head)
	}

	fake.set([]byte("a new artifact"), `"def"`)
	if got, err := source(client).ETag(context.Background()); err != nil || got != `"def"` {
		t.Errorf("ETag after a change = %q, %v; want \"def\"", got, err)
	}
}

// A poller compares this generation's ETag with the last one it saw, and ""
// compared to "" never differs: a store that omits the header would look
// like an object that never changes. That is refused rather than trusted.
// The ceiling is inclusive: an object of exactly MaxBytes is a legal
// catalogue, and a check written as >= would refuse it.
func TestReadAcceptsAnObjectExactlyAtTheCeiling(t *testing.T) {
	body := make([]byte, catalogue.MaxBytes)
	_, client := newFakeS3(t, body, `"abc"`)

	got, err := source(client).Read(context.Background())
	if err != nil {
		t.Fatalf("Read refused an object exactly at the ceiling: %v", err)
	}
	if len(got) != catalogue.MaxBytes {
		t.Fatalf("Read returned %d bytes, want %d", len(got), catalogue.MaxBytes)
	}
}

// A present-but-empty ETag header is the other way a store can fail to
// signal change; the SDK hands it over as a pointer to "", not nil.
func TestAPresentButEmptyETagIsAnError(t *testing.T) {
	fake, client := newFakeS3(t, []byte("the artifact"), "")
	fake.emptyETag = true

	_, err := source(client).ETag(context.Background())
	if err == nil {
		t.Fatal("a HEAD with an empty ETag header reported a successful ETag")
	}
	if !strings.Contains(err.Error(), "cannot signal change") {
		t.Errorf("the error does not say why an empty ETag is refused: %v", err)
	}
}

func TestAnAbsentETagIsAnError(t *testing.T) {
	_, client := newFakeS3(t, []byte("the artifact"), "")

	_, err := source(client).ETag(context.Background())
	if err == nil {
		t.Fatal("a HEAD with no ETag header reported a successful ETag")
	}
	if !strings.Contains(err.Error(), "s3://garm/catalogue/catalogue.binpb") {
		t.Errorf("the error does not name the object: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot signal change") {
		t.Errorf("the error does not say why an empty ETag is refused: %v", err)
	}
}

// An unreachable or missing object is an error naming the URL, because the
// operator reading it needs to know WHICH object, and an S3 SDK error alone
// names a bucket and a key in a sentence nobody can grep for.
func TestAFailureNamesTheObject(t *testing.T) {
	fake, client := newFakeS3(t, []byte("x"), `"abc"`)
	fake.fail(http.StatusInternalServerError)

	_, readErr := source(client).Read(context.Background())
	if readErr == nil {
		t.Fatal("a failing store reported a successful read")
	}
	_, etagErr := source(client).ETag(context.Background())
	if etagErr == nil {
		t.Fatal("a failing store reported a successful HEAD")
	}
	for _, err := range []error{readErr, etagErr} {
		if !strings.Contains(err.Error(), "s3://garm/catalogue/catalogue.binpb") {
			t.Errorf("the error does not name the object: %v", err)
		}
	}
}

// --catalogue takes a path or an s3:// URL, and anything that is neither a
// usable URL nor a path has to be refused rather than treated as a filename:
// "s3://garm" as a path is a file nobody has, and the error would be about a
// missing file rather than about a malformed flag.
func TestParseS3URL(t *testing.T) {
	for _, c := range []struct {
		raw         string
		bucket, key string
		ok          bool
	}{
		{"s3://garm/catalogue.binpb", "garm", "catalogue.binpb", true},
		{"s3://garm/catalogue/catalogue.binpb", "garm", "catalogue/catalogue.binpb", true},
		{"s3://garm", "", "", false},
		{"s3://garm/", "", "", false},
		{"s3://garm//catalogue.binpb", "", "", false},
		{"s3:///key", "", "", false},
		{"s3://", "", "", false},
		{"/var/lib/garm/catalogue.binpb", "", "", false},
		{"", "", "", false},
	} {
		bucket, key, ok := catalogue.ParseS3URL(c.raw)
		if ok != c.ok || bucket != c.bucket || key != c.key {
			t.Errorf("ParseS3URL(%q) = %q, %q, %v; want %q, %q, %v",
				c.raw, bucket, key, ok, c.bucket, c.key, c.ok)
		}
	}
}

// The digest is over the bytes as handed over, so a refused artifact can be
// named in a log line without being parsed first.
func TestDigestOfIsOverTheBytesAsGiven(t *testing.T) {
	// sha256 of the empty string, which anyone can check.
	const empty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := catalogue.DigestOf(nil); got != empty {
		t.Errorf("DigestOf(nil) = %q, want %q", got, empty)
	}
	if catalogue.DigestOf([]byte("a")) == catalogue.DigestOf([]byte("b")) {
		t.Error("two different artifacts have the same digest")
	}
}
