package catalogue

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the part of the S3 client this package uses, and it is exactly two
// read operations.
//
// Narrow on purpose. garmd reads a policy document from an object store; it
// does not write one, does not create buckets, and must not acquire the
// ability to. A seam wide enough to put an object is a seam somebody
// eventually puts an object through.
type S3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// S3Source reads a catalogue from an S3-compatible object store.
//
// The second Source there is, beside the file. What makes it a different
// question rather than a different filename is that the object changes under a
// running process: a file is placed by whoever deployed this binary, and a
// bucket is writable by whoever holds a key. The reload path is where that is
// answered — a generation this deployment cannot govern never becomes current
// — and this type does nothing but fetch bytes and report an ETag.
type S3Source struct {
	Bucket string
	Key    string
	Client S3API
}

var _ Source = (*S3Source)(nil)

func (s *S3Source) Read(ctx context.Context) ([]byte, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s.Key),
	})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s, err)
	}
	defer func() { _ = out.Body.Close() }()

	// Bounded by the same ceiling Load applies, one byte over so that an
	// object past it fails here with a sentence rather than after the whole
	// thing is in memory. A bucket somebody can write is not a bucket that
	// only ever holds what was meant to be there.
	body, err := io.ReadAll(io.LimitReader(out.Body, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s, err)
	}
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("%s is larger than the %d-byte ceiling", s, MaxBytes)
	}
	return body, nil
}

// ETag is the change signal.
//
// OPAQUE, and compared rather than interpreted. S3 quotes it, some
// S3-compatible stores do not, and a multipart upload's carries a part-count
// suffix — none of which matters to a poller asking "is this the object I
// already have". A cheaper HEAD rather than a GET, because polling every
// thirty seconds must not mean downloading the catalogue every thirty seconds.
func (s *S3Source) ETag(ctx context.Context) (string, error) {
	out, err := s.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s.Key),
	})
	if err != nil {
		return "", fmt.Errorf("checking %s: %w", s, err)
	}
	etag := aws.ToString(out.ETag)
	if etag == "" {
		// A poller compares this generation's ETag with the last one it saw,
		// and "" equal to "" never differs — a store that omits the header
		// would look indistinguishable from an object that never changes.
		// Refused rather than trusted as "unchanged".
		return "", fmt.Errorf("checking %s: cannot signal change: no ETag", s)
	}
	return etag, nil
}

func (s *S3Source) String() string { return fmt.Sprintf("s3://%s/%s", s.Bucket, s.Key) }

// ParseS3URL splits s3://bucket/key.
//
// Anything that is not one is reported as not one, rather than being allowed
// through as a path: "s3://garm" treated as a filename produces an error about
// a missing file, which sends an operator to check a mount rather than to fix
// a flag.
func ParseS3URL(raw string) (bucket, key string, ok bool) {
	rest, found := strings.CutPrefix(raw, "s3://")
	if !found {
		return "", "", false
	}
	bucket, key, found = strings.Cut(rest, "/")
	// A leading slash in what follows the bucket is an empty first key
	// segment — "s3://garm//catalogue.binpb" — which is a malformed flag,
	// not a key that happens to start with a slash.
	if !found || bucket == "" || key == "" || strings.HasPrefix(key, "/") {
		return "", "", false
	}
	return bucket, key, true
}

// EndpointEnv is the variable that points this at something other than AWS.
const EndpointEnv = "AWS_ENDPOINT_URL"

// NewS3Client builds a client from the AWS default credential chain.
//
// The default chain rather than flags, because credentials on a command line
// are visible in `ps`, in shell history and in whatever the orchestrator logs
// — and every deployment target already has an answer: an instance role, a
// service account, a mounted file.
//
// AWS_ENDPOINT_URL points it at SeaweedFS or MinIO, and forces path-style
// addressing when it does: a local endpoint is an address rather than a name,
// and a virtual-host request would resolve bucket.127.0.0.1.
//
// It also sets RequestChecksumCalculationWhenRequired, for symmetry with
// `garm catalogue publish` on the other side of this store, which needs that
// setting because SeaweedFS and MinIO reject the CRC32 trailer the SDK's
// newer default attaches to a PutObject. It is inert here — GetObject and
// HeadObject never attach a request checksum regardless of this setting —
// so this line changes nothing this package does; it is set so that anyone
// pointing this client at a write path later inherits the same answer rather
// than rediscovering it. The read-side knob to watch instead is
// ResponseChecksumValidation, which governs whether THIS client verifies a
// checksum on what it receives; worth a look at the Task 10 smoke test
// against the real store.
func NewS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("the AWS configuration: %w", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if ep := os.Getenv(EndpointEnv); ep != "" {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		}
	}), nil
}
