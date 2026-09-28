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
	return aws.ToString(out.ETag), nil
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
	if !found || bucket == "" || key == "" {
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
// and a virtual-host request would resolve bucket.127.0.0.1. It also sets
// RequestChecksumCalculationWhenRequired, matching `garm catalogue publish`
// on the other side of this store: SeaweedFS and MinIO reject the CRC32
// trailer the SDK's newer default attaches to every request, so both sides
// of the same local store have to agree not to send one.
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
