package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/garm-ai/garmd/internal/catalogue"
)

// catalogueSource decides what --catalogue named.
//
// It returns the boot source AND, for an object store, the same value as the
// thing to poll. The same value rather than two constructions, because two
// could disagree about the key — and a process that serves one artifact while
// polling another would reload on a change to a document it is not serving.
//
// A file yields no pollable object. Watching a file is a different question
// (inotify, a mount that swaps under the process) and the answer to it is not
// "poll it every thirty seconds".
func catalogueSource(ctx context.Context, raw string) (catalogue.Source, *catalogue.S3Source, error) {
	bucket, key, ok := catalogue.ParseS3URL(raw)
	if !ok {
		if strings.HasPrefix(raw, "s3://") {
			return nil, nil, fmt.Errorf("--catalogue %q is not a usable object: it must "+
				"be s3://bucket/key, naming the object itself and not a prefix", raw)
		}
		return catalogue.FileSource{Path: raw}, nil, nil
	}
	client, err := catalogue.NewS3Client(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("--catalogue %s: %w", raw, err)
	}
	src := &catalogue.S3Source{Bucket: bucket, Key: key, Client: client}
	return src, src, nil
}
