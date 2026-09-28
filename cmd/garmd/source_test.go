package main

import (
	"context"
	"strings"
	"testing"
)

// --catalogue takes a path or an s3:// URL, and what is neither must be
// refused rather than treated as a filename: the error for a malformed URL
// otherwise reads as a missing file and sends an operator to check a mount.
func TestTheCatalogueFlagDistinguishesAPathFromAnObject(t *testing.T) {
	src, obj, err := catalogueSource(context.Background(), "/var/lib/garm/catalogue.binpb")
	if err != nil {
		t.Fatalf("a path was refused: %v", err)
	}
	if obj != nil {
		t.Error("a file catalogue produced a pollable object; nothing polls a file")
	}
	if got := src.String(); !strings.Contains(got, "/var/lib/garm/catalogue.binpb") {
		t.Errorf("source = %q, which does not name the file", got)
	}
}

func TestAMalformedS3URLIsRefusedRatherThanTreatedAsAPath(t *testing.T) {
	for _, raw := range []string{"s3://garm", "s3://", "s3:///catalogue.binpb"} {
		if _, _, err := catalogueSource(context.Background(), raw); err == nil {
			t.Errorf("%q was accepted", raw)
		} else if !strings.Contains(err.Error(), "s3://bucket/key") {
			t.Errorf("the error for %q does not say the shape expected: %v", raw, err)
		}
	}
}

// An s3:// URL yields BOTH the boot source and the object the poller watches,
// because they must be the same object: two constructions could disagree about
// the key, and the process would then serve one artifact and poll another.
func TestAnS3URLYieldsTheSameObjectForBootAndForPolling(t *testing.T) {
	src, obj, err := catalogueSource(context.Background(), "s3://garm/catalogue/catalogue.binpb")
	if err != nil {
		t.Fatalf("catalogueSource: %v", err)
	}
	if obj == nil {
		t.Fatal("an s3:// catalogue produced nothing to poll")
	}
	if src.String() != obj.String() {
		t.Errorf("boot reads %q and the poller watches %q", src, obj)
	}
	if obj.Bucket != "garm" || obj.Key != "catalogue/catalogue.binpb" {
		t.Errorf("bucket/key = %q/%q, want garm/catalogue/catalogue.binpb",
			obj.Bucket, obj.Key)
	}
}
