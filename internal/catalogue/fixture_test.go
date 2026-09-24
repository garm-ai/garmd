package catalogue_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/bufbuild/protocompile"
	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Fixtures are built in process, with no dependency on the garm binary.
//
// An earlier version shelled out and SKIPPED when it was not on PATH, which
// made every test here pass by doing nothing. A green run with zero coverage
// is worse than a red one, because nobody looks at it twice.
//
// What this does not cover is producer/consumer agreement — that garm writes
// what this reads. That belongs in a cross-repo test where both exist, not in
// a skip.

func buildCatalogue(t *testing.T, toolName string) []byte {
	t.Helper()
	return buildCatalogueFrom(t, map[string]string{"t.v1": toolName})
}

// buildCatalogueFrom builds one catalogue holding a single tool per proto
// package, so a test can put the same short name in two of them.
func buildCatalogueFrom(t *testing.T, tools map[string]string) []byte {
	t.Helper()
	srcs := map[string]string{}
	var paths []string
	for pkg, toolName := range tools {
		path := strings.ReplaceAll(pkg, ".", "/") + "/t.proto"
		srcs[path] = protoFor(pkg, toolName)
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return assemble(t, srcs, paths)
}

func protoFor(pkg, toolName string) string {
	return fmt.Sprintf(`syntax = "proto3";
package %s;
import "garm/tool/v1/tool.proto";
option go_package = "example.com/gen/%s;x";
message In {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  // The thing to look up.
  optional string id = 1;
}
message Out {
  option (garm.tool.v1.default_field_policy) = { read: CLEARANCE_PUBLIC on_deny: { omit: {} } };
  optional string status = 1;
}
service S {
  rpc Get(In) returns (Out) {
    option (garm.tool.v1.tool) = {
      name: "%s" title: "T" description: "A tool."
      verb: VERB_READ min_clearance: CLEARANCE_PUBLIC
    };
  }
}
`, pkg, strings.ReplaceAll(pkg, ".", "_"), toolName)
}

func assemble(t *testing.T, srcs map[string]string, paths []string) []byte {
	t.Helper()

	// The annotations resolve from the linked registry rather than from
	// source, so a fixture is one file and says only what it is about.
	res := protocompile.WithStandardImports(protocompile.CompositeResolver{
		protocompile.ResolverFunc(func(path string) (protocompile.SearchResult, error) {
			fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
			if err != nil {
				return protocompile.SearchResult{}, protoregistry.NotFound
			}
			return protocompile.SearchResult{Desc: fd}, nil
		}),
		&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(srcs)},
	})
	files, err := (&protocompile.Compiler{Resolver: res}).Compile(context.Background(), paths...)
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
	// *dynamicpb.Message where it wants a *toolv1.ToolPolicy. The same round
	// trip the real producer does.
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	set = &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(raw, set); err != nil {
		t.Fatal(err)
	}

	body, err := proto.Marshal(&cataloguev1.Catalogue{
		AnnotationSchemaVersion: 1,
		Files:                   set,
		Provenance:              &cataloguev1.Provenance{Producer: "catalogue_test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
