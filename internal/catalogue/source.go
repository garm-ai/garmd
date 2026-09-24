package catalogue

import (
	"context"
	"fmt"
	"os"
)

// FileSource reads a catalogue from disk.
//
// The only source there is, for now. A KV watch or an OCI reference is a
// question about what a running process will accept a new policy document
// from, which is a trust decision rather than a plumbing one — and the file
// is the one everybody can reason about.
type FileSource struct{ Path string }

func (f FileSource) Read(context.Context) ([]byte, error) { return os.ReadFile(f.Path) }
func (f FileSource) String() string                       { return fmt.Sprintf("file %s", f.Path) }

// BytesSource serves a catalogue already in memory, for tests and for a
// process handed its catalogue by something else.
type BytesSource struct {
	Body []byte
	Name string
}

func (b BytesSource) Read(context.Context) ([]byte, error) { return b.Body, nil }
func (b BytesSource) String() string {
	if b.Name == "" {
		return "bytes"
	}
	return b.Name
}
