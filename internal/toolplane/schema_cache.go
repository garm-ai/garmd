package toolplane

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/garm-ai/garm/policy"
)

// schemaKey identifies one projection.
//
// Keyed on descriptor IDENTITY rather than full name, for the same reason
// toolpolicy's plan cache is: two distinct descriptors can share a name — a
// dynamicpb message beside a generated type — and they are not
// interchangeable. The dimension is in the key because input and output are
// decided on different clearances.
type schemaKey struct {
	desc   protoreflect.MessageDescriptor
	shape  policy.Shape
	output bool
}

// schemaCache memoizes projections per (descriptor, shape, dimension).
//
// This is what makes discovery affordable. Projection cost scales with
// DISTINCT SHAPES, not with callers: a thousand principals sharing a
// clearance and compartment set share one projected schema, exactly as they
// already share one compiled redaction plan.
type schemaCache struct {
	mu sync.RWMutex
	m  map[schemaKey]Schema
}

func newSchemaCache() *schemaCache { return &schemaCache{m: map[schemaKey]Schema{}} }

func (c *schemaCache) get(k schemaKey, build func() Schema) Schema {
	c.mu.RLock()
	s, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		return s
	}
	s = build()
	c.mu.Lock()
	// Another goroutine may have built it first. Keep theirs: identical
	// input produces an identical projection, and returning one object per
	// key is what the cache promises.
	if existing, ok := c.m[k]; ok {
		c.mu.Unlock()
		return existing
	}
	c.m[k] = s
	c.mu.Unlock()
	return s
}

// SchemaFor returns the input and output schemas this principal should be
// shown for a tool.
//
// The returned maps are SHARED and must be treated as read-only. Every caller
// of the same shape gets the same object — that is the point of the cache —
// so mutating one corrupts the projection for every principal that shape
// covers. Callers marshal it; nobody edits it.
//
// A tool whose plans cannot be compiled returns an error rather than an
// unprojected schema. Spec §4: a tool that fails to project must be ABSENT,
// never rendered unprojected — the same instinct as step 8, where a response
// with no plan is not returned.
func (c *Core) SchemaFor(t ToolDef, p *Principal) (in, out Schema, err error) {
	if p == nil {
		return nil, nil, fmt.Errorf("toolplane: a principal is required to project a schema")
	}
	if t.Input == nil || t.Output == nil {
		return nil, nil, fmt.Errorf("toolplane: %s: tool has no input or output descriptor", t.FQN)
	}

	inPlan, err := c.PlanFor(t.Input)
	if err != nil {
		return nil, nil, fmt.Errorf("toolplane: %s: input: %w", t.FQN, err)
	}
	outPlan, err := c.PlanFor(t.Output)
	if err != nil {
		return nil, nil, fmt.Errorf("toolplane: %s: output: %w", t.FQN, err)
	}

	shape := p.Shape()
	in = c.schemas.get(
		schemaKey{desc: t.Input, shape: shape, output: false},
		func() Schema { return ProjectInput(inPlan, shape, t.FieldDocs) },
	)
	out = c.schemas.get(
		schemaKey{desc: t.Output, shape: shape, output: true},
		func() Schema { return ProjectOutput(outPlan, shape, t.FieldDocs) },
	)
	return in, out, nil
}

// SchemaFor delegates to the Core, so a surface holding a *Server projects
// through exactly the same cache as one holding a *Core.
func (s *Server) SchemaFor(t ToolDef, p *Principal) (in, out Schema, err error) {
	return s.core.SchemaFor(t, p)
}
