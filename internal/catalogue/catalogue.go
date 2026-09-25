package catalogue

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	cataloguev1 "github.com/garm-ai/garm/contracts/garm/catalogue/v1"
	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/garm-ai/garmd/internal/tool"
)

// SchemaVersion is the annotation schema this binary speaks, and MaxBehind is
// how far back it reads: N-2, matching ControlService's existing contract
// policy rather than inventing a second skew rule.
const (
	SchemaVersion = 1
	MaxBehind     = 2
)

// MaxBytes is a ceiling on an artifact, not a budget.
//
// It exists so that a pathological file fails with a sentence instead of an
// OOM kill — a process that dies before it can log anything looks like a
// crashloop with no cause. Deliberately generous: a measured catalogue runs
// about 384 bytes per tool, so this is room for roughly half a million tools,
// far past where the tool budget below should have stopped anyone.
const MaxBytes = 256 << 20

// Catalogue is one generation, immutable once built.
//
// Immutability is what makes reload safe. A request takes the current
// catalogue once at entry and uses that same one for authorization, input
// checking, resolution and sanitisation — so a swap mid-request cannot mix
// descriptors from two generations. Nothing here is written after Load
// returns.
type Catalogue struct {
	// Digest is SHA-256 over the artifact bytes as they were handed over,
	// computed before anything was parsed. With the binary's version it is
	// the pair that answers "which tools is this process serving".
	Digest string

	SchemaVersion uint32
	Files         *protoregistry.Files
	Defs          []tool.Def

	Compartments []*toolv1.Decl
	ToolSets     []*toolv1.Decl
	FieldDocs    map[string]string

	// DescriptorHashes is the wire shape each proto package declares, keyed
	// by package. A service advertises the same digest; a mismatch means it
	// implements a different contract from the one this catalogue governs.
	DescriptorHashes map[string]string
	Provenance       *cataloguev1.Provenance

	// Bytes is the artifact's size.
	//
	// HeapBytes is what this generation retains, measured rather than
	// estimated from a per-tool constant — that constant came from synthetic
	// protos and nobody deploys those. Set by the Store after Load returns,
	// because measuring inside Load counts the descriptor set it parsed from,
	// which is dead by the time anyone cares.
	Bytes     int
	HeapBytes uint64

	LoadedAt time.Time
}

// Load parses and validates an artifact. It either returns a usable catalogue
// or an error; there is no partially-loaded state.
//
// Every failure here is closed. Serving the part of a policy document one
// understands fails open by construction, and the annotations a binary cannot
// parse are disproportionately the NEW ones — which are the ones that
// restrict.
func Load(body []byte, now func() time.Time) (*Catalogue, error) {
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("catalogue is %d bytes; the ceiling is %d. This is a "+
			"guard against a pathological artifact, not a budget — if it is genuinely "+
			"this large, the catalogue is serving more than one deployment should",
			len(body), MaxBytes)
	}

	// Digest first, over the bytes as given. Computing it after parsing would
	// record what this binary understood rather than what it was handed.
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	msg := &cataloguev1.Catalogue{}
	if err := proto.Unmarshal(body, msg); err != nil {
		return nil, fmt.Errorf("catalogue %s is not a catalogue: %w", digest, err)
	}

	if err := checkSchema(msg.GetAnnotationSchemaVersion(), digest); err != nil {
		return nil, err
	}

	files, err := protodesc.NewFiles(msg.GetFiles())
	if err != nil {
		// A descriptor set was meant to be self-contained. An unresolved
		// import means it is not, and resolving one at boot would mean
		// reaching somewhere this process deliberately cannot reach.
		return nil, fmt.Errorf("catalogue %s does not resolve: %w", digest, err)
	}

	defs := buildDefs(files)
	if err := assignClientNames(defs); err != nil {
		return nil, fmt.Errorf("catalogue %s: %w", digest, err)
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("catalogue %s declares no tools; a process serving "+
			"nothing is never what anyone meant", digest)
	}

	return &Catalogue{
		Digest:           digest,
		Bytes:            len(body),
		SchemaVersion:    msg.GetAnnotationSchemaVersion(),
		Files:            files,
		Defs:             defs,
		Compartments:     msg.GetCompartments(),
		ToolSets:         msg.GetToolSets(),
		FieldDocs:        msg.GetFieldDocs(),
		DescriptorHashes: msg.GetDescriptorHashes(),
		Provenance:       msg.GetProvenance(),
		LoadedAt:         now(),
	}, nil
}

// HeapInUse is the live heap after a collection. Exported so the Store can
// measure across a load from outside it.
func HeapInUse() uint64 { return heapInUse() }

func heapInUse() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// heapDelta is what the load added. Reported as zero rather than as a
// negative if the collector freed more than the load allocated, which happens
// and is not worth explaining in a startup line.
func heapDelta(before uint64) uint64 {
	after := heapInUse()
	if after < before {
		return 0
	}
	return after - before
}

// checkSchema enforces the N-2 window.
//
// Scoped to garm.tool.v1 and nothing else. A catalogue may carry declarations
// annotated in other namespaces — an agent runner's, for instance — and this
// process ignores them entirely. Widening the check to every extension
// namespace would refuse such a catalogue at boot, which is knowledge of
// agents acquired through an error message.
func checkSchema(got uint32, digest string) error {
	if got > SchemaVersion {
		return fmt.Errorf("catalogue %s uses annotation schema v%d; this build reads "+
			"v%d at most. Upgrade garmd before adopting it", digest, got, SchemaVersion)
	}
	// v1 is the first schema there is, so the window floor cannot go below it
	// however wide MaxBehind is.
	oldest := SchemaVersion - MaxBehind
	if oldest < 1 {
		oldest = 1
	}
	if got < uint32(oldest) {
		return fmt.Errorf("catalogue %s uses annotation schema v%d; this build reads "+
			"v%d and back to v%d. Rebuild it", digest, got, SchemaVersion, oldest)
	}
	return nil
}

// buildDefs projects every annotated method into a Def.
//
// This is what the generated registry used to do at build time, done at boot
// from descriptors instead — which is the whole reason a tool can be added
// without releasing this binary.
func buildDefs(files *protoregistry.Files) []tool.Def {
	var defs []tool.Def
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			ms := svc.Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				p, _ := proto.GetExtension(m.Options(), toolv1.E_Tool).(*toolv1.ToolPolicy)
				if p == nil || p.GetExclude() {
					continue
				}
				defs = append(defs, defFor(fd, svc, m, p))
			}
		}
		return true
	})
	// RangeFiles does not promise an order, and a catalogue that lists its
	// tools differently on each boot makes every diff and every log useless.
	sort.Slice(defs, func(i, j int) bool { return defs[i].FQN < defs[j].FQN })
	return defs
}

func defFor(fd protoreflect.FileDescriptor, svc protoreflect.ServiceDescriptor,
	m protoreflect.MethodDescriptor, p *toolv1.ToolPolicy) tool.Def {

	name := p.GetName()
	if name == "" {
		name = snake(string(m.Name()))
	}
	return tool.Def{
		FullMethod:   fmt.Sprintf("/%s/%s", svc.FullName(), m.Name()),
		FQN:          fmt.Sprintf("%s.%s", fd.Package(), name),
		Name:         name,
		Title:        p.GetTitle(),
		Description:  p.GetDescription(),
		Verb:         p.GetVerb(),
		MinClearance: p.GetMinClearance(),
		Compartments: p.GetCompartments(),
		Sets:         p.GetSets(),
		Input:        m.Input(),
		Output:       m.Output(),

		ApprovalMode:     p.GetApproval().GetMode(),
		AuditLevel:       p.GetAudit().GetLevel(),
		HasAuthorization: p.GetAuthorization() != nil,

		Idempotent:    p.GetEffects().GetIdempotent(),
		Reversibility: p.GetEffects().GetReversibility(),
		External:      p.GetEffects().GetExternal(),

		WhenNotToUse: p.GetGuidance().GetWhenNotToUse(),
		OnError:      p.GetGuidance().GetOnError(),
	}
}

// assignClientNames decides what a caller sees for each tool.
//
// A short name that is unique in this catalogue is used as it stands, because
// `get_balance` is easier for a model to reason about than
// `acme_accounts_v1_get_balance`. Where two tools share one, BOTH get the
// flattened package prefix — prefixing only the newcomer would make a tool's
// name depend on which package was read first.
//
// Determinism is the property that makes this safe rather than clever. Two
// replicas loading the same catalogue must agree, or a call routes differently
// depending on which one answers. The catalogue is byte-identical by
// construction and this function reads nothing else, so they do.
//
// This is a LABEL. Identity is the FQN: manifests pin by it and the ledger
// records it, so the same tool may be shown under different names in two
// catalogues without anything downstream noticing.
func assignClientNames(defs []tool.Def) error {
	counts := map[string]int{}
	for _, d := range defs {
		counts[d.Name]++
	}
	for i := range defs {
		if counts[defs[i].Name] == 1 {
			defs[i].ClientName = defs[i].Name
			continue
		}
		pkg := strings.TrimSuffix(defs[i].FQN, "."+defs[i].Name)
		defs[i].ClientName = strings.ReplaceAll(pkg, ".", "_") + "_" + defs[i].Name
	}

	// Prefixing is not injective: proto package segments may contain
	// underscores, so `a.b.c` and `a_b.c` flatten alike. Vanishingly rare and
	// catastrophic if unnoticed — a caller would reach whichever tool the
	// dispatcher found first — so it fails the load rather than the request.
	seen := map[string]string{}
	for _, d := range defs {
		if prev, dup := seen[d.ClientName]; dup {
			return fmt.Errorf("tools %s and %s both present as %q to a caller; "+
				"rename one, or rename a proto package so the two do not flatten alike",
				prev, d.FQN, d.ClientName)
		}
		seen[d.ClientName] = d.FQN
	}
	return nil
}

// snake is the default tool name when a declaration does not give one. It
// mirrors the generator's own derivation, because a tool that is named one
// thing at build time and another at load time is worse than either.
func snake(s string) string {
	var out []rune
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				out = append(out, '_')
			}
			r += 'a' - 'A'
		}
		out = append(out, r)
	}
	return string(out)
}
