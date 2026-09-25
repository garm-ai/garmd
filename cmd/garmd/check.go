package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/serve"
	"github.com/garm-ai/garmd/internal/toolplane"
)

// `garmd check` answers, in CI, the question a deployment answers at startup:
// would this catalogue mount here?
//
// It is the REAL check rather than an approximation of it — the same Reload,
// the same AddTools, the same serve.Prepare, in the same binary. A CI
// validator that reimplemented the mount rules would drift from them, and the
// drift would show up as a deploy that fails after a green build, which is
// precisely the failure this exists to prevent.
//
// What it does not do is bind a listener, connect to NATS, or authenticate
// anybody. Mounting is decided before any of that.
func newCheckCmd() *cobra.Command {
	var cataloguePath string
	var maxTools int
	var withGrants, withFGA, withNotifier bool
	var auditRetention time.Duration

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check whether a catalogue would mount on a given deployment",
		Long: "check loads a catalogue and builds the governance chain from it, exactly\n" +
			"as `serve` does before binding, then reports what would be served.\n\n" +
			"Mountability is a property of the PAIR — a catalogue and the deployment\n" +
			"it runs on — not of the catalogue alone. A tool declaring an approval\n" +
			"gate mounts where a grant verifier exists and refuses where one does\n" +
			"not, and both are correct. So the flags below say what the target\n" +
			"deployment can do, and the answer is only meaningful against them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, checkOpts{
				catalogue:      cataloguePath,
				maxTools:       maxTools,
				withGrants:     withGrants,
				withFGA:        withFGA,
				withNotifier:   withNotifier,
				auditRetention: auditRetention,
			})
		},
	}
	cmd.Flags().StringVar(&cataloguePath, "catalogue", "", "Path to the catalogue to check")
	cmd.Flags().IntVar(&maxTools, "max-tools", 0,
		"Refuse a catalogue declaring more tools than this. 0 means no limit")
	cmd.Flags().BoolVar(&withGrants, "with-grants", false,
		"The target deployment has a grant verifier (step 5)")
	cmd.Flags().BoolVar(&withFGA, "with-fga", false,
		"The target deployment has an instance-authorization checker (steps 4 and 7)")
	cmd.Flags().BoolVar(&withNotifier, "with-notifier", false,
		"The target deployment has a notifier (step 10)")
	cmd.Flags().DurationVar(&auditRetention, "audit-retention", 0,
		"How long the target deployment's audit sink keeps a record. Zero means "+
			"it has no audit sink at all, not that it keeps records forever — a "+
			"tool declaring LEVEL_AUDIT then refuses")
	return cmd
}

type checkOpts struct {
	catalogue      string
	maxTools       int
	withGrants     bool
	withFGA        bool
	withNotifier   bool
	auditRetention time.Duration
}

func runCheck(cmd *cobra.Command, o checkOpts) error {
	if o.catalogue == "" {
		return fmt.Errorf("--catalogue is required: there is nothing to check without one")
	}

	store := catalogue.NewStore(catalogue.Options{MaxTools: o.maxTools})
	cat, err := store.Reload(cmd.Context(), catalogue.FileSource{Path: o.catalogue})
	if err != nil {
		return err
	}

	h := &serve.Handler{
		Store: store,
		// A key invented here, which `serve` refuses to do and is right to.
		// The difference is what the key is FOR: it salts hash redactions so
		// the same value stays recognisable across rows, and nothing here
		// produces a row. Mounting does not read it. Requiring a real secret
		// to lint a catalogue in CI would be friction with nothing behind it.
		HashKey:  ephemeralHashKey(),
		Recorder: discardRecorder{},
	}
	if o.withGrants {
		h.Grants = assumedGrants{}
	}
	if o.withFGA {
		h.FGA = assumedFGA{}
	}
	if o.withNotifier {
		h.Notifier = assumedNotifier{}
	}
	if o.auditRetention > 0 {
		h.Audit = assumedAudit{retention: o.auditRetention}
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "catalogue %s\n", cat.Digest)
	fmt.Fprintf(out, "  %d tool(s), %d compartment(s), annotation schema v%d\n",
		len(cat.Defs), len(cat.Compartments), cat.SchemaVersion)
	fmt.Fprintf(out, "  against a deployment with: %s\n", describeCapabilities(o))

	if err := h.Prepare(cat); err != nil {
		return fmt.Errorf("this catalogue would NOT mount:\n  %w", err)
	}

	fmt.Fprintf(out, "\nwould mount %d tool(s):\n", len(cat.Defs))
	for _, d := range cat.Defs {
		fmt.Fprintf(out, "  %-44s %s\n", d.FQN, d.Verb)
	}
	return nil
}

func describeCapabilities(o checkOpts) string {
	var have []string
	if o.withGrants {
		have = append(have, "grants")
	}
	if o.withFGA {
		have = append(have, "instance authorization")
	}
	if o.withNotifier {
		have = append(have, "notify")
	}
	if o.auditRetention > 0 {
		have = append(have, fmt.Sprintf("an audit sink keeping %s", o.auditRetention))
	}
	if len(have) == 0 {
		return "none of the optional steps"
	}
	s := have[0]
	for _, h := range have[1:] {
		s += ", " + h
	}
	return s
}

// ephemeralHashKey is 32 random bytes, thrown away when this process exits.
func ephemeralHashKey() []byte {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return b[:]
}

// The stand-ins below exist so `check` can answer "would this mount on a
// deployment that HAS a grant verifier" without having one.
//
// They are named "assumed" rather than "stub" or "noop" deliberately: every
// one of them would be a catastrophe in a serving path — a grant verifier that
// approves everything, an audit sink that discards what it is given — and the
// name should read as a lie the moment it appears anywhere near `serve`. The
// mount check only ever asks whether they are non-nil and, for audit, what
// retention they claim.
type assumedGrants struct{}

func (assumedGrants) Verify(context.Context, *toolplane.Principal, toolplane.ToolDef) error {
	return nil
}

type assumedFGA struct{}

func (assumedFGA) Pre(context.Context, *toolplane.Principal, toolplane.ToolDef, proto.Message) error {
	return nil
}

func (assumedFGA) Post(_ context.Context, _ *toolplane.Principal, _ toolplane.ToolDef, resp proto.Message) (proto.Message, error) {
	return resp, nil
}

type assumedNotifier struct{}

func (assumedNotifier) Notify(context.Context, *toolplane.Principal, toolplane.ToolDef, ledger.Event) {
}

type assumedAudit struct{ retention time.Duration }

func (assumedAudit) Write(context.Context, ledger.Event) error { return nil }
func (a assumedAudit) Retention() time.Duration                { return a.retention }

type discardRecorder struct{}

func (discardRecorder) Record(context.Context, ledger.Event) {}
