// Command garmd is the garm daemon: a policy-enforcing proxy between an agent
// and the tools it may call.
//
// It is not the command line tool. That is garm, in a separate repository, and
// nothing here depends on it beyond the contract language they share.
//
// This file is flags and the signal context, and nothing else: the daemon
// itself is garmd.Serve, in the root package, which garm-ai/stack's garmstack
// runs too. There is one implementation, not one per caller.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/garm-ai/garmd"
)

func main() {
	// SIGTERM shuts the listener down gracefully: in-flight calls finish, new
	// ones are refused. A tool call cut off mid-flight is a call whose effect
	// the caller cannot determine. Serve drains on a cancelled context and on
	// nothing else, so this is the only shutdown path there is.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "garmd",
		Short: "The governed tool plane",
		Long: "garmd stands between an agent and the tools it may call, and decides\n" +
			"on every call what passes and what the caller is allowed to see of\n" +
			"the answer.\n\n" +
			"It serves the tools a catalogue declares, not the tools it was built\n" +
			"with. Adding a tool is a catalogue rebuild and a restart.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.AddCommand(newVersionCmd(), newServeCmd(), newCheckCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), garmd.Version())
			return nil
		},
	}
}

func newServeCmd() *cobra.Command {
	var cataloguePath, natsURL, listen string
	var cataloguePoll time.Duration
	var audience, hashKeyFile string
	var jwksURLs, issuers []string
	var grantIssuer, grantJWKSURL, grantAudienceName string
	var maxTools int
	var auditRetention time.Duration
	var ledgerStream bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the tool plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return garmd.Serve(cmd.Context(), garmd.Config{
				Catalogue:     cataloguePath,
				CataloguePoll: cataloguePoll,

				NATS:        natsURL,
				Listen:      listen,
				MaxTools:    maxTools,
				JWKSURLs:    jwksURLs,
				Issuers:     issuers,
				Audience:    audience,
				HashKeyFile: hashKeyFile,

				GrantIssuer:   grantIssuer,
				GrantJWKS:     grantJWKSURL,
				GrantAudience: grantAudienceName,
				// The FLAG being set is what turns the audit stream on, not
				// its value: zero is a meaningful retention (indefinite, per
				// the Sink contract) and the strongest claim available, so it
				// cannot double as "unconfigured". Unconfigured leaves the
				// Sink nil, and a catalogue with an audited tool then refuses
				// to start — which is correct.
				Audit:          cmd.Flags().Changed("audit-stream-retention"),
				AuditRetention: auditRetention,
				LedgerStream:   ledgerStream,

				// The startup report and the running log go where cobra was
				// told to put them, so `garmd serve > report` still works and
				// a test can read both back.
				Out: cmd.OutOrStdout(),
				Log: slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)),
			})
		},
	}
	cmd.Flags().StringVar(&cataloguePath, "catalogue", "",
		"The catalogue artifact this process serves: a path, or s3://bucket/key for "+
			"an object store. An object is re-read when it changes, a file is not — "+
			"a file is placed by whoever deployed this binary and does not change "+
			"underneath it")
	cmd.Flags().DurationVar(&cataloguePoll, "catalogue-poll", 30*time.Second,
		"How often to check an s3:// catalogue for a change, by ETag. Ignored for a "+
			"file, and 0 turns it off — this process then serves the generation it "+
			"booted with until a restart. Matches the reconciler's cadence: there is "+
			"no notification, and a shorter interval only asks the object store more "+
			"often")
	cmd.Flags().StringVar(&natsURL, "nats", nats.DefaultURL,
		"NATS server the tool services are reachable on")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:7440",
		"Address for the agent-facing tool plane. Loopback by default: a plane "+
			"nobody can reach is an outage someone notices in minutes, and one "+
			"exposed to the cluster is a breach nobody notices at all")
	cmd.Flags().IntVar(&maxTools, "max-tools", 0,
		"Refuse a catalogue declaring more tools than this. 0 means no limit; "+
			"set it to catch a deployment pointed at the wrong catalogue")
	cmd.Flags().StringArrayVar(&jwksURLs, "jwks", nil,
		"JWKS endpoint whose keys sign the tokens this plane accepts. Required, and "+
			"REPEATABLE: give it once per --issuer, in the same order. A plane that "+
			"cannot identify its callers can make only one honest decision, and it is "+
			"not to serve them")
	cmd.Flags().StringArrayVar(&issuers, "issuer", nil,
		"Issuer this plane trusts, paired with the --jwks at the same position. "+
			"Repeatable: the governed door verifies a human's token from an IdP and a "+
			"runner's from the STS in one process, and one key set for both would let "+
			"either sign for the other. Separate from --jwks on purpose: trusting "+
			"whatever iss a fetched key set happens to sign means trusting whoever can "+
			"answer that URL")
	cmd.Flags().StringVar(&audience, "audience", "garm",
		"Audience minted tokens must name. A token for another service must not "+
			"be spendable here")
	cmd.Flags().DurationVar(&auditRetention, "audit-stream-retention", 0,
		"How long the audit pipeline keeps a record, and publish the audit stream to "+
			"JetStream on --nats. This is an ASSERTION about the object store behind "+
			"the forwarder, which garmd cannot read: the mount check refuses a tool "+
			"asking for longer, so a value longer than the truth makes that check pass "+
			"against a promise that is false. 0 means indefinite. Unset means no audit "+
			"stream at all, and a catalogue declaring an audited tool will not start")
	cmd.Flags().BoolVar(&ledgerStream, "ledger-stream", false,
		"Publish the ledger to JetStream on --nats, in batches, falling back to stdout "+
			"for anything that cannot be published. Off by default: without it every "+
			"row is a log line a rotation deletes")
	cmd.Flags().StringVar(&hashKeyFile, "hash-key-file", "",
		"File holding the key for hash redactions. Required, and it must be the "+
			"SAME key on every replica and across restarts: a key that changes "+
			"means the same value hashes two ways, so the correlation those "+
			"redactions exist to preserve stops working silently")
	cmd.Flags().StringVar(&grantIssuer, "grant-issuer", "",
		"Issuer whose approval grants this plane accepts. Setting it TURNS ON step 5: "+
			"without it a catalogue declaring a MODE_GRANT tool will not mount, which "+
			"is the correct refusal — an approval-gated tool served with no verifier "+
			"is an approval nobody gave")
	cmd.Flags().StringVar(&grantJWKSURL, "grant-jwks", "",
		"JWKS endpoint whose keys sign approval grants. Defaults to --jwks when that is "+
			"given exactly once, because an STS that issues both tokens and approvals is "+
			"the ordinary deployment and typing the same URL twice is how the two end up "+
			"disagreeing. REQUIRED once --jwks is repeated: there is then no unambiguous "+
			"default, and taking the first would verify approvals against a key set that "+
			"may not be the grant issuer's")
	cmd.Flags().StringVar(&grantAudienceName, "grant-audience", "",
		"Audience an approval grant must name. Defaults to --audience. A grant minted "+
			"for another deployment is a VALID grant, and this is the only thing that "+
			"stops it being spent here")
	return cmd
}
