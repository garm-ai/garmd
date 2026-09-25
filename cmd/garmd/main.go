// Command garmd is the garm daemon: a policy-enforcing proxy between an agent
// and the tools it may call.
//
// It is not the command line tool. That is garm, in a separate repository, and
// nothing here depends on it beyond the contract language they share.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/garm-ai/garm/policy"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	"github.com/garm-ai/garmd/internal/serve"
	garmnats "github.com/garm-ai/garmd/internal/transport/nats"
)

func main() {
	if err := newRoot().Execute(); err != nil {
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
	root.AddCommand(newVersionCmd(), newServeCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version())
			return nil
		},
	}
}

// version reports the module version the Go toolchain stamped: a tag for an
// installed build, "(devel)" from a working tree.
//
// Once a catalogue can be loaded this stops being the whole answer. Identity
// is the pair (binary version, catalogue digest), and a garmd that reports
// only half of it cannot answer which tools it is serving.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "dev"
	}
	return info.Main.Version
}

// bytesHuman keeps a startup line readable. Binary units, because the numbers
// it prints are memory and file sizes rather than anything a disk vendor
// measured.
func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func newServeCmd() *cobra.Command {
	var cataloguePath, natsURL, listen string
	var jwksURL, issuer, audience, hashKeyFile string
	var maxTools int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the tool plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, serveOpts{
				catalogue: cataloguePath,
				natsURL:   natsURL,
				listen:    listen,
				maxTools:  maxTools,
				jwksURL:   jwksURL,
				issuer:    issuer,
				audience:  audience,
				hashKey:   hashKeyFile,
			})
		},
	}
	cmd.Flags().StringVar(&cataloguePath, "catalogue", "",
		"Path to the catalogue artifact this process serves")
	cmd.Flags().StringVar(&natsURL, "nats", nats.DefaultURL,
		"NATS server the tool services are reachable on")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:7440",
		"Address for the agent-facing tool plane. Loopback by default: a plane "+
			"nobody can reach is an outage someone notices in minutes, and one "+
			"exposed to the cluster is a breach nobody notices at all")
	cmd.Flags().IntVar(&maxTools, "max-tools", 0,
		"Refuse a catalogue declaring more tools than this. 0 means no limit; "+
			"set it to catch a deployment pointed at the wrong catalogue")
	cmd.Flags().StringVar(&jwksURL, "jwks", "",
		"JWKS endpoint whose keys sign the tokens this plane accepts. Required: "+
			"a plane that cannot identify its callers can make only one honest "+
			"decision, and it is not to serve them")
	cmd.Flags().StringVar(&issuer, "issuer", "",
		"Issuer this plane trusts. Required, and separate from --jwks on purpose: "+
			"trusting whatever iss a fetched key set happens to sign means trusting "+
			"whoever can answer that URL")
	cmd.Flags().StringVar(&audience, "audience", "garm",
		"Audience minted tokens must name. A token for another service must not "+
			"be spendable here")
	cmd.Flags().StringVar(&hashKeyFile, "hash-key-file", "",
		"File holding the key for hash redactions. Required, and it must be the "+
			"SAME key on every replica and across restarts: a key that changes "+
			"means the same value hashes two ways, so the correlation those "+
			"redactions exist to preserve stops working silently")
	return cmd
}

type serveOpts struct {
	catalogue string
	natsURL   string
	listen    string
	maxTools  int
	jwksURL   string
	issuer    string
	audience  string
	hashKey   string
}

func runServe(cmd *cobra.Command, o serveOpts) error {
	path := o.catalogue
	maxTools := o.maxTools
	// A tool plane with no catalogue serves nothing. Saying so is better than
	// binding a listener that answers 404 — that is the failure nothing
	// downstream can detect.
	if path == "" {
		return fmt.Errorf("--catalogue is required: garmd serves the tools an artifact " +
			"declares, and will not bind a listener it has nothing to serve on")
	}

	// Identity and the redaction key are refused up front, before anything is
	// loaded or bound.
	//
	// There is no anonymous mode and no --insecure. Every such switch that
	// has ever existed has ended up on in production, and the failure is
	// silent: the plane serves, the tools answer, and every call is
	// authorised as nobody. Running locally is not a reason to relax it —
	// `garmdev idp` from github.com/garm-ai/devkit mints tokens against a
	// real key set for exactly this.
	if o.jwksURL == "" || o.issuer == "" {
		return fmt.Errorf("--jwks and --issuer are both required: garmd decides what a " +
			"caller may do, which it cannot do without knowing who they are.\n" +
			"For a laptop: `go run github.com/garm-ai/devkit/cmd/garmdev idp` then\n" +
			"  --jwks http://127.0.0.1:7450/.well-known/jwks.json \\\n" +
			"  --issuer https://garmdev.invalid/idp")
	}
	hashKey, err := readHashKey(o.hashKey)
	if err != nil {
		return err
	}

	store := catalogue.NewStore(catalogue.Options{MaxTools: maxTools})
	cat, err := store.Reload(cmd.Context(), catalogue.FileSource{Path: path})
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	// Identity is the PAIR. A build number alone stopped answering "which
	// tools is this process serving" the moment the catalogue left the binary.
	fmt.Fprintf(out, "garmd %s\n", version())
	fmt.Fprintf(out, "catalogue %s\n", cat.Digest)
	if p := cat.Provenance; p != nil {
		fmt.Fprintf(out, "  built by %s (%s)\n", p.GetProducer(), p.GetCompiler())
	}
	fmt.Fprintf(out, "  annotation schema v%d, %d compartment(s), %d tool set(s)\n",
		cat.SchemaVersion, len(cat.Compartments), len(cat.ToolSets))

	// The size line is always printed, limit or not. What it guards against
	// is a deployment pointed at the organisation-wide catalogue rather than
	// its own, and an operator who never sets a limit should still be able to
	// see that happen.
	budget := "no limit set"
	if m := store.MaxTools(); m > 0 {
		budget = fmt.Sprintf("limit %d", m)
	}
	fmt.Fprintf(out, "  %s, %s held, %d tool(s), %s\n",
		bytesHuman(int64(cat.Bytes)), bytesHuman(int64(cat.HeapBytes)), len(cat.Defs), budget)

	fmt.Fprintf(out, "%d tool(s) declared:\n", len(cat.Defs))
	for _, d := range cat.Defs {
		shown := ""
		if d.ClientName != d.Name {
			// Worth saying out loud: a name differing from its declaration is
			// the sort of thing an operator should learn at startup rather
			// than from a confused caller.
			shown = fmt.Sprintf("  (callers see %s)", d.ClientName)
		}
		fmt.Fprintf(out, "  %-44s %s%s\n", d.FQN, d.Verb, shown)
	}

	nc, err := nats.Connect(o.natsURL,
		nats.Name("garmd"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return fmt.Errorf("connecting to nats at %s: %w", o.natsURL, err)
	}
	defer nc.Close()

	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
	tp := garmnats.New(nc)

	// The compartments a token may assert come from the CATALOGUE, not from
	// this binary: an enterprise defines its own taxonomy and ships it in the
	// artifact. A name the catalogue does not declare is dropped from the
	// principal rather than refused, so an IdP-side typo costs access and not
	// availability — the surface logs the drop, because dropping authority
	// silently is how a typo becomes an unexplained denial nobody can trace.
	//
	// Built once, from the boot catalogue. See KNOWN-GAPS.md: a reload that
	// adds a compartment does not reach this registry until a restart.
	reg, err := policy.NewRegistry(cat.Compartments)
	if err != nil {
		return fmt.Errorf("the catalogue's compartment declarations: %w", err)
	}

	// Reconciliation is not optional in a deployment. Without it, a service
	// built from a different contract answers anyway — protobuf ignores
	// unknown fields and defaults absent ones — and the call is authorised,
	// sanitised and ledgered as a success while reading fields as something
	// else.
	rec := &serve.Reconciler{Store: store, Discoverer: tp, Log: log}

	// Step 1. The verifier fetches the key set lazily and caches it, so a
	// slow or absent IdP at boot costs the first call rather than the
	// process.
	verifier := authn.NewVerifier(authn.Config{
		KeySet:       authn.NewKeySet(authn.KeySetConfig{URL: o.jwksURL}),
		Issuers:      []string{o.issuer},
		Audience:     o.audience,
		Compartments: reg,
	})

	h := &serve.Handler{
		Store:      store,
		Invoker:    tp,
		Log:        log,
		Reconciler: rec,
		Principals: authn.PrincipalFunc(verifier, log),
		HashKey:    hashKey,
		// slog for now. A bank needs this durable and tamper-evident, and
		// KNOWN-GAPS.md says so rather than this line pretending otherwise.
		Recorder: record.NewSlog(log),
	}

	// Before the listener. A catalogue declaring supervision this deployment
	// cannot apply must stop the process, not each request: the schema author
	// was forced into the declaration, so the only outcomes left are a
	// refusal here and a tool running with none of the supervision it claims.
	if err := h.Prepare(cat); err != nil {
		return fmt.Errorf("this catalogue cannot be served: %w", err)
	}

	srv := &http.Server{
		Addr: o.listen,
		// The middleware only LIFTS the bearer token into the context; it
		// never verifies it. Verification is step 1, inside the chain's
		// reach, so a bad token is refused with a ledger row rather than by a
		// 401 the ledger never sees.
		Handler:           authn.Middleware(h),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SIGTERM shuts the listener down gracefully: in-flight calls finish, new
	// ones are refused. A tool call cut off mid-flight is a call whose effect
	// the caller cannot determine.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go rec.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	fmt.Fprintf(out, "listening on %s, routing over %s\n", o.listen, nc.ConnectedUrl())
	fmt.Fprintf(out, "  callers verified against %s (issuer %s, audience %s)\n",
		o.jwksURL, o.issuer, o.audience)
	fmt.Fprintf(out, "\n"+
		"  Every call goes through the chain. Steps 1, 2, 3, 8 and 9 are\n"+
		"  implemented; instance authorization, grants and notify are NOT, and a\n"+
		"  tool declaring them is mounted as though it had not. See KNOWN-GAPS.md\n"+
		"  before putting this in front of anything that matters.\n\n")

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	fmt.Fprintln(out, "stopped")
	return nil
}

// readHashKey loads the key that keys hash redactions.
//
// From a FILE rather than a flag, because a flag value is visible in `ps`, in
// shell history, and in whatever logs the orchestrator keeps of the command
// line it ran. A file is what a secret manager mounts.
//
// There is no generated fallback. A random key per boot would work and hide
// the problem: hashes would differ between replicas and across restarts, so
// the correlation these redactions exist to preserve would stop working with
// nothing to see. Better to refuse than to silently do the useless thing.
func readHashKey(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("--hash-key-file is required: hash redactions replace a " +
			"value with a keyed digest so the same value stays recognisable across " +
			"rows, and a key this process invented would make that false without " +
			"anything failing")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the hash key: %w", err)
	}
	key = bytes.TrimSpace(key)
	// 16 bytes is the floor, not a recommendation. Short keys are guessable,
	// and a guessable key makes a hash redaction reversible by anyone willing
	// to try the values they already suspect — which for identifiers is all
	// of them.
	if len(key) < 16 {
		return nil, fmt.Errorf("the hash key in %s is %d bytes; at least 16 are needed, "+
			"or the digests it produces can be reversed by guessing the input",
			path, len(key))
	}
	return key, nil
}
