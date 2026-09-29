// Package garmd is the governed tool plane: the catalogue, the chain, the
// listener and the drain that cmd/garmd used to hold inline.
//
// The binary is the way you run this daemon. Serve exists so that
// garm-ai/stack's garmstack can run garmd, the STS, agentd and the dev IdP as
// goroutines in a single process for local development and demonstration —
// each still speaking NATS and HTTP to the others. That single-process mode
// is never for production, because one process holding agentd's client key,
// the STS's signing key and this daemon's verifier configuration is one
// compromise away from all three.
//
// This is the first package here outside internal/, and the reason is the one
// CLAUDE.md names: somebody asked. There is exactly one implementation —
// cmd/garmd parses flags into a Config and calls Serve, and so does garmstack.
package garmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"

	"github.com/garm-ai/garm/contracts/audit"
	"github.com/garm-ai/garm/contracts/ledger"
	"github.com/garm-ai/garm/contracts/wire"
	"github.com/garm-ai/garm/policy"
	auditjs "github.com/garm-ai/garmd/internal/audit/jetstream"
	"github.com/garm-ai/garmd/internal/authn"
	"github.com/garm-ai/garmd/internal/catalogue"
	"github.com/garm-ai/garmd/internal/record"
	recordjs "github.com/garm-ai/garmd/internal/record/jetstream"
	"github.com/garm-ai/garmd/internal/reload"
	"github.com/garm-ai/garmd/internal/serve"
	garmnats "github.com/garm-ai/garmd/internal/transport/nats"
)

// Version reports the module version the Go toolchain stamped: a tag for an
// installed build, "(devel)" from a working tree.
//
// Once a catalogue can be loaded this stops being the whole answer. Identity
// is the pair (binary version, catalogue digest), and a garmd that reports
// only half of it cannot answer which tools it is serving.
func Version() string {
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

// Config is every knob `garmd serve` has, as values: one field per flag
// cmd/garmd binds. Nothing here is parsed, looked up in the environment or
// read from a command line inside Serve.
type Config struct {
	Catalogue string
	// CataloguePoll is how often an s3:// catalogue's ETag is checked. It
	// does nothing for a file.
	CataloguePoll time.Duration

	NATS     string
	Listen   string
	MaxTools int
	// Paired by position: JWKSURLs[i] is the key set for Issuers[i]. Two
	// slices rather than one slice of pairs because they arrive as two flags,
	// and trustedIssuers is the single place that turns them into pairs.
	JWKSURLs []string
	Issuers  []string
	Audience string
	// HashKeyFile is the file holding the key for hash redactions, not the
	// key: see readHashKey for why it is never a value on a command line.
	HashKeyFile string

	GrantIssuer   string
	GrantJWKS     string
	GrantAudience string

	// Audit says the audit stream was CONFIGURED, which is not the same as
	// AuditRetention being non-zero: zero is a meaningful retention
	// (indefinite) and so cannot double as "unconfigured".
	Audit          bool
	AuditRetention time.Duration
	LedgerStream   bool

	// Out is where the startup report is written — what this process is,
	// what it will serve and what it will refuse. nil means os.Stdout.
	Out io.Writer

	// Log is where this daemon logs while it runs. nil means a text handler
	// on stderr.
	Log *slog.Logger
}

// out is cfg.Out, or stdout.
func (c Config) out() io.Writer {
	if c.Out != nil {
		return c.Out
	}
	return os.Stdout
}

// logger is cfg.Log, or a text handler on stderr.
func (c Config) logger() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// Serve loads the catalogue, binds the tool plane and runs every call
// through the chain until ctx is cancelled, then drains and returns nil.
//
// Cancelling ctx is the only shutdown path: cmd/garmd turns SIGINT and
// SIGTERM into a cancelled context, so a signal and a cancellation drain
// through this same code rather than through two that can drift apart. A
// tool call cut off mid-flight is a call whose effect the caller cannot
// determine, so in-flight calls finish and new ones are refused.
func Serve(ctx context.Context, cfg Config) error {
	path := cfg.Catalogue
	maxTools := cfg.MaxTools
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
	trusted, err := trustedIssuers(cfg.Issuers, cfg.JWKSURLs)
	if err != nil {
		return err
	}
	hashKey, err := readHashKey(cfg.HashKeyFile)
	if err != nil {
		return err
	}

	// A path or an object, decided once. The object is returned twice over —
	// the same value boots this process and is the one the poller watches —
	// because two constructions could disagree about the key, and a process
	// serving one artifact while polling another would reload on a change to a
	// document it is not serving.
	src, object, err := catalogueSource(ctx, path)
	if err != nil {
		return err
	}
	store := catalogue.NewStore(catalogue.Options{MaxTools: maxTools})
	cat, err := store.Reload(ctx, src)
	if err != nil {
		return err
	}

	out := cfg.out()
	// Identity is the PAIR. A build number alone stopped answering "which
	// tools is this process serving" the moment the catalogue left the binary.
	fmt.Fprintf(out, "garmd %s\n", Version())
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

	nc, err := nats.Connect(cfg.NATS,
		nats.Name("garmd"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return fmt.Errorf("connecting to nats at %s: %w", cfg.NATS, err)
	}
	defer nc.Close()

	log := cfg.logger()
	tp := garmnats.New(nc)

	// Step 5, before the listener. A replay cache that cannot be opened, or one
	// that forgets faster than the catalogue's longest approval, is a
	// misconfiguration that must stop this process rather than be discovered
	// by whoever replays a grant.
	grantsFor, coversGrants, err := grantVerifier(ctx, nc, cat, cfg)
	if err != nil {
		return err
	}

	// Where the two halves of the record go. They share a connection and
	// nothing else: the ledger batches and degrades, the audit stream writes
	// one message per call and may refuse one. See KNOWN-GAPS.md.
	recorder, auditSink, closeRecord, err := records(ctx, nc, log, cfg)
	if err != nil {
		return err
	}
	defer closeRecord()

	// The compartments a token may assert come from the CATALOGUE, not from
	// this binary: an enterprise defines its own taxonomy and ships it in the
	// artifact. A name the catalogue does not declare is dropped from the
	// principal rather than refused, so an IdP-side typo costs access and not
	// availability — the surface logs the drop, because dropping authority
	// silently is how a typo becomes an unexplained denial nobody can trace.
	//
	// Built from the boot catalogue and held behind a swappable pointer, so
	// the taxonomy is replaced without a restart: the poller below calls Set
	// in the same operation as the swap, and only on a generation that became
	// current.
	//
	// What already follows the catalogue is the taxonomy each REQUEST folds
	// against: the surface pins the current plane's registry on the request
	// (authn.WithRegistry), which outranks this one. That is not tidiness —
	// a compartment set is a bitset numbered over a whole generation, so a
	// fold and the chain that judges it must be on the same generation or the
	// caller holds compartments nobody granted.
	reg, err := policy.NewRegistry(cat.Compartments)
	if err != nil {
		return fmt.Errorf("the catalogue's compartment declarations: %w", err)
	}
	compartments := authn.NewSwappable(reg)

	// Reconciliation is not optional in a deployment. Without it, a service
	// built from a different contract answers anyway — protobuf ignores
	// unknown fields and defaults absent ones — and the call is authorised,
	// sanitised and ledgered as a success while reading fields as something
	// else.
	rec := &serve.Reconciler{Store: store, Discoverer: tp, Log: log}

	// Step 1. Each key set is fetched lazily and cached, so a slow or absent
	// IdP at boot costs the first call from THAT issuer rather than the
	// process — and a second issuer being down does not stop the first one's
	// callers.
	verifier := authn.NewVerifier(authn.Config{
		Trusted:           trusted,
		Audience:          cfg.Audience,
		CompartmentSource: compartments,
	})

	h := &serve.Handler{
		Store:      store,
		Invoker:    tp,
		Log:        log,
		Reconciler: rec,
		Principals: authn.PrincipalFunc(verifier, log),
		HashKey:    hashKey,
		Recorder:   recorder,
		// Nil unless --audit-stream-retention was given, and nil is safe
		// rather than merely untidy: Prepare refuses to mount any tool
		// declaring an audit stream, so a catalogue that needs one stops the
		// process at startup instead of being served unaudited.
		Audit: auditSink,
		// Nil unless --grant-issuer was given, and nil is the configured
		// answer: Prepare refuses to mount any MODE_GRANT tool without one, so
		// a deployment that forgot the flag stops at startup instead of
		// serving an approval-gated tool unapproved.
		Grants: grantsFor,
	}

	// Ask each issuer what it actually mints, before binding.
	//
	// An issuer minting `garm://garmd` against a daemon defaulting to `garm`
	// refuses every token at runtime, correctly, with a message about the
	// token rather than the configuration. This turns that into a startup
	// error naming both sides. An issuer that publishes nothing — the dev IdP,
	// a stock enterprise IdP — is unchecked rather than refused.
	//
	// Every issuer, not the first: the one that is misconfigured is exactly
	// the one nobody checked.
	for _, t := range trusted {
		if err := authn.CheckIssuerMetadata(ctx, t.JWKS, t.Issuer, cfg.Audience); err != nil {
			return err
		}
	}

	// Before the listener. A catalogue declaring supervision this deployment
	// cannot apply must stop the process, not each request: the schema author
	// was forced into the declaration, so the only outcomes left are a
	// refusal here and a tool running with none of the supervision it claims.
	if err := h.Prepare(cat); err != nil {
		return fmt.Errorf("this catalogue cannot be served: %w", err)
	}

	srv := &http.Server{
		Addr: cfg.Listen,
		// The middleware only LIFTS the bearer token into the context; it
		// never verifies it. Verification is step 1, inside the chain's
		// reach, so a bad token is refused with a ledger row rather than by a
		// 401 the ledger never sees.
		Handler:           authn.Middleware(h),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go rec.Run(ctx)

	// Only for an object store, and only with an interval. A file catalogue is
	// placed by whoever deployed this binary and does not change underneath
	// it; --catalogue-poll at zero is an operator saying they want the
	// generation this process booted with and no other.
	if object != nil && cfg.CataloguePoll > 0 {
		poller := &reload.Poller{
			Source: object,
			Store:  store,
			// The same handler and the same swappable taxonomy the surface
			// reads, so a swap replaces the chain and the taxonomy together.
			Handler:      h,
			Compartments: compartments,
			// Nil unless step 5 is configured, and nil is right: with no
			// verifier a MODE_GRANT generation is refused by the mount check
			// anyway, and there is no bucket for a ceiling to outlast.
			Admit:    coversGrants,
			Log:      log,
			Interval: cfg.CataloguePoll,
		}
		go poller.Run(ctx)
	}
	// Closed once every in-flight call has finished. The buffered ledger is
	// flushed AFTER that, because a call still running is a row not yet
	// recorded, and flushing first would drop precisely the rows the
	// shutdown produced.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	fmt.Fprintf(out, "listening on %s, routing over %s\n", cfg.Listen, nc.ConnectedUrl())
	// One line per issuer. An operator reading this is checking that the
	// process trusts who they think it trusts, and a summary count would hide
	// exactly the pairing that is wrong.
	for _, t := range trusted {
		fmt.Fprintf(out, "  callers verified against %s (issuer %s, audience %s)\n",
			t.JWKS, t.Issuer, cfg.Audience)
	}
	if cfg.LedgerStream {
		fmt.Fprintf(out, "  ledger batched to %s, falling back to stdout\n", wire.LedgerStream)
	} else {
		fmt.Fprintf(out, "  ledger to stdout only; a log rotation deletes it\n")
	}
	// Said here, with the rest of what this process will do while it runs,
	// because it is the one line that tells an operator the catalogue can
	// change without them: what it refuses matters more than the interval.
	switch {
	case object != nil && cfg.CataloguePoll > 0:
		fmt.Fprintf(out, "  catalogue polled at %s every %s; a generation this "+
			"deployment cannot govern, or whose approvals would outlive the replay "+
			"cache, is refused and the current one keeps serving\n",
			object, cfg.CataloguePoll)
	case object != nil:
		fmt.Fprintf(out, "  catalogue read once from %s and NOT polled "+
			"(--catalogue-poll %s); a changed object is picked up at the next "+
			"restart\n", object, cfg.CataloguePoll)
	default:
		fmt.Fprintf(out, "  catalogue read once from %s; a file does not change "+
			"under a running process, and nothing here watches it\n", src)
	}
	if auditSink != nil {
		fmt.Fprintf(out, "  audit stream %s, retention asserted as %s\n",
			wire.AuditStream, retentionText(auditSink.Retention()))
	} else {
		fmt.Fprintf(out, "  no audit stream; a catalogue declaring an audited tool "+
			"would not have started\n")
	}
	fmt.Fprint(out, chainBanner(grantsFor != nil, cfg.GrantIssuer))

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained
	fmt.Fprintln(out, "stopped")
	return nil
}

// records builds the two recording paths and returns a function that flushes
// the batched one.
//
// They are built together because they share the JetStream context and are
// constantly confused for each other, and separating them here is where the
// difference is easiest to state: the Recorder cannot fail a call and so
// buffers, the Sink exists to be able to fail one and so does not.
func records(ctx context.Context, nc *nats.Conn, log *slog.Logger, cfg Config) (
	ledger.Recorder, audit.Sink, func(), error) {

	// The fallback is the same slog recorder this daemon used before there
	// was a stream at all. It is what everything the batcher cannot publish
	// degrades to, so a broker outage costs durability and not rows.
	fallback := record.NewSlog(log)
	recorder := ledger.Recorder(fallback)
	closeRecord := func() {}

	if !cfg.LedgerStream && !cfg.Audit {
		return recorder, nil, closeRecord, nil
	}

	js, err := natsjs.New(nc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening JetStream on %s: %w", cfg.NATS, err)
	}

	if cfg.LedgerStream {
		pub, err := recordjs.New(recordjs.Config{JS: js, Fallback: fallback, Log: log})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the ledger publisher: %w", err)
		}
		recorder = pub
		// context.Background rather than the serve context, which is already
		// cancelled by the time this runs — Close strips cancellation for the
		// same reason, and passing a live one here would only be a second
		// place to get it wrong.
		closeRecord = func() { _ = pub.Close(context.Background()) }
	}

	if !cfg.Audit {
		return recorder, nil, closeRecord, nil
	}

	// Before anything is served. A stream that drops records while acking
	// them is worse than no stream, because a fail_closed tool reads the ack
	// as the guarantee it asked for — so the misconfiguration has to stop the
	// process rather than be discovered by whoever goes looking for the row.
	if err := auditjs.AssertStream(ctx, js, log); err != nil {
		closeRecord()
		return nil, nil, nil, fmt.Errorf("this deployment cannot audit: %w", err)
	}
	sink, err := auditjs.New(auditjs.Config{JS: js, Retention: cfg.AuditRetention})
	if err != nil {
		closeRecord()
		return nil, nil, nil, fmt.Errorf("the audit sink: %w", err)
	}
	return recorder, sink, closeRecord, nil
}

func retentionText(d time.Duration) string {
	if d == 0 {
		return "indefinite"
	}
	return d.String()
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
