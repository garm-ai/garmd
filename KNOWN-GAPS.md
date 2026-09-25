# Known gaps

## Built

- `internal/catalogue` — load, verify, digest, retain. `garmd serve
  --catalogue` reports `(version, digest)`, what the catalogue costs, and
  lists what it serves. A byte ceiling guards pathological input;
  `--max-tools` is an opt-in budget for catching a deployment pointed at the
  wrong catalogue.
- `internal/transport` — the Invoker and Discoverer ports, with a NATS
  adapter. Invocation, and discovery over `$SRV.INFO`.
- `internal/tool` — `Def`, the in-memory declaration.
- `internal/serve` — the agent-facing surface. Dynamic dispatch: a request is
  unmarshalled into a message built from a catalogue descriptor, routed over
  NATS, and the reply unmarshalled into another. No generated types anywhere.
- Reconciliation. A service advertises its descriptor hash; the catalogue
  records one per proto package; `garmd` compares them every 30s and refuses
  to route on a mismatch. Silence is not agreement, and a failed sweep leaves
  the previous verdict standing.
- `internal/authn` — step 1. JWT over a cached JWKS, issuer and audience
  allowlists, and delegation folding that can only narrow.
- `internal/record` — where an event goes. Its SHAPE is in the contract,
  because a tool call and a generation call must produce one record type.
- `internal/record/jetstream` — the ledger, batched onto `GARM_LEDGER`.
  Flushes on an interval, a count AND a byte bound, and on `Close`. Anything
  it cannot publish goes to a fallback Recorder — normally slog — so a broker
  outage costs durability and not rows. It never returns an error and never
  blocks, because `ledger.Recorder` is documented "must not fail the call".
- `internal/audit/jetstream` — the audit Sink, on `GARM_AUDIT`. One
  synchronous publish per write, the ack awaited, the error returned. It is
  the exact opposite of the ledger's publisher in every respect, and
  deliberately: a write-ahead still sitting in a buffer is a write-ahead that
  never happened.

**The chain is wired.** Every call goes through `toolplane.Core.Invoke` and by
no other route: the NATS hop is registered as the chain's resolver, so
reaching a tool means passing the steps first. `serve/e2e_test.go` proves it
over a real broker with a real verifier — a valid token reaches the tool, and
an absent, expired or under-cleared one never does.

The chain is derived from the catalogue generation rather than built beside
it, because the compartments it decides with and the plans it compiles both
come out of the artifact. Reload replaces the pair or neither.

## Not built

**Steps 4, 5, 7 and 10 have no implementation here, and a tool that declares
them will not mount.** Instance authorization, grant verification and notify
are `CoreConfig` seams, and `AddTools` refuses any tool declaring supervision
the Core has not been given: a MODE_GRANT tool with no `GrantVerifier`, an
authorization block with no `FGAChecker`, a MODE_NOTIFY tool with no
`Notifier`. `serve.Prepare` runs that at startup, so the refusal stops the
process rather than arriving one 503 at a time after a green deploy.

The refusal reads what THIS Core was configured with, not what the build
contains, so supplying a verifier makes the same tool mount. It is an
allowlist: an enum member that does not exist yet refuses by construction
rather than falling through.

Nothing in this repository currently supplies any of the three. So in
practice a catalogue containing an approval-gated tool cannot be served at
all — which is the intended failure, and the reason it is safe that the steps
are unimplemented.

The audit block no longer refuses unconditionally. `LEVEL_AUDIT`,
`fail_closed` and `retain_days` are all honourable now that a Sink exists —
the first two by the Sink being configured at all, the third by comparison
against the retention the operator asserted. `record_request` and
`record_response` still refuse, because a ledger `Event` carries no payload
and neither publisher invents one.

The refusal is still worth its shape. Four of the five fields used to be
dropped by the catalogue loader, which took `GetLevel()` and nothing else: a
tool could ask for a blocking, seven-year, payload-recording trail and mount
cleanly against a recorder writing to stdout, just by saying `LEVEL_LEDGER`.

## The audit stream is implemented, and stops short of the lake

`garm/contracts/audit.Sink` is the durable, separately-retained half of the
record, and the half that MAY refuse a call. The chain uses it: an audited
tool writes its intent before the resolver runs and its outcome after, and a
failed write-ahead refuses the call when the tool declared `fail_closed`.
Write-ahead rather than write-after because the alternative does not work for
anything irreversible — recording afterwards and failing the response tells
the caller the payment did not happen, when it did.

`internal/audit/jetstream` implements it. `--audit-stream-retention` turns it
on; without the flag `Audit` stays nil, and a catalogue containing an audited
tool still refuses to start. Nil cannot mean "audited tool served unaudited".

**`Retention()` is an assertion, not a measurement, and it is the sharp edge
here.** The forwarder acks a message as soon as it has flushed it onward,
which deletes it, so the stream's own `MaxAge` is a buffer window of hours —
nothing like the years a tool asks for in `retain_days`. The real retention is
the lifecycle policy on the object store behind the forwarder, which this
process cannot read. So the operator types it, the mount check compares
against it, and a value longer than the truth makes that check pass while the
promise is false. It is discovered by whoever goes looking for the row.

**The forwarder is not here.** Nothing drains either stream to a lake — that
is `forwarder`, still in the private monorepo. Until it exists the streams
are buffers, and `GARM_AUDIT` is a `DiscardNew` stream that will eventually
fill and start refusing calls, which is the correct direction and still an
outage.

**Startup asserts the audit stream's configuration and refuses to serve a
lossy one.** `DiscardOld` — JetStream's default — drops the oldest messages
while every publish goes on acking, so `fail_closed` would keep succeeding
against records quietly evaporating. `MemoryStorage` makes the ack mean
nothing. Both stop the process. Fewer than three replicas only warns, because
a single-node dev broker is legitimate and refusing there gets the check
turned off. A stream that does not exist yet is also only a warning: publishes
to a subject no stream captures fail loudly on every call.

**Nothing creates the streams.** garmd asserts and refuses; provisioning is an
operator's, because a daemon that creates its own audit stream creates it with
whatever defaults it was compiled with, on a cluster nobody inspected.

**The ledger can be durable now, and is not by default.** `--ledger-stream`
publishes batches to `GARM_LEDGER`; without it step 9 is still a line on
stdout that a log rotation deletes. The flag is off by default because
switching a deployment's ledger to a stream nothing drains yet would be a
change of failure mode disguised as a default.

The batching is not an optimisation of an already-async `Record`. The costs
are per event — a goroutine and a marshal each — and above all
`WithPublishAsyncMaxPending` is a hard ceiling rather than backpressure: when
the pending window fills, publishing errors and metering degrades to log
lines under exactly the load worth metering.

`audit.record_request` and `audit.record_response` still refuse at mount. A
ledger `Event` carries no payload, and neither publisher invents one.

**A quarantine refusal leaves no ledger row.** The surface refuses a tool
whose service implements a different contract BEFORE the chain runs, so that
the call cannot look like it happened. The cost is that the refusal is not
ledgered — and a contract mismatch in production is exactly the event someone
will later want a row for. Wiring the reconciler in as the chain's
`AvailabilitySource` would fix it; the two checks would then need deciding
between rather than both existing.

**The verifier's compartment registry is built once, at boot.** It comes from
the catalogue, so a reload that ADDS a compartment does not reach the
verifier: tokens asserting the new name have it dropped, and callers lose
authority until a restart. It fails in the safe direction — narrower, never
wider — and it fails silently, which is the objectionable half.

**No MCP surface, no catalogue service, no second listener.** The dev IdP's
tool-list panel needs the catalogue service and reports that it cannot reach
garm until then.

## Drift with devkit is not caught

`garm-ai/devkit` mints the dev tokens this verifier reads, and neither may
import the other: a module that can assert any identity must not be in the
dependency graph of one that decides what an identity may do. CI asserts it
from both sides.

Nothing currently fails if the token body and the verifier disagree. In the
monorepo one test minted and verified in a single process; that test is split,
and the seam between the halves is unguarded. The intended fix is a
cross-repository CI check — clone devkit, mint, assert the `Principal` — which
keeps it caught with no build edge either way. It is not built.

## Coverage

`toolplane` is the outlier at 53%, and it is the package that decides
everything. `cmd/garmd` is at 3%: flag parsing around a listener, with the
parts worth testing covered where they live — the one test there pins that no
audit configuration leaves the Sink nil rather than typed-nil, which every
mount refusal depends on.

The two publishers are at 92% (`internal/audit/jetstream`) and 99%
(`internal/record/jetstream`), both against a real embedded broker for
everything a broker decides — the ack, the duplicate id, a full `DiscardNew`
stream. Nothing in either file skips when something is missing: a test file
whose tests all skip reports `ok` while covering none of its subject.

Three test files did NOT come across from the monorepo, each for a reason
rather than by omission: `mount_test.go` exercises the generated-registry
mount path that the catalogue replaces, `core_invocation_context_test.go`
drives the NATS resolver directly, and the server-level tests target an HTTP
server that `serve` replaced. What they covered still needs covering, against
the new shapes.

**Producer/consumer agreement is untested** — that a real `garm-ai/tool-go`
service and this adapter agree on the wire. The faithful version needs the
dependency CI exists to refuse, so it belongs in a cross-repo test where both
sides exist, not in a fake here and not in a skip.

## Reachable but unexercised

**Client-name disambiguation.** `internal/catalogue` prefixes colliding short
names deterministically, and it is tested — but `garm catalogue build` refuses
to produce a catalogue that needs it, because L3 still treats a reused name as
an error.

That is the intended order, not an oversight: L3 relaxes only after the MCP
surface dispatches on the disambiguated name, and relaxing it first would
reintroduce the misroute L3 prevents. See the design record,
`decisions/2026-09-25-mcp-dispatches-on-the-fqn.md`.

## Deliberately elsewhere

**`garmmcp`, `forwarder` and the generation plane** are still in the private
monorepo. The generation plane is parked there on purpose; the others arrive
as their surfaces are ported.
