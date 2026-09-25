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

`audit.level LEVEL_AUDIT` is the exception: it refuses unconditionally,
because there is no seam to supply an audit stream. That becomes a nil check
like the others when the sink lands.

**The ledger is not durable.** `--catalogue` deployments record through
`record.Slog`, so step 9 is a line on stdout. A tool declaring
`audit: { fail_closed: true, retain_days: 2555 }` is satisfied today by
something a log rotation will delete. The type system honours the
declaration; the substrate does not. This is what the sink is for.

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

`toolplane` is the outlier at 48%, and it is the package that decides
everything. `cmd/garmd` is at zero: flag parsing around a listener, with the
parts worth testing covered where they live.

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
