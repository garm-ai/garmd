# Known gaps

## Built

- `internal/catalogue` — load, verify, digest, retain. `garmd serve
  --catalogue` reports `(version, digest)`, what the catalogue costs, and
  lists what it serves. A byte ceiling guards pathological input;
  `--max-tools` is an opt-in budget for catching a deployment pointed at the
  wrong catalogue.
- `internal/transport` — the Invoker and Discoverer ports. No adapter.
- `internal/tool` — `Def`, the in-memory declaration.

- `internal/serve` — the agent-facing surface. Dynamic dispatch: a request is
  unmarshalled into a message built from a catalogue descriptor, routed over
  NATS, and the reply unmarshalled into another. No generated types anywhere.
- `internal/transport/nats` — invocation, and discovery over `$SRV.INFO`.
- Reconciliation. A service advertises its descriptor hash; the catalogue
  records one per proto package; `garmd` compares them every 30s and refuses
  to route on a mismatch. Silence is not agreement, and a failed sweep leaves
  the previous verdict standing.

- `internal/toolplane` — the chain, at 48% coverage from the monorepo's own
  tests. **Not yet wired into `serve`**, so a request still bypasses it.
- `internal/record` — where an event goes. Its SHAPE is in the contract,
  because a tool call and a generation call must produce one record type.

## Not built

**The chain is not wired in.** `internal/toolplane.Core` exists and compiles,
with steps 2, 3, 8 and 9 implemented and 1, 4, 5, 7, 10 stubbed as the
monorepo left them. But `serve` still calls the transport directly, so no
request passes through it. Until it does, this routes and does not govern,
and the startup warning means exactly what it says.

**Coverage is uneven and the gaps are named.** The chain is at 48% and the
catalogue at 81%; `serve` is at 38% (the reconciler is covered, the handler is
not) and `transport/nats`, `record`, `tool` and `cmd/garmd` are at zero.

Three test files did NOT come across from the monorepo, each for a reason
rather than by omission: `mount_test.go` exercises the generated-registry
mount path that the catalogue replaces, `core_invocation_context_test.go`
drives the NATS resolver directly, and the server-level tests
(`interceptor`, `server`, `catalog`) target an HTTP server that `serve`
replaced. What they covered still needs covering, against the new shapes.

**Step 1 has no implementation.** `garmauth` — JWT, JWKS, the act chain — is
still in the monorepo, so there is no way to build a real `Principal`. That is
the next port, and it is what unblocks wiring the rest.

**No MCP surface, no catalogue service, no second listener.**

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

**`garmmcp`, `garmauth`, `forwarder` and the generation plane** are still in
the private monorepo. The generation plane is parked there on purpose; the
others arrive as the chain is ported.
