# Known gaps

## Built

- `internal/catalogue` — load, verify, digest, retain. `garmd serve
  --catalogue` reports `(version, digest)` and lists what it serves.
- `internal/transport` — the Invoker and Discoverer ports. No adapter.
- `internal/tool` — `Def`, the in-memory declaration.

## Not built

**No resolver.** `serve` loads a catalogue and then refuses, because it cannot
route to the services that implement it. The NATS adapter behind
`transport.Invoker` is the next piece.

**No chain.** None of the ten steps are ported. Nothing here authenticates,
authorises, checks input or sanitises — so nothing here should be deployed.

**No listeners.** `serve` binds nothing.

**No MCP surface, no catalogue service.**

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
