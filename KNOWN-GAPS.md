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

## Not built

**No chain. This routes; it does not govern.** None of the ten steps exist:
no authentication, no authorization, no input checking, no redaction, no
ledger. `serve` says so at startup, and it means it — in front of anything
real this is an ungoverned proxy wearing a governed one's name.

**No reconciliation, and the gap is on the producer side.** A service
advertises its descriptor hash on `$SRV.INFO`, and `garmd` reads it into
`transport.Service.Identity` — but the catalogue carries no hash to compare it
against, so nothing checks that a service implements the contract the
catalogue declares. `garm catalogue build` needs to stamp the per-package hash
using the generator's existing function; a second implementation of that hash
would be worse than none.

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
