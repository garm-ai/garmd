# garmd

**The governed tool plane.** A policy-enforcing proxy between an agent and the
tools it may call, deciding on every call what passes and what the caller is
allowed to see of the answer.

A long-running process — systemd or Kubernetes starts it. The command line tool
is [`garm`](https://github.com/garm-ai/garm).

Named for the hound that guards the gate in Norse myth, which is what this does.

## The catalogue is not compiled in

A garmd build does not know which tools exist. It loads a **catalogue
artifact** — a descriptor set plus the annotations that govern it — at startup,
and serves exactly what that artifact declares.

Adding a tool is a catalogue rebuild and a restart, not a release of this
binary. Identity is the pair `(binary version, catalogue digest)`, reported at
startup, on the health endpoint and on every ledger event, so *which tools is
this process serving* stays exactly answerable.

A binary reads the current annotation schema and the two previous. Backward is
generous; forward fails closed at boot rather than loading a policy document it
only partly understands.

## What is deliberately not here

- **The annotations and the generator** — [`garm`](https://github.com/garm-ai/garm).
- **Anything a tool service imports.** A tool must not be able to reach this
  code and attempt the chain locally; a second, unreviewed implementation of
  enforcement is the failure this boundary prevents.
- **Any tool.** This repository never build-depends on one. A catalogue crosses
  that line as data.
- **Agents.** An agent is a tool. garmd has no agent annotation, no dispatch
  kind and no agent-shaped field.

## Status

`serve` binds a listener and routes tool calls: one route,
`POST /pkg.Service/Method`, dispatched dynamically from the catalogue's
descriptors and answered through the chain. Every answer carries
`Garm-Catalogue-Digest` — which catalogue produced it — and, whenever the call
reached the chain and so produced a ledger row, `Garm-Event-Id`: the id of that
row, which is how a caller joins its own record of a call to the ledger's.

Not every step of the chain is implemented. `KNOWN-GAPS.md` is the list, and it
is kept honest rather than aspirational.

MIT licensed.
