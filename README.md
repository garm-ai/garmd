# garm

**The governed runtime.** A policy-enforcing proxy that sits between an agent
and the tools it may call, and decides what passes.

Named for the hound that guards the gate in Norse myth, which is what this
does.

## What is here

| | |
|---|---|
| `cmd/garmd/` | The daemon. The sidecar that serves the generation API and the tool plane. |
| `toolplane/` | The governance core: authenticate, authorise, check input, resolve, sanitise, ledger. Fixed order, not configurable. |
| `catalogue/` | Loads a catalogue artifact at boot, verifies it, reports its digest. |
| `generation/` | The app-facing model API: providers, prompts, metering, policy. |
| `agent/` | The agent runner — manifests and a bounded loop. |
| `ops/` | The usage stream to a queryable lake. Never in a request path. |

## The catalogue is not compiled in

A garm build does not know which tools exist. It loads a **catalogue
artifact** — a descriptor set plus the annotations that govern it — at
startup, and serves exactly what that artifact declares.

Adding a tool is therefore a catalogue rebuild and a restart, not a release of
this binary. Identity is the pair `(binary version, catalogue digest)`,
reported at startup, on the health endpoint, and on every ledger event: "which
tools is this process serving" stays exactly answerable.

A binary reads the current annotation schema and the two previous. Backward is
generous; forward fails closed at boot rather than loading a policy document
it only partly understands.

## What is deliberately not here

- **The annotations and the generator** — [`spec`](../spec).
- **Anything a tool service imports.** A tool must not be able to reach this
  code and attempt the policy chain locally; a second, unreviewed
  implementation of enforcement is the failure this boundary exists to
  prevent. See [`tool-go`](../tool-go) and [`tool-python`](../tool-python).
- **Any tool.** This repository must never build-depend on one. A catalogue
  crosses that line as data, never as an import.

## Status

Not yet seeded. Intent recorded; code arrives at Phase 4 of the split.
