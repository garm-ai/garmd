# garmd — the governed tool plane

A policy-enforcing proxy between an agent and the tools it may call. It decides,
on every call, what passes and what the caller is allowed to see of the answer.

It is a daemon. The command line tool is `garm`, in a separate repository.

## The three invariants

**1. garmd does not know its tools at build time.** It loads a catalogue
artifact at boot and serves exactly what that declares. This repository must
never build-depend on one that implements tools — a catalogue crosses that line
as data. CI asserts it.

**2. garmd does not know about agents.** An agent is a tool: a service at a NATS
subject with a declaration garmd governs like any other. There is no agent
annotation here, no dispatch kind, no agent-shaped field. Every mechanism the
agent plane needs turned out to be one the tool plane already has — depth is a
generic hop counter, and a runner's bundle digest is just another opaque
identity string compared through the same reconciliation.

*The subtle half:* the catalogue's version check is scoped to `garm.tool.v1` and
ignores every other extension namespace. Widen it and a catalogue carrying agent
annotations is refused at boot — agent-awareness acquired through an error
message.

**3. The chain is not configurable.** Ten steps, fixed order. The moment it is a
slice someone assembles, "is authorization applied?" stops being a structural
fact. What is pluggable is *how* a step is implemented, never *whether* it runs.

## Layout

```
cmd/garmd/              the binary
internal/
  catalogue/            load, verify, digest → the tools this process serves
  toolplane/            the chain: ten steps in a fixed order
  transport/            Invoker and Discoverer ports
    nats/               the one adapter
```

**Everything starts `internal/`.** A daemon has no library consumers until
someone asks, and promoting a package later is easy where demoting one is
breaking.

**`internal/toolplane` keeps its name** even though this repository *is* the
tool plane. 149 commits of design record refer to the tool plane and to
`toolplane.Core`; continuity with the corpus beats avoiding a mild redundancy.

## Transport is two ports, not one

Invocation is easy and any protocol does it. Discovery is not: it answers which
services are reachable, at which version, advertising which identity — from the
running process rather than from configuration. That is what lets garmd say a
tool is *declared but unreachable* instead of assuming a catalogue entry implies
a service.

NATS implements both. The second adapter waits for a named trigger — an
enterprise that cannot run NATS — not for a feeling that abstraction is tidy.

## Working here

```
mise install     the toolchain
mise run test    go test ./... -race
mise run ci      what CI runs
```

Task names match every other garm-ai repository. There is no `gen` task yet
because there are no protos yet.

## The design record is not in this repository

It lives in **[`garm-ai/spec`](https://github.com/garm-ai/spec)** (private),
checked out beside this one at `../spec/docs/superpowers/`. One interlinked
corpus — the specs cite each other by section — so it was not split across
repositories.

The ones that govern this repository:

- `specs/2026-09-24-call-stack-design.md` — the ten steps, and where each fails
- `specs/2026-09-25-public-split-design.md` — the catalogue as an artifact, §1 and Stack A
- `decisions/2026-09-25-garmd-does-not-know-about-agents.md`
- `decisions/2026-09-25-transport-is-a-port.md`
- `specs/2026-09-24-tool-service-shell-design.md` — what is on the other side of the hop

**Do not create `docs/superpowers/` here.**

## Not yet built

Everything. `serve` returns an error rather than binding a listener it has
nothing to serve on. The order is catalogue first, then the chain ported onto
it — so the compiled-in registry path is never ported at all.
