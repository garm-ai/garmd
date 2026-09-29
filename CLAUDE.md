# garmd — the governed tool plane

A policy-enforcing proxy between an agent and the tools it may call. It decides,
on every call, what passes and what the caller is allowed to see of the answer.

It is a daemon. The command line tool is `garm`, in a separate repository, and
this daemon does not depend on it. The one garm-ai module in the build is
`github.com/garm-ai/contracts` — the annotation vocabulary, the policy lattice,
the ledger and wire shapes. It was a directory inside `garm` until v0.2.0 of
the contract module, so anything in the corpus spelling a package
`garm/contracts/…` or `garm/policy` means `contracts/…` and `contracts/policy`
today.

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

`internal/catalogue/agentblind_test.go` holds this. It builds a catalogue whose
service carries a `garm.agent.v1.agent` option — declared in the fixture's own
proto source, never imported, because importing the type to prove it is not read
would defeat the point — and asserts that the two annotated methods mount as two
ordinary tools, that no error names the namespace, and that the annotation's
bytes survive unread. `internal/serve/agentblind_test.go` carries the same
fixture through `ListTools`, where an agent-aware garmd would most plausibly
leak: the two tools come back shaped like every other tool, and no value that
exists only inside the manifest — prompt digest, step bound, model alias, the
tools it may call — appears anywhere in the body. Breaking the invariant fails
there rather than in somebody's acceptance test.

*The one type it does know:* `garm.card.v1.Card`. Step 8 walks a card's value
and drops the elements whose `access` label the viewer does not reach
(`internal/toolplane/sanitise.go`). **That is not agent-awareness, and the
distinction is exact.** garmd knows a TYPE, the way it knows
`google.protobuf.Timestamp` is a value rather than a structure to classify —
not a tool, not an agent, not a task, and never an annotation: it reads a
`Label` off the message and nothing else in the package, so it cannot tell an
approval card from a start card, and the catalogue's version check is as
narrow as it ever was. The reason the type has to be known at all is that
inside it the policy is carried by the VALUE rather than by the descriptor: a
queue of tasks cannot say in a `.proto` which row is whose. The card
vocabulary is not linked either — `internal/toolplane/testdata/card.proto` is
a fixture, the type is matched by full name, and CI asserts
`github.com/garm-ai/contracts/garm/card` stays out of the dependency graph.
(It was `garm/contracts/garm/card` before the contract became its own module;
the grep in `.github/workflows/ci.yml` follows the package, because a boundary
check that greps a path nothing imports any more passes while asserting
nothing.)

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
breaking. One has asked: the root package is `garmd.Serve`, the entry point
`cmd/garmd` and `garm-ai/stack`'s `garmstack` both call — never for production.

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

**Discovery is two rounds, and it says when it could not hear.** `$SRV.PING`
plane-wide enumerates which services are running and how many instances each
has; then one `$SRV.INFO.<name>` per service, bounded concurrency, for the
endpoints and the advertised descriptor hash. One plane-wide `$SRV.INFO` was
what it used to be, and it put every instance of every service into one
collection, so an over-replicated service could crowd out a healthy one's
reply. Per-service rounds make the reply count one service's replica count,
and make incompleteness per-service.

`transport.Round` carries that: what answered, and which services were not
heard in full. **An incomplete round may add a quarantine and may never lift
one** — a mismatch is a positive observation a missing reply cannot produce,
while lifting rests on silence, which a missing reply imitates exactly.

**A third-party dependency, deliberately.**
`github.com/synadia-io/orbit.go/natsext` — Synadia's, the NATS authors' own
extension collection — supplies `RequestMany`. It is one file, requires only
`nats.go` which this adapter already links, and it is here to remove a bug
class: collection used to be a `ChanSubscribe` into a 64-message channel, and
nats.go DISCARDS rather than blocks when such a channel is full. An iterator
has no fixed buffer to overflow. Its stall timer is what usually ends a round
now, so a fast plane no longer pays the whole window.

The invocation hop carries `Garm-Invocation` beside the request: the caller's
assertions, encoded by `contracts/callctx`. Assertions, never credentials —
the token does not cross this boundary, and neither does clearance or
compartments, because a tool that can see clearance is a tool that will
eventually filter.

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

## What is not built

`serve` is built: it loads a catalogue, binds, and runs every call through the
chain. An answer that produced a ledger row carries `Garm-Event-Id` naming it
(successes and every refusal the chain decided; not the ones refused before
it), and a successful answer also carries `Garm-Catalogue-Digest`.

Step 5 — human approval grants, single-use — is implemented, and `garmd serve
--grant-issuer` is what constructs it. Without the flag there is no verifier,
and that is the configured answer rather than a hole: a MODE_GRANT catalogue
then does not mount.

What is not implemented is instance authorization (steps 4 and 7) and notify
(step 10) — and a catalogue declaring either **will not mount**, so this
process refuses to start rather than serve a tool ungated while its schema says
it is supervised. That refusal is the design, not a gap.

`KNOWN-GAPS.md` is the list, and it is kept honest by the tasks that change
what it says.
