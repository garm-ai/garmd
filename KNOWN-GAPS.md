# Known gaps

What this daemon does not do, and what it does on purpose that will surprise
you. Not an inventory of what works — the code says that, and a file that
repeats it goes stale in a way the code cannot.

## What nothing here checks

**A discovery round that hears nothing cannot tell an empty plane from an
unreachable one.** Discovery is a scatter-gather, so silence is the only thing
a window can end on. `Services` marks a round incomplete when a reply was
dropped, when the ceiling closed mid-collection, or when a service answered
fewer instances than the enumeration counted — but a round in which NOTHING
arrived is reported as a complete answer about an empty plane, because
reporting it as incomplete would freeze the reconciler on a deployment that
legitimately has nothing running. A broker that is up and refusing therefore
still reads as "nothing is deployed". Closing it needs a second signal about
the broker itself, not a longer window.

**Per-service rounds are driven by the plane's own enumeration, not by the
catalogue.** `$SRV.INFO.<name>` addresses a micro service by the name it
registered, and micro validates that against `^[A-Za-z0-9\-_]+$` — never a
proto FQN. `agentd` derives its name with `wire.MicroServiceName`, so it is
predictable; `tool-go` takes whatever string the tool's author passes to
`garmtool.New`, and the reference plane's services are called `web`,
`accounts`, `payments`. So the catalogue cannot name the services it declares,
and discovery asks `$SRV.PING` first to find out. The cost is a round trip per
sweep. Closing it means `tool-go` naming its service from `wire`, or a
catalogue that records the micro name — until then, driving the INFO rounds
from the catalogue would silently discover nothing.

**`Retention()` is an assertion, not a measurement.** The forwarder acks an
audit message once it has flushed it onward, which deletes it, so the stream's
own `MaxAge` is a buffer window of hours rather than the years a tool asks for
in `retain_days`. The real retention is the lifecycle policy on the object
store behind the forwarder, which this process cannot read. The operator types
it and the mount check compares against it, so a value longer than the truth
makes the check pass while the promise is false. It is discovered by whoever
goes looking for the row.

**A quarantine refusal leaves no ledger row.** A tool whose service implements
a different contract is refused before the chain runs, so the call cannot look
like it happened — and a contract mismatch in production is exactly the event
someone will later want a row for. Wiring the reconciler in as the chain's
`AvailabilitySource` would fix it, and the two checks would then need deciding
between rather than both existing.

**Producer/consumer agreement is untested**: that a real `garm-ai/tool-go`
service and this adapter agree on the wire. The faithful version needs the
dependency CI exists to refuse, so it belongs in a cross-repository test where
both sides exist, not in a fake here and not in a skip.

**The conformance suite covers the cases in `suites/sts.json` and no others.**
A claim shape only a different persona or a different tool declaration would
exercise is unchecked, and the STS is pinned at `v0.3.0` rather than a branch,
so the suite proves agreement with a released STS rather than with `main`.
Two specific holes inside it: `devkit` mints `aud` as a bare string, so the
array form is covered only by `internal/authn/verify_test.go` driving the
verifier directly; and the compartment vocabulary is the suite's own
declaration rather than a built catalogue, so a `dropped` assertion proves the
verifier drops a name the SUITE does not declare.

**The card vocabulary is a fixture, not the linked type.**
`internal/toolplane/testdata/card.proto` and `internal/conformance/testdata/`
are byte copies of the contract module's `proto/garm/card/v1/card.proto`, kept
that way because CI refuses a build dependency on `garm/card`. Nothing
automatically compares them, so the copies drift the day the contract changes
and nobody re-copies.

## Deliberate, and worth knowing

**Steps 4, 7 and 10 have no implementation, and a catalogue declaring them
will not mount.** Instance authorization and notify are `CoreConfig` seams;
`AddTools` refuses a tool declaring supervision the Core was not given, and
`serve.Prepare` runs that at startup. The process refuses to start rather than
serve a tool ungated while its schema says it is supervised. Step 5 IS
implemented — `garmd serve --grant-issuer` constructs it, and without the flag
a `MODE_GRANT` catalogue does not mount.

**The grants bucket's expiry is derived once, at startup.** A JetStream
bucket's TTL belongs to the deployment rather than to this process, so a
reload cannot widen it. What a reload does instead is refuse: a generation
whose longest `max_grant_age` plus the clock skew exceeds the retention the
bucket reports keeps the previous generation serving, and only a restart
re-derives it. So a catalogue that lengthens an approval ceiling cannot be
rolled out by reload alone.

**Nothing creates the streams, and nothing drains them.** garmd asserts the
audit stream's configuration and refuses a lossy one — `DiscardOld` or
`MemoryStorage` stop the process — but provisioning is an operator's, because
a daemon that creates its own audit stream creates it with whatever defaults it
was compiled with. The forwarder that would drain either stream to a lake is
not here, so `GARM_AUDIT` is a `DiscardNew` buffer that will eventually fill
and start refusing calls. That is the correct direction and still an outage.

**The ledger is not durable by default.** `--ledger-stream` publishes to
`GARM_LEDGER`; without it step 9 is a line on stdout that a log rotation
deletes. Off by default because switching a deployment's ledger to a stream
nothing drains yet is a change of failure mode disguised as a default.

**A reload can hold three copies of the descriptors.** The pre-flight builds
the candidate's chain from bytes in hand, `Store.Reload` parses the same bytes
again into the generation it installs, and the chain is built again for that
one. The catalogue that is serving is never one of the copies dropped, so it
is a peak rather than a leak; closing it means splitting `Store.Reload` into a
validate half and an install half.

**`ListTools` has no cap and no filter on the wire.** No page size, no ceiling
on the number of tools and none on the bytes — `maxRequestBytes` guards the
request side only. agentd's client refuses an answer over 16 MiB as a terminal
step failure, so the first symptom of a large catalogue is a run that cannot
start. `toolplane.CatalogFilter` is the mechanism when it is needed; the
endpoint hard-wires the zero value because the spec fixes the request as `{}`.

**Discovery is a poll.** `Watch` returns an error saying so rather than a
channel that never fires.

## Enforced rather than written down

These are asserted by `.github/workflows/ci.yml`, which is the difference a
reviewer most needs to know. A grep that matches nothing passes while asserting
nothing, so each one is checked under both tag sets with a fail-closed guard on
empty output.

- No dependency on a token minter (`devkit`, `sts`), tests included.
- No build dependency on any repository that implements tools.
- No dependency on `contracts/garm/agent` — garmd stays agent-blind.
- No dependency on `contracts/garm/card` — garmd knows that type by NAME.
- No build dependency on the embedded broker or a storage client.
- No build dependency on the tool-side runtime.
- **No database, no migrations.** garmd decides and records and stores nothing
  a tool could ask it for; state that outlives a request would make this proxy
  a second source of truth competing with the ledger. The check forbids
  `database/sql` — the choke point every idiomatic driver goes through — plus
  the drivers, ORMs and migration runners that reach a database without it.
