# Known gaps

## Built

- `internal/catalogue` — load, verify, digest, retain. `garmd serve
  --catalogue` reports `(version, digest)`, what the catalogue costs, and
  lists what it serves. A byte ceiling guards pathological input;
  `--max-tools` is an opt-in budget for catching a deployment pointed at the
  wrong catalogue.
- **An `s3://` catalogue, with a safe reload.** `--catalogue s3://bucket/key`
  loads from an S3-compatible store, and `--catalogue-poll` (default 30s)
  checks its ETag. A change is pre-flighted before anything swaps: the bytes
  are read once, loaded, their compartment declarations built into a registry,
  their approval ceilings checked against the replay cache this process
  actually holds, and the chain built for them — and only then does the store
  take them. Any refusal at any of those leaves the previous generation serving
  and logs at error naming the serving digest and, whenever the bytes got as far
  as being read, the refused one (an object past the byte ceiling has no
  digest to name). An unreachable
  store is a warning and no swap: a bucket that cannot be read is not evidence
  that what is serving is wrong. The ETag only says *look again*; the DIGEST
  decides, so a re-upload of identical bytes is not a new generation. A refused
  object is reconsidered every poll — a refusal can lift without the object
  changing — but it is not fetched again while its ETag is unchanged, and an
  unchanged refusal is restated hourly rather than every thirty seconds.

**A reload is not cheap in memory, and one shape of it is worth naming.** The
pre-flight builds the candidate's chain from bytes in hand, `Store.Reload` then
parses those same bytes a second time into the generation it installs, and the
chain is built again for that one — so a swap can hold three copies of the
artifact's descriptors at once, and it forces two collections (the store
measures the heap around the load). The catalogue that is serving is never one
of the copies dropped, so this is a peak rather than a leak. Closing it means
splitting `Store.Reload` into a validate half and an install half so the
generation that was checked is the generation installed; that is a change to
`internal/catalogue` and its tests, deferred rather than done here. A refused
object is also held until it changes or a swap succeeds, so a process serving a
small catalogue against a bucket holding a large bad one carries both.
- `internal/transport` — the Invoker and Discoverer ports, with a NATS
  adapter. Invocation, and discovery over `$SRV.INFO`. **Every hop carries
  `Garm-Invocation`**: the caller's assertions — tenant and correlation id,
  the subject and its kind, the delegation chain in `act`, the absolute
  deadline, and the ledger row's id as `call_id` — encoded by
  `contracts/callctx`. Assertions only: never the caller's token, and never
  clearance or compartments, which are garm's to decide with and not a tool's
  to see. A tool runtime that refuses a request without the header is now
  reachable from here.
- `internal/tool` — `Def`, the in-memory declaration.
- `internal/serve` — the agent-facing surface. Dynamic dispatch: a request is
  unmarshalled into a message built from a catalogue descriptor, routed over
  NATS, and the reply unmarshalled into another. No generated types anywhere.
- **The ledger row's id is on every answer that produced one**, as
  `Garm-Event-Id`: on a success, and on every refusal that reached the chain —
  step 1's 401, the `not_found` for a tool the caller may not see, a chain
  error, a `grant_required`, and the 500 from a resolver that panicked. The
  refusals decided *before* the chain produce no row and carry no id: an
  unrouted 404, a quarantined package's 503, a 413, a 400 that would not
  unmarshal. A header naming a row nobody can find would send whoever is
  debugging to query a ledger that will never answer.

  `Garm-Catalogue-Digest` is narrower and is **not** a pair with it: it rides
  on successful responses only, so a refusal says which row explains it but
  not which catalogue decided it. Widening it is a small change nobody has
  needed yet.
- **`ListTools`** — `POST /garm.v1.ToolCatalogService/ListTools`, bearer token,
  `{}`. Answers the tools this caller may see, each with its FQN, route, verb,
  approval mode, material fields, the author's guidance prose and the input
  schema projected at the caller's own shape. It is not a tool: it mounts
  nothing, crosses no hop, and writes no ledger row on success. Unauthenticated
  is 401 with a row, through the same path the tool route uses.

  The listing is `Core.Catalog`, which is the same visibility predicate step 2
  denies with — so it cannot advertise a tool the chain would refuse. A second,
  hand-written list would agree today and stop agreeing the first time either
  changed, and the symptom would be a model attempting a tool it can never call.
- **`ListTools` takes an audience.** The body may name `PERSON`, `AGENT` or
  `RUNNER`; absent means `AGENT`, so a model's listing is unchanged by the
  field existing and a catalogue that declares no audience anywhere lists
  exactly as it did. A tool is offered when its declared audience admits the
  asked-for one **and** the caller's claims reach it — the second half is step
  2's predicate, untouched, so asking for an audience widens nothing. A row
  gained `sets` and `audience`; `audience` is what the author declared and `[]`
  when they declared nothing.

  **An audience is a LISTING rule and not a fourth gate.** Nothing in the ten
  steps reads it: a caller that knows a method name can still CALL a `PERSON`
  tool their claims reach, and gets whatever the chain gives them. That is the
  design's own division (§2.5: "step 2's visibility, unchanged") and it is
  sound for cards specifically, because a card's contents are projected by the
  card walk at the viewer's own reach whoever fetched it. Closing it would
  mean an audience that can deny a call, which is a fifth vocabulary to check
  when one is refused. Revisit only if something other than a card ever needs
  an audience to be an entitlement.

  ***The audience is read out of the catalogue, not out of the binary.***
  `ToolPolicy.audience` is Track G's and the garm this repository builds
  against (v0.14.2) has no such field. `internal/catalogue/audience.go` finds
  the field's NUMBER by NAME in the catalogue's own `garm.tool.v1.ToolPolicy`
  descriptor — so Track G's number choice cannot break the read — and then
  reads the VALUE either off the linked type (once a garm bump gives it one)
  or out of the unknown bytes the annotation carried through the load. A plain
  field and an extension of `ToolPolicy` are the same read. A catalogue whose
  `tool.proto` has no `audience` at all yields nothing, which reads as `AGENT`:
  the pre-audience behaviour, exactly.

  garm v0.17.0 ships the field (`ToolPolicy.audience = 14`, a plain field —
  the spec wrote `extend ToolPolicy`, which is impossible because `ToolPolicy`
  declares no extension ranges), so the ordinary path is now the reflective
  one and the fixtures compile against the linked contract.
  `internal/catalogue/testdata/future_tool.proto` keeps the OTHER path
  covered: it is v0.17.0's `tool.proto` with `audience` moved to field 40, so
  the linked type has nothing there, the value survives in unknown bytes, and
  the by-name lookup is the only thing that can find it. Deleting that fixture
  deletes the only coverage of the mechanism that will let the next field ship
  the same way.
- **A grant's task reaches the ledger row.** The STS binds an approval to the
  task it was given on (cards-and-tasks design §7), so two tasks with the same
  material — the same payment asked twice — cannot share one grant. When the
  claim is present it lands on the row as the `task_id` TAG, whether the grant
  verified or not: "an approval naming task X was presented and rejected" and
  "no approval naming a task was ever presented" are different facts. Both
  spellings are read (`garm_grant.task`, which the STS mints, and `task_id`,
  the request field it is copied from). A tag rather than a column because
  `ledger.Event` is shared with every other plane and has no slot; promote it
  when a second caller asks.

  **garmd does not CHECK the binding, and that is deliberate.** The thing that
  knows which task is being decided is the caller that opened it — the tasks
  tool, comparing the claim against the row it stored — and a check here would
  have nothing to compare against but itself. What garmd owes the claim is that
  it does not FAIL a grant: a verifier that refused what it did not recognise
  would make every claim the STS adds a breaking change, and the symptom would
  be every approval in the estate failing at once on the day the STS shipped
  it. `internal/grants/verify_test.go` pins the acceptance and the reporting;
  the tasks tool owes the comparison.
- **Validation violations reach the caller, projected.** A request that
  breaks a `buf.validate` rule answers 400 with `violations: [{field, rule,
  message}]`. The disclosure rule (`toolplane/violations.go`): a violation is
  listed when its field path is in the caller's own input projection —
  `SchemaFor` at the caller's shape, the object `ListTools` sent them — and a
  CEL rule when every field its expression selects off `this` is; the
  message is protovalidate's constraint sentence, replaced by the rule id
  alone when it could carry a value (a CEL message computed from the value, a
  rule with no declared message, a standard message that contains the
  refused string). The caller's values are never in the body — it sent them.
  Left out on purpose, in the safe direction: a CEL rule with a
  comprehension, one selecting off an index, or one naming an identifier
  protovalidate does not bind is never listed, because which field its
  variable aliases is not a question worth answering here; and a string map
  key on a path is spelled `[*]`. The ledger row is unchanged: the full
  protovalidate text in `error_detail`, nowhere else.
- **A tool's coded refusal is mapped, not 500.** The NATS adapter returns a
  micro error as `transport.CodedError`; the chain recognises one whose code
  it understands (`400 403 404 409 415 422 429 502 504` — `toolplane/errors.go`
  is the table) as a refusal the TOOL decided: the row is `denied` with
  `error_kind: tool_refused` and the tool's own message in `error_detail`,
  and the door answers status = the code with
  `{"code":"tool_refused","tool_code":"<code>","message":"<static sentence>"}`.
  The tool's words are never on the wire, whatever the tool promised about
  them. A code outside the table — `500`, a typo — is still `internal`, on
  the same path as before. The chain reads the code through a small
  interface rather than importing the transport port, so a second adapter
  answers the same way by satisfying it.
- Reconciliation. A service advertises its descriptor hash; the catalogue
  records one per proto package; `garmd` compares them every 30s and refuses
  to route on a mismatch. Silence is not agreement, and a failed sweep leaves
  the previous verdict standing.
- `internal/authn` — step 1. JWT over cached JWKS, and `--issuer`/`--jwks` are
  repeatable and paired by position: one key set per issuer, chosen by the
  token's own `iss` and then required to match the issuer whose keys verified
  it. That second check is the load-bearing half — routing on an unverified
  claim without it would let one trusted issuer mint tokens bearing another's
  name. The governed door needs it: a human's token comes from an IdP and the
  runner's from the STS, in one process. Audience allowlist, and delegation
  folding that can only narrow.
- **The `exec` claim, additively.** A token may carry a top-level
  `"exec": {"sub": "runner:<id>", "iss": …}` outside the `act` chain; the fold
  copies `exec.sub` to `Principal.Execution` and nothing in the chain reads it.
  A malformed one — a bare string, an object with no `sub` — refuses the token
  rather than being dropped, because a claim whose job is to say who ran
  something must not be allowed to say nothing.

  It is attribution and only attribution. `exec` is not a delegation hop and is
  not counted by `Claims.Depth`, so a runner cannot spend a level of the
  four-deep ceiling; it is read from the OUTERMOST claims only, never folded,
  because a runner asserts no authority there is anything to intersect. And
  garmd checks nothing whatsoever about `exec.iss`: it names whoever minted the
  runner's identity, not an issuer this process trusts, and requiring it to be
  one would make a token unusable for a reason that has no bearing on what the
  call may do.

  `agentd/internal/authn` parses the same claim the same way —
  `claims.go:162-172` for the shape and the refusal, `claims.go:69-70` for it
  not being a hop, `Fold` in `principal.go` for the copy onto the principal — so
  the two processes agree on what a token means.

  The row records it. `newEvent` copies `Principal.Execution` onto
  `ledger.Event.ExecutionSubject` (`execution_subject`, field 71, from
  `garm v0.14.2`) for every outcome the chain decides, so "which of these calls
  came through a runner" is answerable — and a direct call leaves it empty,
  which is what makes the column mean anything. The JetStream ledger carries it
  through `ledger.ToProto`; the stdout recorder prints it in the tool block
  beside `principal_kind`, because the default deployment has no stream and a
  field nobody prints is a field nobody can query.
- **A request folds its token against the generation it is being served by.**
  The surface reads the plane once and pins that chain's compartment registry
  on the request (`authn.WithRegistry`), and step 1 folds against it. A
  compartment set is a bitset numbered by sorted index over a whole
  generation's declarations, so a principal folded under one generation and
  judged under another holds neither more authority nor less — it holds a
  DIFFERENT set, and walks through whichever tool those bits happen to name
  there. A name no generation declares is still dropped rather than refused,
  because an IdP-side typo must cost that caller that compartment and not the
  whole token.

  `authn.Swappable` also holds a taxonomy behind an atomic pointer, for a
  verifier with no plane behind it, and the daemon passes one. A successful
  reload calls `Set`, in the same operation as the swap and after it: the chain
  for the generation now current is published first, then its taxonomy, so the
  two are never left disagreeing for longer than those two lines — and a
  generation that was refused leaves the old taxonomy exactly where it was. A
  Config naming both a registry and a source is refused rather than resolved.
- **`app: garmd` on every row.** `toolplane.AppName` is set in `newEvent`,
  so every row the chain writes — successes, every refusal it decides, and
  step 1's — names the plane that wrote it, which is what the lake partitions
  on (`PARTITION_BY (date, app)` in sink's Parquet writer) and what the
  JetStream subject carries (`garm.v1.ledger.<tenant>.<app>`). Rows used to
  carry an empty `app` and landed under `app=` beside agentd's `app=agentd`.
  The plane, not the declaring service: the service is already the package
  prefix of `tool`, and one partition per catalogue package is the join the
  column exists to avoid. Neither the ledger contract nor sink's README names
  a rule; sink's writer and agentd's recorder both treat `app` as the writer,
  so garmd does too.
- **Card projection at step 8** (`internal/toolplane/sanitise.go`). A response
  that is a `garm.card.v1.Card`, or carries one in a field or a repeated
  field, is walked after the field plan: every element, fact and choice with
  an `access` label the viewer does not reach is removed, the path (or a
  `Fact.field`) named in the card's `disclosure.withheld_fields` and counted
  on the ledger row beside the field redactions. An unlabelled element is read
  at the endpoint's own policy and never at PUBLIC; one labelled BELOW it
  refuses the whole call, 500, with `error_kind: card_invalid` and the
  element's path in `error_detail`. A card whose own label the viewer misses
  is `not_found` unary and dropped from a page.

  **A card is an opaque leaf to the FIELD plan**, and it has to be:
  `garm.card.v1` is recursive (`Element → Section → Element`) and its interior
  carries no field policies at all, so a `policy.Compile` that descended would
  refuse it outright — a card-serving catalogue could not mount. Since garm
  v0.17.0 `policy.IsOpaqueLeafMessage` names `garm.card.v1.Card` and
  `policy.Compile` handles both the nested case and a response that IS a card
  (an empty plan), so garmd calls it unchanged. Track D shipped an internal
  mirror of that walk for one release because the seam did not exist; it is
  gone.

  The card WALK keeps its own descent rule (`cardChildOf`) rather than sharing
  `policy.SubtreeOf`, deliberately: the two now want opposite things at a
  card — the field plan stops there, the card walk is looking for it — and
  sharing one predicate would make each release of garm's policy package a
  silent change to which cards get projected, with the failure looking like a
  card served whole. Taking v0.17.0 caught exactly that, as a red test.

  **A Section is a floor per call, not only per template.** An element
  labelled below the element that encloses it refuses the card
  (`label_below_section`, or `label_below_element` when the container is not a
  Section). Lint C8 checks the same rule at publish time and can only see a
  TEMPLATE; a card an override built in Go has no template to lint and reaches
  a viewer all the same, and the leak is specific — a child at INTERNAL inside
  a RESTRICTED section clears the endpoint floor, so floor 1 has nothing to
  say about it, and a reader who cannot see the heading would be shown what
  was under it. An unlabelled child likewise takes its section's label, not
  the endpoint's.

  ***The card vocabulary is read, never linked.*** garmd matches the type by
  full name and reads `access` through protoreflect, by field NAME, checking
  the number against the design's fixed values (`Element.access` 10,
  `Fact.access` 4, `Choice.access` 3, `Card.access` 10; `Label.clearance` 1,
  `Label.compartments` 2). A pinned message whose `access` sits at a different
  number, or a `Card` carrying no recognisable `access` at all, **refuses the
  card** (`card_invalid`, the sentence naming the message and the numbers)
  rather than reading as unlabelled: unlabelled means "read at the enclosing
  floor", which the caller has already passed, so a drifted contract that
  degraded to unlabelled would publish every element it had labelled. Refusing
  is the only fail-closed answer to a vocabulary this build has not met.

  Not linking it is a boundary CI asserts, so the tests cannot compile against
  the real package either: `internal/toolplane/testdata/card.proto` and
  `internal/conformance/testdata/card.proto` are **verbatim copies of garm
  v0.17.0's `garm/card/v1/card.proto`**, and
  `TestTheCardFixturePinsTheFieldNumbersTheDesignFixes` is what holds the
  shape. **They are the one thing here that does not update itself: re-copy
  both whenever `card.proto` changes.** The drift test catches a change to
  `access`'s number or name and nothing else.
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

**Steps 4, 7 and 10 have no implementation here, and a tool that declares them
will not mount.** Instance authorization and notify are `CoreConfig` seams, and
`AddTools` refuses any tool declaring supervision the Core has not been given:
an authorization block with no `FGAChecker`, a MODE_NOTIFY tool with no
`Notifier`. `serve.Prepare` runs that at startup, so the refusal stops the
process rather than arriving one 503 at a time after a green deploy.

**Step 5 IS implemented and IS constructed.** `internal/grants` verifies an
approval — issuer, audience, tool, subject, age against the tool's own ceiling,
approver seniority, and the material digest over the values the human actually
saw — and `internal/replay` makes it single-use through the `GARM_GRANTS_SPENT`
JetStream bucket, atomically and across replicas. `garmd serve --grant-issuer`
builds both, sizes the bucket by the longest `max_grant_age_seconds` the
catalogue declares plus the clock tolerance, checks that against the retention
the bucket actually has, and refuses to start if the cache would forget a grant
while it is still valid. The clock tolerance is `authn.DefaultSkew`, the same
60 seconds the token path allows, so a token that verifies and an approval that
does not cannot be the same clock; it is added to the bucket's lifetime because
the verifier accepts an approval that much past its ceiling. Without the flag there is no verifier and a MODE_GRANT catalogue
does not mount.

**A MODE_GRANT tool with no `max_grant_age_seconds` will not start.** Without a
ceiling the age check is skipped and an approval is valid for whatever `exp` the
issuer minted, which the tool's author cannot cap and the cache cannot be sized
to outlast — so the grant would be replayable after its spent-record expired.
The refusal names the tool.

*The bucket's expiry is still derived once, at startup, from the boot
catalogue, and a reload does not re-derive it.* A JetStream bucket's TTL is a
property of the bucket, which this deployment does not own alone, so widening
it under a running process is not garmd's to do. What the reload does instead
is REFUSE: a generation whose longest `max_grant_age` plus the skew exceeds the
retention the bucket actually reports keeps the previous generation serving,
with the reason logged, and the operator restarts — which is the one action
that does re-derive the bucket. That turns a silent replay window into a
refusal, and it is a real limitation rather than a closed gap: a catalogue
lengthening a ceiling cannot be rolled out to a running process by reload
alone.

The floor case is the same shape. A process started against a catalogue with no
gated tool opened its bucket at `bucketFloorTTL`, one hour, so a reload that
introduces the first gated tool is admitted only while that tool's ceiling plus
the skew fits inside the hour, and refused otherwise.

A presented approval that is not good for this call — wrong tool, wrong
subject, too old, already spent, material that differs from what was approved —
is a `permission_denied`, not a `grant_required`: a caller told to fetch another
approval after tampering with one would do exactly that.

An approval that could not be CHECKED — a half-configured verifier, a key set
that could not be fetched, a replay cache that could not answer — is the same
`permission_denied` on the wire, because the caller did nothing different and
saying which would tell a prober when this deployment's dependencies are down.
It differs for the operator: only these are logged at error level, naming the
tool and never the grant.

The refusal reads what THIS Core was configured with, not what the build
contains, so supplying a verifier makes the same tool mount. It is an
allowlist: an enum member that does not exist yet refuses by construction
rather than falling through.

`garmd serve` supplies the `GrantVerifier` when `--grant-issuer` is given, and
supplies neither `FGAChecker` nor `Notifier` at all. So a catalogue declaring
instance authorization or notify still cannot be served — which is the intended
failure, and the reason it is safe that those steps are unimplemented — while an
approval-gated catalogue is served by a deployment that configured step 5 and
refused by one that did not.

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

**`ListTools` has no cap and no filter on the wire.** It answers the whole
projection in one body: no page size, no ceiling on the number of tools, and no
ceiling on the bytes — `maxRequestBytes` guards the request side only. A caller
with a large catalogue is a large body per poll, and agentd's client refuses an
answer over 16 MiB as a TERMINAL step failure rather than retrying it (an
oversized answer is oversized again next time), so the first symptom is a run
that cannot start rather than a slow one.

`toolplane.CatalogFilter` is the mechanism when it is needed — name prefix,
verb, service, tool set, maximum approval mode, conjunctive — and it is already
what `Core.Catalog` takes. The endpoint hard-wires the zero value, because §3.7
fixes the request as `{}` and Track D sends that. Putting those fields on the
wire is additive and nobody has needed it yet; the catalogue sizes people run
today fit comfortably, and `--max-tools` is the blunt instrument in the
meantime.

**A catalogue declaring a tool at `/garm.v1.ToolCatalogService/ListTools` will
not mount.** The surface answers that path before it looks a route up, so such
a tool would be permanently shadowed — never invoked, never refused, never
reported, with every call to it returning somebody's tool list while the
catalogue went on saying the tool was served. `serve.newPlane` refuses it by
name, which covers the boot mount and the reload pre-flight both.

**No MCP surface and no second listener.** `ListTools` is on the main listener
and speaks JSON over Connect's unary shape, not MCP's `tools/list`. Serving
both from this one projection is the intended next step, and until it happens an
MCP client has nothing here to talk to.

## Drift with the STS is caught, for the cases sts.json covers

`garm-ai/sts` mints the tokens and the approval grants this verifier reads,
and neither may import the other: a module that can assert any identity must
not be in the dependency graph of one that decides what an identity may do.
CI asserts it from both sides.

The seam between minting and verifying is a cross-repository CI check, not a
same-process test. `internal/conformance` loads a suite of cases from
`internal/conformance/suites/sts.json`, drives the running service over HTTP
per case, and checks the answer with this repository's own code. Four kinds
of case, and each asserts exactly one thing:

- **`expect`** — the STS's `POST /token` mints, `internal/authn` verifies and
  folds, and the resulting `Principal` is compared field by field. `subject`,
  `actor`, `clearance`, `compartments`, `verbs`, `toolSets`, `dropped`,
  `execution`, `tenant` and `chain` are all asserted whether the case names
  them or not, so a case that omits `execution` is asserting the token
  carried no `exec` claim at all — which is what pins the runner's
  provenance to the governed door and nowhere else. `tenant` and `chain`
  are required at load, because a fold always produces both: the tenant is
  what confines a caller to their own organisation's data, and the chain is
  every hop the fold walked, compared in order (`chain[0]` is the subject,
  the last hop the actor).
- **`mintError`** — the STS REFUSES. Only a `*RefusalError` satisfies it: a
  dead port asserts nothing, and accepting one would make a suite of
  refusal cases pass against a service that was never running.
- **`grant`** — the STS's `POST /approve` issues an approval and this
  daemon's own `internal/grants.Verifier` must accept it, followed by a
  direct assertion that the digest is over the values the issuer was given
  and that the approver recorded is the one it derived from the verified
  token.
- **`grantError`** — the STS's `POST /approve` REFUSES, and refuses the one
  way its contract allows: the opaque `400 {"error":"access_denied"}`. A
  500, a 405, or a 400 whose body names the reason all fail the case — the
  first two because a crashed or misrouted service is not a refusal, the
  last because a reason in the response is the enumeration oracle the
  opaque body exists to prevent. `sts.json` carries four: a customer
  identity presented as the approver, an approver whose token carries an
  `act` chain (an agent approving its own destructive call), a material
  path that would forge a separator in the digest, and a calling service
  that sent no `client_assertion`. The two knobs a refusal case can turn —
  `approverActor` and `omitClientAssertion` — do not exist on a `grant`
  case at all; the loader refuses them there.

The `conformance` job in `.github/workflows/ci.yml` starts devkit as the
upstream IdP, starts the STS trusting it, runs the suite and fails the build
on any disagreement — with no build-time edge between the repositories: both
are `checkout`'d and run as processes, never imported, and the `boundaries`
job re-asserts `go list -deps -test ./...` names neither `garm-ai/devkit`
nor `garm-ai/sts`, under both tag sets.

**The STS is checked out at the `v0.3.0` tag.** The endpoints the exchange-2
and `/approve` cases drive and the deploy fixtures they read first shipped
there; an older
`sts` refuses to start on the `approve:` block this job writes. A tag, not a
branch, on purpose: a branch ref would make this job follow whatever lands on
the STS side, and a case could then be made to pass by an edit there rather
than by the two sides agreeing. The tag is bumped by hand when the suite grows
a case that needs a newer STS.

What remains unguarded, in five parts:

**The suite covers the cases in `sts.json` and no others**, so a claim shape
only a different persona or a different tool declaration would exercise is
still unchecked. Two rows of the STS's `/approve` refusal table are out of
this job's reach by construction: "the approver's issuer is not configured
`kind: employee`" needs a second upstream issuer configured as `customer`,
and devkit mints one fixed `iss` that the STS's config may name once — so
the suite's customer case exercises the neighbouring row instead (a
`customer:` subject from an employee-kind issuer, refused rather than
repaired), and the issuer-kind row itself is pinned only by `sts`'s own
`TestApproveRefusesANonEmployeeApprover`. Nothing here asserts that two
grants carry different `jti`s either — single-use is `internal/grants`'s
subject, and the harness's own replay cache is per-run. `devkit.json` is
still shipped beside `sts.json` and is no longer driven by any job; its
`tenant` expectations pin the `bank` default in devkit's
`examples/personas.yaml`, so it runs against a devkit started with
`--personas` and no `--tenant`.

**A grant case checks the issuer's half of material binding and not
garmd's.** `grants.Verifier.checkMaterial` re-extracts material values from
the actual request message using its descriptor; a suite file carries no
proto message and no descriptor, so the harness declares a `ToolDef` with no
`MaterialFields` — which makes that check a no-op — and asserts the digest
directly instead. Re-extraction from a real request is covered by
`internal/grants`'s own tests, never by this job.

**The suites live in this repository.** `internal/conformance/suites/` holds
`devkit.json` and `sts.json`. They were in the private `spec` repo, which made
this a public repository's CI reaching into a private one: it needed a
`GARM_CI_TOKEN` secret, and a pull request from a fork is handed no secrets at
all, so the job had to skip there. Drift was caught for maintainers and not for
outside contributors — the people most likely to change a claim shape without
knowing what depends on it.

The suites moved; the job did not stop needing a secret. `garm-ai/sts` is
itself private, so the `conformance` job still checks it out with
`GARM_CI_TOKEN` and is still skipped on a pull request from a fork. What the
move bought is that the FILES are readable and reviewable by everyone, and
that `TestTheShippedSuitesLoad` — an ordinary `go test ./...` — refuses a
malformed one on every build, fork PRs included. The tokens behind them are
still only minted for maintainers.

Moving them here costs the arrangement its third party. The verifier now owns
the expectations it verifies against, so a fold bug and a matching expectation
edit can land in one commit. That is a real weakening, and it is why these
files are DATA a reviewer reads rather than code: a changed expectation shows
up in a diff as a changed fold, which is exactly the thing worth arguing about.

**The `aud` array form — the bug this branch fixes — is never exercised by
the drift check.** `devkit` mints `aud` as a bare string, so every token the
conformance run sees carries the scalar form. A green conformance run is
therefore NOT evidence that the array-form audience fix works; the only thing
covering it is the audience table in `internal/authn/verify_test.go`, which
drives the verifier directly with `aud` as a string, as an array containing
the audience, as an array not containing it, and absent. Closing this would
mean devkit gaining a way to mint the array form and the suite gaining a case
that asks for it.

**The compartment vocabulary is the suite's own declaration, not a real
catalogue.** `internal/conformance.Run` builds the `policy.Registry` from
`s.Compartments` — the list in `devkit.json` — so the `dropped` assertions
prove the verifier drops a name the SUITE does not declare, not one no
deployed catalogue declares. The design record lists "the compartment
vocabulary against a real catalogue" among the gaps this job closes; that one
is not closed. What would close it is checking both sides against a built
catalogue — the `garm claims check --against` shape — rather than against a
vocabulary the suite asserts about itself.

## Coverage

`toolplane` is the outlier at 53%, and it is the package that decides
everything. `cmd/garmd` is no longer only flag parsing: at 38% across 29 tests,
`records`, `trustedIssuers`, `grantVerifier`, `longestGrantAge`, `chainBanner`
and `catalogueSource` are each tested there, because each one is a seam where a
wiring mistake produces a process that starts cleanly and enforces less than it
says. The two that matter most are the ones asserting a NIL interface — no
audit configuration leaves `Audit` nil, no `--grant-issuer` leaves `Grants`
nil — because a typed nil in either field would mount exactly the tool the
refusal exists to stop.

`internal/reload` is tested against an httptest object store with a real S3
client, and every test there is about a generation that must NOT be served.

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

**The card conformance table runs in the ordinary suite**, unlike the minter
one. `internal/conformance/cards_test.go` states the cards-and-tasks design's
§12 garmd rows declaratively — a fact at `RESTRICTED + [financial]` seen by two
personas over one endpoint, a `Section` with a withheld child and one with
none left, a child labelled below its section and one labelled above it, floor
1's refusal with the path on the ledger row, a card whose own label the viewer
misses, and a `PERSON` tool absent from an `AGENT` listing.
It needs nothing running because both sides of the agreement are in the
repository: the contract (a card's `access`, a tool's `audience`) as fixtures
under `testdata`, and this daemon's reading of it. The minter suite is behind
`-tags conformance` because it needs a live STS; a table that could run and
did not would be a table nobody runs.

Every row goes through `Core.Invoke`, not the walk directly. A projection
asserted against the walk alone would pass with step 2 removed, and step 2 is
half of what each of those rows is about — which is why two of them assert a
`not_found` rather than a projection.

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
