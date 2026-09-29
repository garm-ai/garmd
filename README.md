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
and serves exactly what that artifact declares. `--catalogue` takes a path or
an `s3://bucket/key` URL; credentials come from the AWS default chain, and
`AWS_ENDPOINT_URL` points it at SeaweedFS or MinIO.

Adding a tool is a catalogue rebuild rather than a release of this binary —
and for an `s3://` catalogue, without a restart either; a file catalogue still
needs one. Identity is the pair `(binary version, catalogue digest)`, reported
at startup and on every ledger event, so *which tools
is this process serving* stays exactly answerable. Every ledger row also
carries `app: garmd` — the plane that wrote it, the same way agentd's rows say
`agentd` — because the lake is partitioned by `(date, app)` and a row with
none lands under `app=`; the tool a row is about is its own column.

**An `s3://` catalogue is reloaded without a restart, or refused.**
`--catalogue-poll` (30s by default, `0` to turn it off) checks the object's
ETag; when it changes,
the bytes are read once and everything that can refuse runs on them before
anything is swapped — they must load, their compartment declarations must
build a taxonomy, their approval ceilings must still be covered by the replay
cache this process opened at startup, and the chain must mount every tool they
declare. Only then does the new generation become the one being served, and its
taxonomy reach the verifier in the same operation.

Any refusal leaves the previous generation serving and logs at error, naming
the generation still serving and — whenever the bytes got as far as being read
— the digest refused. A store that cannot be reached is a warning and no swap:
a bucket nobody can read is not evidence that what is serving is wrong, and
withdrawing a working catalogue is the one thing to avoid at the moment nobody
can replace it.

A refused object is reconsidered on every poll, because a refusal can lift
without the object changing, but it is not fetched again while its ETag is
unchanged, and the same refusal is restated at most hourly rather than on every
poll. A file catalogue is never polled; it is placed by whoever deployed the
binary and does not change underneath it.

A binary reads the current annotation schema and the two previous. Backward is
generous; forward fails closed at boot rather than loading a policy document it
only partly understands.

Identity is configured the same way: `--issuer` and `--jwks` are repeatable and
paired by position, one key set per issuer. A deployment serving an agent
verifies the human's token from its IdP and the runner's from the STS in one
process, and a single key set for both would let either sign for the other.

A token may also carry a top-level `"exec": {"sub": "runner:agentd", "iss": …}`
— the runner that executed the call, beside the `act` chain rather than in it.
`internal/authn` parses it, the fold copies `exec.sub` onto
`Principal.Execution`, and that is the end of what happens to it inside the
chain: **nothing in the ten steps reads it.** It is attribution, like the
principal's kind — a fifth vocabulary that could deny a call would mean two
places to look when one is refused.

It is not a delegation hop, so it does not count against the four-deep chain
ceiling, and garmd checks nothing at all about `exec.iss`: it names whoever
minted the runner's identity, not an issuer this process has to trust. What
garmd does insist on is that a present `exec` is well formed — an object with a
non-empty `sub`. A malformed one refuses the token instead of being dropped,
because the alternative is a record that says a call was direct when it was not.

What reads `Principal.Execution` is the ledger, and only the ledger. Every row
the chain writes carries it as `execution_subject`, empty for a direct call —
a column that is always filled distinguishes nothing. It does not cross the
NATS hop: `Garm-Invocation` carries what the caller asserts, and which process
executed the call is not something the tool on the far side has any business
deciding on.

## What is deliberately not here

- **The annotations and the generator** — [`garm`](https://github.com/garm-ai/garm).
- **Anything a tool service imports.** A tool must not be able to reach this
  code and attempt the chain locally; a second, unreviewed implementation of
  enforcement is the failure this boundary prevents.
- **Any tool.** This repository never build-depends on one. A catalogue crosses
  that line as data.
- **Agents.** An agent is a tool. garmd has no agent annotation, no dispatch
  kind and no agent-shaped field.

## Running it in-process

The binary is the way you run garmd. `garmd.Serve(ctx, garmd.Config{…})` — the
root package, importable — is the same program with the flag parsing taken off
the front, and there is one implementation behind both. It exists so
`garm-ai/stack`'s `garmstack` can run garmd, the STS, agentd and the dev IdP as
goroutines in one process for local development and demonstration, each still
speaking NATS and HTTP to the others. That single-process mode is never for
production: one process holding agentd's client key, the STS's signing key and
this daemon's verifier configuration is one compromise away from all three.

## Status

`serve` binds a listener and routes tool calls: one route,
`POST /pkg.Service/Method`, dispatched dynamically from the catalogue's
descriptors and answered through the chain.

Beside it is one endpoint that is not a tool. `POST
/garm.v1.ToolCatalogService/ListTools`, with a bearer token and a `{}` body,
answers what this caller may be offered:

```json
{
  "catalogue_digest": "sha256:…",
  "tools": [
    {
      "fqn": "acme.v1.get_balance",
      "method": "/acme.v1.AccountsService/GetBalance",
      "title": "Read a balance",
      "description": "…",
      "verb": "VERB_READ",
      "sets": ["payments"],
      "audience": ["AGENT"],
      "approval_mode": "MODE_UNSPECIFIED",
      "material_fields": [],
      "guidance": {"when_to_use": "…", "when_not_to_use": "…", "on_error": "…"},
      "input_schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "…": "…"}
    }
  ]
}
```

**What it leaves out is the point.** A tool this caller could not call is not
in the list at all, and the filter is not a second rule that agrees with the
chain: it is the same visibility predicate step 2 denies with — clearance,
compartments, verb and tool-set scope, folded against the generation serving
this request. So the listing cannot advertise a tool the chain would refuse,
and a caller cleared for none gets `"tools": []` rather than an error. Existence
is itself information, which is why an omitted tool is omitted rather than
marked as denied. The input schema is likewise projected at this caller's own
shape, so a field they may not write is not in the schema they are shown.

**The body may name an audience.** `{"audience": "PERSON"}`, or `AGENT` or
`RUNNER`; absent means `AGENT`, which is why a model's listing is unchanged by
this field existing. A set says who *holds* a tool; an audience says what it is
*for*, and that is a different question with a different answer over the same
entitlements. `get_balance` is a tool plenty of people's claims reach and
nobody should ever be shown a form for; a card is person-facing whatever its
parent tool is. So a tool declares its audience in its own contract, and a row
is listed when that audience admits the asked-for one **and** the caller's
claims reach it. Neither half is new and neither substitutes for the other:
asking for `PERSON` widens nothing, because the second half is still step 2's
predicate. An audience that is not one of the three is a 400 rather than a
quiet fall back to the model's list.

A row carries its `sets` and its `audience` for the same reason it carries
`approval_mode`: a client that has to group a listing otherwise keeps its own
copy of the catalogue's vocabulary. `audience` is what the author *declared*,
`[]` when they declared nothing — the same distinction `approval_mode` keeps
between `MODE_UNSPECIFIED` and `MODE_NONE`. An empty audience reads as `AGENT`
wherever it is applied.

A request that breaks its own contract is a 400 whose body lists the
violations this caller may see, `violations: [{field, rule, message}]` beside
the code, so a model can repair the request instead of retrying it unchanged.
A violation is listed when its field is in the input schema this caller was
shown — the same projection `ListTools` sent it, so a field it may not send is
never named — and a cross-field CEL rule only when every field it reads is;
the message is protovalidate's own sentence about the constraint, dropped for
the rule id alone wherever it could carry a value, so the caller's values never
come back to it. The ledger row carries the full detail as before.

A tool that ran and answered with a code of its own — `403` off an allowlist,
`404` nothing there, `502` an upstream that failed; any of `400 403 404 409
415 422 429 502 504`, the codes tool-go's `toolbind.CodedError` carries — is a
refusal the tool decided, and the caller reads it as one: the HTTP status is
that code and the body is `{"code":"tool_refused","tool_code":"404",
"message":"…"}` with a static sentence per code. The tool's own message goes
to the ledger's `error_detail` and never to the wire — tools promise it is
page-free, and garmd does not rely on the promise — and the row is `denied`
with `error_kind: tool_refused`. Any other code, `500` included, is still
`internal`.

The body carries no policy: no clearance, no compartment names, no redaction
plan, nothing about any other caller. Everything in it is something the caller
can act on — including `approval_mode` and `material_fields`, which are what it
needs to go and obtain a grant before calling a gated tool. Enums are spelled
as their names, the way protojson spells them, so a consumer needs no copy of
the enum. The example above declares no approval block, which is why it reads
`MODE_UNSPECIFIED` rather than `MODE_NONE`: the second is a value an author
chose, the first is an author who said nothing, and only `MODE_GRANT` means a
call needs an approval.

`catalogue_digest` is in the body and on `Garm-Catalogue-Digest`, and it is the
generation this request pinned, read once: a listing is one generation's,
whole, even when a reload lands while it is being answered. A successful listing
writes no ledger row — a catalogue polled every turn would bury the calls under
the listings — but an unauthenticated one is a 401 with a row, through the same
step 1 the tool route uses, and carries that row's `Garm-Event-Id`.

The path is reserved: a catalogue that declares a tool at it will not mount,
naming the tool, because the listing is answered before any route lookup and
such a tool could never be called.

Every answer that produced a ledger row carries `Garm-Event-Id` — the id of
that row, which is how a caller joins its own record of a call to the ledger's.
That is successes and every refusal the chain decided: the 401, the `not_found`
for a tool you may not see, chain errors, `grant_required`. The refusals
decided before the chain — an unrouted 404, a quarantined package, a body too
large or one that would not unmarshal — produce no row and so carry no id.

A successful answer also carries `Garm-Catalogue-Digest`, naming the catalogue
that served it. Refusals do not carry it today.

An approval may name the task it was given on — `garm_grant.task`, which is
what stops the same payment asked twice sharing one grant. garmd records it on
the ledger row as the `task_id` tag, whether the grant verified or not, and
checks nothing about it: the thing that knows which task is being decided is
the caller that opened it, and a check here would have nothing to compare
against but itself. What matters from this side is that a claim garmd does not
read cannot fail a grant.

Going the other way, the NATS hop carries `Garm-Invocation`: what the caller
asserts — subject and kind, the delegation chain, tenant, correlation id, the
absolute deadline, and the same ledger row id as `call_id` — so a tool learns
who is calling it and a delegated call does not arrive looking direct. It
carries assertions and never credentials: the caller's token does not cross
this boundary in any form, and neither does clearance or compartments.

### Cards are a type garmd projects

Step 8 redacts a response field by field, from the policy its descriptor
carries. That works for every answer whose shape is fixed at compile time and
for no answer whose policy is per row — a queue of approval tasks, or a card
built from another tool's material, cannot say in a `.proto` which row is
whose.

So garmd knows one message type by name: `garm.card.v1.Card`. Wherever a
response is a card, or carries one in a field or a repeated field, step 8 walks
the value after the field plan has run and applies one rule — every element,
fact and choice carries an `access` label of a clearance and compartments, and
the ones this viewer does not reach are **removed**, not masked, with their
paths named in the card's own `disclosure.withheld_fields` and counted on the
ledger row beside the field redactions. A card whose own label the viewer does
not reach is `not_found` as a unary answer and simply absent from a page — the
same closed answer a tool they may not see gets. A section all of whose
children were withheld goes whole.

Two things make that safe to hand a tool. An element with **no** label is read
at the policy of whatever encloses it — the section it sits in, or failing
that the endpoint — and never at PUBLIC, so a handler that forgot to label
something cannot thereby publish it. And an element labelled **below** that
floor refuses the whole call with a 500 and `card_invalid` on the ledger row,
naming the element: a card carrying a label looser than the gate it came
through was built against a policy nobody checked, and serving the rest of it
would mean trusting the labels that happen to look right.

The floor is per element, not only per endpoint. A section is a floor for what
is inside it — a child may be labelled higher, never lower — which the
contract's lint checks on a declared *template*, and which is checked again
here because a card a handler built in Go has no template to lint and reaches
a viewer all the same. A child at `INTERNAL` inside a `RESTRICTED` section
clears the endpoint's floor and would otherwise be shown to a reader who
cannot see the heading it sits under.

This is not garmd learning what a card means. It reads the label and nothing
else — not the kinds, not the templates, not `card_role` — and it cannot tell
an approval card from a start card. What it knows is a type, the way it already
knows a `google.protobuf.Timestamp` is a value rather than a structure to
classify.

Steps 1, 2, 3, 6, 8 and 9 of the chain are implemented, and step 5 — human
approval grants, single-use — is implemented and constructed when
`--grant-issuer` is set. Instance authorization (steps 4 and 7) and notify
(step 10) are not implemented, and a catalogue declaring either refuses to
mount rather than being served ungated.

## Checking the minter agrees

The tokens and approval grants this daemon verifies are minted by
[`garm-ai/sts`](https://github.com/garm-ai/sts), which this repository never
imports. Whether the two sides agree is checked by `internal/conformance`: a
suite of cases in `internal/conformance/suites/sts.json` (and a devkit one
beside it) is driven against a running minter over HTTP, and every answer is
verified with this repository's own code. Four kinds of case — `expect`,
`mintError`, `grant` and `grantError` — and each asserts exactly one thing;
`KNOWN-GAPS.md` says what each pins and what none of them reaches.

CI runs it in the `conformance` job of `.github/workflows/ci.yml` against
`sts` at a pinned tag. To run it on a laptop, start devkit as the upstream IdP
and the STS trusting it, then point the suite at both (the job's steps are the
reference for the STS config; pick ports nothing else holds):

```
garmdev idp --addr 127.0.0.1:17450 --audience garm-customer-idp        # devkit, the upstream IdP
sts -config sts-config.yaml                                             # listen: 127.0.0.1:18081, trusting the devkit issuer as kind: employee
go test -tags conformance ./internal/conformance/ -v \
  -suite suites/sts.json -idp http://127.0.0.1:18081 -minter form \
  -client-id conformance-client -client-key conformance-client.key \
  -token-endpoint-aud https://sts.internal.example.com/token \
  -upstream-idp http://127.0.0.1:17450
```

The devkit suite takes the other minter shape:
`garmdev idp --addr 127.0.0.1:17451 --personas examples/personas.yaml`, then
`-suite suites/devkit.json -idp http://127.0.0.1:17451 -minter get`. The run
is behind a build tag and refuses to start without `-suite` and `-idp`: a
conformance run with nothing to check must not report ok.

See `KNOWN-GAPS.md` before putting this in front of anything that matters. It
is kept honest rather than aspirational.

MIT licensed.
