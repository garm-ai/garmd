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
is this process serving* stays exactly answerable.

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

## Status

`serve` binds a listener and routes tool calls: one route,
`POST /pkg.Service/Method`, dispatched dynamically from the catalogue's
descriptors and answered through the chain.

Beside it is one endpoint that is not a tool. `POST
/garm.v1.ToolCatalogService/ListTools`, with a bearer token and a `{}` body,
answers what this caller may call:

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

A request that breaks its own contract is a 400 whose body lists the
violations this caller may see, `violations: [{field, rule, message}]` beside
the code, so a model can repair the request instead of retrying it unchanged.
A violation is listed when its field is in the input schema this caller was
shown — the same projection `ListTools` sent it, so a field it may not send is
never named — and a cross-field CEL rule only when every field it reads is;
the message is protovalidate's own sentence about the constraint, dropped for
the rule id alone wherever it could carry a value, so the caller's values never
come back to it. The ledger row carries the full detail as before.

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

Going the other way, the NATS hop carries `Garm-Invocation`: what the caller
asserts — subject and kind, the delegation chain, tenant, correlation id, the
absolute deadline, and the same ledger row id as `call_id` — so a tool learns
who is calling it and a delegated call does not arrive looking direct. It
carries assertions and never credentials: the caller's token does not cross
this boundary in any form, and neither does clearance or compartments.

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
