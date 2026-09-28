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
and serves exactly what that artifact declares. A file on disk and an object
in an S3-compatible store are both implemented as a source for that artifact,
though `--catalogue` cannot yet take an `s3://` URL — that flag wiring is a
later task.

Adding a tool is a catalogue rebuild and a restart, not a release of this
binary. Identity is the pair `(binary version, catalogue digest)`, reported at
startup, on the health endpoint and on every ledger event, so *which tools is
this process serving* stays exactly answerable.

A binary reads the current annotation schema and the two previous. Backward is
generous; forward fails closed at boot rather than loading a policy document it
only partly understands.

Identity is configured the same way: `--issuer` and `--jwks` are repeatable and
paired by position, one key set per issuer. A deployment serving an agent
verifies the human's token from its IdP and the runner's from the STS in one
process, and a single key set for both would let either sign for the other.

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

See `KNOWN-GAPS.md` before putting this in front of anything that matters. It
is kept honest rather than aspirational.

MIT licensed.
