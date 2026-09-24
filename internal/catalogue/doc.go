// Package catalogue loads the artifact that says which tools this process
// serves.
//
// garmd does not know its tools at build time. It reads a catalogue — a
// FileDescriptorSet plus a header naming the annotation schema version, the
// declared compartments and tool sets, the producer and the build — and serves
// exactly what that artifact declares.
//
// The consequences the rest of the daemon depends on:
//
//   - The digest is computed over the artifact bytes BEFORE anything is
//     parsed. Digesting after parsing would record what garmd understood
//     rather than what it was handed.
//
//   - Identity is the pair (binary version, catalogue digest), reported at
//     startup, on the health endpoint and on every ledger event. That pair is
//     what replaces "the catalogue is the version" now that the catalogue is
//     not compiled in.
//
//   - Loading fails closed. A descriptor set with an unresolved import, or an
//     annotation schema version outside this binary's window, is a startup
//     failure naming both versions — never a partial load. Serving the part of
//     a policy document one understands is failing open by construction, and
//     the annotations a binary cannot parse are disproportionately the new
//     ones, which are the ones that restrict.
//
//   - The version window is scoped to garm.tool.v1 and IGNORES every other
//     extension namespace. Without that, a catalogue carrying agent
//     annotations would be refused at boot, and garmd would have acquired
//     knowledge of agents through an error message.
//
// See the design record: specs/2026-09-25-public-split-design.md §1 and its
// Stack A, and decisions/2026-09-25-garmd-does-not-know-about-agents.md.
package catalogue
