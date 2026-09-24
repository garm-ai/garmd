// Package toolplane is the governance chain: ten steps, in a fixed order,
// around every tool call.
//
// The name is kept from the design record rather than shortened to something
// like "chain" — 149 commits of specifications refer to the tool plane and to
// toolplane.Core by those names, and continuity with the corpus is worth more
// than avoiding a mild redundancy with the repository's own purpose.
//
// The chain is not configurable. The moment it is a slice someone assembles,
// "is authorization applied?" stops being a structural fact and becomes a
// property of how that slice was built. What IS pluggable is the
// implementation of a step that must vary — how instance authorization is
// checked, where the ledger goes — never whether a step runs.
//
// See specs/2026-09-24-call-stack-design.md.
package toolplane
