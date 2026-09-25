// Package record is where a governed call's event goes.
//
// The event's SHAPE is not here — it is in the contract, because a tool call
// and a generation call must produce one record type or "what happened"
// has two answers. Where that record is written is a deployment's business
// and differs per plane, so it is here.
//
// Named record rather than ledger so that a file can import both this and the
// contract's ledger package without one of them needing an alias. Two
// packages called ledger, one holding the shape and one holding the writers,
// is the kind of ambiguity that gets resolved wrongly at three in the morning.
package record
