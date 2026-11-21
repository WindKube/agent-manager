// Package plan computes, without performing any action or I/O, what a sync
// would do given the hub's lockfiles, amctl's record and the writable targets.
//
// Output is ordered by content, not input order, so --dry-run stays diffable
// across runs; never range over a map when building output.
package plan
