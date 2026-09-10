// Package plan answers one question and performs no action: given the hub's
// resolved lockfiles, amctl's own installation record and the set of targets
// this build can write, what would a sync do?
//
// Compute is pure: no I/O, no clock, no environment lookups. A destination
// path arrives as a caller-supplied DestFunc rather than being derived here.
//
// compute.go decides equality between two versions/digests; direction.go
// orders two versions the hub already chose, to label a change upgrade or
// downgrade. The change set is identical either way - only the label differs.
//
// Output is ordered by content, not input order, so --dry-run stays diffable
// across runs (by target/package/profile, conflicts by kind/package/target/
// destination, skips by profile/package/reason). Never range over a map when
// building output - Go's map order is randomised.
package plan
