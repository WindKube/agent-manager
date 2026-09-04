// Package apply is the only package in amctl permitted to mutate the
// filesystem. Everything that decides *what* to write lives in plan and
// layout, which are pure; everything that actually writes lives here. That
// split is what makes "does amctl ever write outside the user's home" a
// question about one package instead of about the codebase.
//
// The package is three stages, in this order, per entry:
//
//	stage  extract the verified bundle into a staging directory
//	swap   replace the destination with the staged tree, atomically
//	prune  remove entries the installation record still claims
//
// What this package deliberately does not do:
//
//   - It does not implement a whole-sync transaction. Entries are atomic
//     individually; a sync of twelve entries that fails at the seventh leaves
//     six installed and reports itself as partial. A tree-wide transaction
//     was rejected as disproportionate — the next sync converges.
//   - It does not follow a symlink at an entry's destination: see the gate
//     in swap_test.go for why — following one is how amctl would write
//     outside the home directory without ever constructing a path outside it.
//   - It does not list a directory to decide what to remove. Removal walks
//     the installation record only. Listing an agent's directory and
//     deleting what is not in the lockfile deletes hand-written skills.
package apply
