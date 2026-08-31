// Package apply is the only package in amctl permitted to mutate the
// filesystem. Everything that decides *what* to write lives in plan and
// layout, which are pure; everything that actually writes lives here. That
// split is what makes "does amctl ever write outside the user's home"
// (FR-020) a question about one package instead of about the codebase.
//
// The package is three stages, in this order, per entry:
//
//	stage  extract the verified bundle into a staging directory
//	swap   replace the destination with the staged tree, atomically (FR-024)
//	prune  remove entries the installation record still claims
//
// What this package deliberately does NOT do:
//
//   - It does not implement a whole-sync transaction. Entries are atomic
//     individually; a sync of twelve entries that fails at the seventh leaves
//     six installed and reports itself as partial. A tree-wide transaction was
//     rejected as disproportionate — the next sync converges.
//   - It does not follow a symlink at an entry's destination. See the R3 gate
//     in swap_test.go for why: following one is how amctl would write outside
//     the home directory without ever constructing a path outside it.
//   - It does not list a directory to decide what to remove. Removal walks the
//     installation record only (FR-028). Listing an agent's directory and
//     deleting what is not in the lockfile deletes hand-written skills.
package apply
