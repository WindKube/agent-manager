// Package plan answers one question and performs no action: given the hub's
// resolved lockfiles, amctl's own installation record and the set of targets
// this build can write, what would a sync do?
//
// It is the query half of the query/command split (constitution VIII) and the
// value `--dry-run` prints (FR-031). Everything about it follows from that.
//
// # PURE. No I/O, at all
//
// Nothing in this package opens a file, resolves a home directory, reads an
// environment variable, dials a network or consults a clock. `Compute` is a
// function of its three inputs and nothing else, so the plan `--dry-run`
// printed is exactly the plan the subsequent apply executes, and a test can
// construct any transition without a filesystem. A destination path arrives
// as a [DestFunc] supplied by the caller rather than being derived here,
// which keeps internal/layout's environment lookups on the caller's side of
// the boundary.
//
// Two consequences worth stating because both look like omissions:
//
//   - The FR-029 conflict — a managed path modified since installation — is
//     NOT in [Plan.Conflicts] and cannot be. Detecting it means hashing the
//     tree against the recorded R4 fingerprint, which is I/O, and it belongs
//     to internal/apply. What this package contributes is
//     [Change.From].Fingerprinted and [Removal].Fingerprinted: whether the
//     recorded entry can be verified at all. An entry that cannot be must be
//     refused naming --force rather than assumed unmodified, because assuming
//     unmodified is the direction that destroys work.
//   - A profile in the record but absent from Inputs.Lockfiles is left
//     ENTIRELY alone — no removals, no conflicts. Syncing profile A must not
//     prune profile B, and the record is the only thing that knows B exists.
//     Reconciling a profile the caller did not ask about is `prune`'s job and
//     needs the caller's explicit intent.
//
// # FR-009: the hub resolves, this package only reports
//
// The boundary runs between two files, and it is the reason they are two files:
//
//   - compute.go DECIDES. It asks only "are these two versions the same
//     string?" and "is this digest the same 32 bytes?". Equality, never
//     ordering. It contains no notion of newer or older and imports nothing
//     that has one.
//   - direction.go REPORTS. It orders two versions the hub already chose, to
//     label a replacement `upgrade` or `downgrade`. Masterminds/semver may be
//     imported HERE and nowhere else in the CLI (T042b); the [Comparer] seam
//     exists so that swapping it in is one call site.
//
// The property that makes the split real, rather than a naming convention, is
// that the change SET is identical whichever way the comparer answers: add,
// upgrade and downgrade all mean "stage the locked version and swap it in",
// and remove means "unlink what the record claims". A comparer that returned
// nonsense would print the wrong word and write the correct bytes.
// TestTheChangeSetDoesNotDependOnTheVersionComparer asserts exactly that, by
// running Compute twice with the comparer inverted.
//
// # Determinism
//
// `--dry-run` output is read by humans across runs and compared by tests
// across platforms, so the plan is in a total order that depends on the
// inputs' CONTENT and not on their argument order:
//
//   - Add, Upgrade, Downgrade, Unchanged and Remove: by target, then package
//     id, then profile slug.
//   - Conflicts: by kind, then package id, then target, then destination.
//   - Claims inside a conflict or a retention: by profile, then version, then
//     target.
//   - Skipped: by profile, then package id, then the hub's reason.
//
// Maps appear inside Compute only as lookup tables; no output is ever built by
// ranging over one, because Go's map order is deliberately randomised and a
// plan that reordered itself between runs would make every diff unreadable.
package plan
