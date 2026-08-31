package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// AsideSuffix is record.AsideSuffix, re-exported so no call site in this package
// retypes the literal. There is exactly one definition of it in the CLI, and
// that is what makes an entry's removable set computable rather than
// discoverable: record.Entry.RemovablePaths() is {Dest, Dest+AsideSuffix}, so
// FR-028 holds by construction. A second literal here is how the swap and the
// prune drift apart and leave an aside nothing ever removes.
const AsideSuffix = record.AsideSuffix

// ErrCrossDevice marks a staged tree that cannot be renamed onto the
// destination because the two are on different filesystems.
//
// There is deliberately NO recursive-copy fallback. A copy is not atomic, so a
// fallback would silently invert the single requirement this code exists for
// (FR-024): a destination that can be observed half-written. Failing the entry
// and naming both paths is the correct outcome — the fix is to put the staging
// directory on the destination's filesystem, which layout.StagingRoot already
// does, so reaching this error means a mount point or a symlink sits between
// them.
var ErrCrossDevice = errors.New("staged tree is on a different filesystem from the destination")

// ErrStagingPlacement marks a staged tree that is not underneath the
// destination's parent directory. See relInParent.
var ErrStagingPlacement = errors.New("staged tree is not a sibling of the destination")

// SwapResult reports what one swap did, including the two things that can fail
// without failing the install.
type SwapResult struct {
	// Dest and Aside are the two paths this swap touched, and together they are
	// exactly record.Entry.RemovablePaths() for the entry.
	Dest  string
	Aside string

	// Reclaimed says step 1 found a leftover aside with no destination beside it
	// and moved it back: an earlier run of this entry died in the one window
	// where the destination is absent. Worth reporting — it means a previous
	// sync was interrupted mid-install.
	Reclaimed bool

	// DiscardedAside says step 1 found a leftover aside with a destination
	// already in place and removed it: an earlier run died after the new version
	// was installed but before its aside was cleaned up.
	DiscardedAside bool

	// SyncDirErr is step 4's failure, if any. NON-FATAL: the new version is
	// already in place and readable, and the record is written after the swap, so
	// a lost rename loses the record write with it rather than leaving the record
	// claiming an entry that is not there. The fsync narrows that window; it does
	// not create the safety.
	SyncDirErr error

	// RemoveAsideErr is step 5's failure, if any. NON-FATAL: the new version is
	// already in place, so failing the entry here would report a broken install
	// for a working one. See LeftoverAside.
	RemoveAsideErr error
}

// LeftoverAside is the path step 5 could not remove, or "" when there is none.
// It is the same path record.Entry.RemovablePaths() already covers, so nothing
// has to remember it across runs and no glob is ever needed to find it.
//
// Two things remove it, and BOTH are needed: the next swap of this entry
// discards it at step 1, and Apply's sweep retries it at the end of every run
// that mentions the entry. The sweep is not redundant — after the record write
// the entry is Unchanged on every later run, so without it a leftover on a
// converged machine would never be looked at again.
func (r SwapResult) LeftoverAside() string {
	if r.RemoveAsideErr != nil {
		return r.Aside
	}
	return ""
}

// Swap installs the staged tree at staging as dest, atomically per entry
// (FR-024), by gate R3's five-step sequence. staging must be inside dest's
// parent directory — layout.StagingRoot builds such a path — and is consumed by
// a successful swap.
//
// Every rename, remove, stat and open goes through an *os.Root opened on dest's
// parent, so no symlink in or above the destination can move a step of the
// sequence out of that directory. Root.Rename and os.Rename agree on all five
// destination shapes — absent nil, empty dir EEXIST, non-empty dir EEXIST, file
// ENOTDIR, symlink-to-dir ENOTDIR — so the root changes none of the sequence's
// semantics.
//
// What Swap deliberately does NOT do:
//
//   - It does not Stat-then-branch on whether dest exists. That would be two
//     code paths — a three-step swap with no old version, a five-step swap with
//     one — plus a TOCTOU window between the stat and the rename. Tolerating
//     ENOENT at step 2 makes the no-old-version case the same code path.
//   - It does not fall back to a recursive copy across filesystems. See
//     ErrCrossDevice.
//   - It does not follow a symlink at dest, and it does not refuse one either.
//     The link itself is renamed aside and then removed, so nothing is written
//     through it — which is the FR-020 half of the decision, since following one
//     is exactly how amctl would write outside the home without ever
//     constructing a path outside it. The GUARD is the caller's: a symlink at a
//     destination is by definition not something amctl wrote (extraction refuses
//     symlink members, FR-019), so apply must refuse the entry under
//     FR-028/FR-029 unless --force is given, and --force must name the link it
//     destroys. Swap is unconditional by design.
//   - It does not check that dest is inside the invoking user's home. FR-020 is
//     a check on the RESOLVED path and belongs to the caller, before anything is
//     opened.
//   - It does not write the installation record. The record is written after the
//     swap, never before: a record claiming an entry that is not on disk causes a
//     spurious removal attempt, while an entry on disk with no record is merely
//     re-installed next run.
func Swap(staging, dest string) (SwapResult, error) {
	parent, name, err := splitDest(dest)
	if err != nil {
		return SwapResult{}, err
	}
	res := SwapResult{Dest: dest, Aside: dest + AsideSuffix}
	asideName := name + AsideSuffix

	stagingName, err := relInParent(parent, staging, dest)
	if err != nil {
		return res, err
	}

	root, err := os.OpenRoot(parent)
	if err != nil {
		return res, fmt.Errorf("open the parent directory of %s: %w", dest, err)
	}
	defer func() { _ = root.Close() }()

	// STEP 1 — reclaim or discard a leftover aside from an earlier interrupted
	// swap. FATAL: an aside in the way makes step 2 fail forever, since Go
	// refuses any existing directory as a rename destination, empty or not.
	//
	// It RECLAIMS rather than discards when dest is absent. A crash between steps
	// 2 and 3 leaves the aside holding a complete old version — rename is atomic,
	// so it is never partial — and discarding it would destroy the only copy of
	// the version the record claims, leaving this run's step 3 nothing to roll
	// back to.
	if _, lerr := root.Lstat(asideName); lerr == nil {
		_, destErr := root.Lstat(name)
		switch {
		case errors.Is(destErr, fs.ErrNotExist):
			if rerr := root.Rename(asideName, name); rerr != nil {
				return res, fmt.Errorf("reclaim leftover %s: %w", res.Aside, rerr)
			}
			res.Reclaimed = true
		default:
			// dest is there, so the aside is a superseded duplicate from a crash
			// after step 3. dest is authoritative.
			if rerr := root.RemoveAll(asideName); rerr != nil {
				// Naming it as something the operator may delete matters: this
				// is fatal for the entry and stays fatal on every later run
				// until the directory goes, and the aside is never a live
				// install — it is a superseded copy this swap already replaced.
				return res, fmt.Errorf("discard stale %s: %w; it is a leftover copy of an earlier version "+
					"and is safe to delete by hand, and no change to this entry can be applied until it is gone",
					res.Aside, rerr)
			}
			res.DiscardedAside = true
		}
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return res, fmt.Errorf("inspect %s: %w", res.Aside, lerr)
	}

	// STEP 2 — move the old version aside. ENOENT means there was no old version,
	// which is not an error.
	if rerr := root.Rename(name, asideName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return res, fmt.Errorf("move %s aside: %w", dest, rerr)
	}

	// STEP 3 — move the staged tree into place. dest is absent here, which is the
	// only shape os.Rename accepts for a directory on any platform, and is why
	// step 2 is not a nicety but the whole mechanism.
	//
	// FATAL WITH ROLLBACK: after step 2 the machine is changed, so FR-015's
	// "leave the machine unchanged for it" needs the old version put back before
	// the error is returned. A crash cannot do this, which is what step 1 is for.
	if rerr := root.Rename(stagingName, name); rerr != nil {
		wrapped := crossDevice(rerr, staging, dest)
		if _, serr := root.Lstat(name); errors.Is(serr, fs.ErrNotExist) {
			if back := root.Rename(asideName, name); back != nil && !errors.Is(back, fs.ErrNotExist) {
				return res, fmt.Errorf("install %s: %w (rolling %s back failed too: %w)",
					dest, wrapped, res.Aside, back)
			}
		}
		return res, fmt.Errorf("install %s: %w", dest, wrapped)
	}

	// STEP 4 — fsync dest's parent so step 3's directory entry survives a power
	// loss. NON-FATAL. This makes the directory ENTRY durable, not the file
	// CONTENT underneath it: on a delayed-allocation filesystem a power loss here
	// can leave dest present and full of zero-length files, which is the mixture
	// FR-024 forbids and which no care in this function can prevent. Content
	// durability is Stage's — it fsyncs every extracted file before handing the
	// tree over.
	res.SyncDirErr = syncRootDir(root)

	// STEP 5 — remove the aside. NON-FATAL; see SwapResult.RemoveAsideErr.
	res.RemoveAsideErr = root.RemoveAll(asideName)
	return res, nil
}

// crossDevice restates an EXDEV as a refusal naming both paths, so the message
// says what to change. Anything else passes through unaltered.
func crossDevice(err error, staging, dest string) error {
	if !isCrossDevice(err) {
		return err
	}
	return fmt.Errorf("%w: %s cannot be renamed onto %s (%w); a recursive copy would not be atomic, so the entry is refused rather than copied",
		ErrCrossDevice, staging, dest, err)
}

// isCrossDevice reports whether err is a cross-filesystem rename.
func isCrossDevice(err error) bool {
	return err != nil && errors.Is(err, syscall.EXDEV)
}
