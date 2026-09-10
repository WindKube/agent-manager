package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// AsideSuffix is record.AsideSuffix, re-exported so no call site retypes the
// literal: a second definition is how the swap and the prune drift apart.
const AsideSuffix = record.AsideSuffix

// ErrCrossDevice marks a staged tree on a different filesystem from the
// destination. There is deliberately no recursive-copy fallback — a copy
// isn't atomic, so it would let a destination be observed half-written.
var ErrCrossDevice = errors.New("staged tree is on a different filesystem from the destination")

// ErrStagingPlacement marks a staged tree outside the destination's parent; see relInParent.
var ErrStagingPlacement = errors.New("staged tree is not a sibling of the destination")

// SwapResult reports what one swap did, including two non-fatal failures.
type SwapResult struct {
	Dest  string
	Aside string

	Reclaimed      bool // step 1 found an aside with no destination and moved it back
	DiscardedAside bool // step 1 found an aside with the new version already installed
	SyncDirErr     error
	RemoveAsideErr error
}

// LeftoverAside is the path step 5 could not remove, or "" for none;
// retried both at the next swap and by Apply's end-of-run sweep.
func (r SwapResult) LeftoverAside() string {
	if r.RemoveAsideErr != nil {
		return r.Aside
	}
	return ""
}

// Swap installs the staged tree at staging as dest, atomically per entry, by
// a five-step rename sequence, entirely through an *os.Root on dest's parent
// so no symlink above the destination can steer a step outside it. Swap
// never branches on whether dest exists (ENOENT at step 2 covers "no old
// version" without a TOCTOU window), never falls back to a cross-device
// copy, and never follows or refuses a symlink at dest — it renames the
// link aside like anything else and leaves refusing it to the caller.
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

	// STEP 1 — reclaim (dest absent, crash between 2 and 3) or discard
	// (dest present, crash after 3) a leftover aside; fatal if it fails.
	if _, lerr := root.Lstat(asideName); lerr == nil {
		_, destErr := root.Lstat(name)
		switch {
		case errors.Is(destErr, fs.ErrNotExist):
			if rerr := root.Rename(asideName, name); rerr != nil {
				return res, fmt.Errorf("reclaim leftover %s: %w", res.Aside, rerr)
			}
			res.Reclaimed = true
		default:
			if rerr := root.RemoveAll(asideName); rerr != nil {
				return res, fmt.Errorf("discard stale %s: %w; it is a leftover copy of an earlier version "+
					"and is safe to delete by hand, and no change to this entry can be applied until it is gone",
					res.Aside, rerr)
			}
			res.DiscardedAside = true
		}
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return res, fmt.Errorf("inspect %s: %w", res.Aside, lerr)
	}

	// STEP 2 — move the old version aside; ENOENT means there was none.
	if rerr := root.Rename(name, asideName); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return res, fmt.Errorf("move %s aside: %w", dest, rerr)
	}

	// STEP 3 — move the staged tree into place (dest must be absent); on
	// failure, restore the old version before returning.
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

	// STEP 4 — fsync dest's parent for the rename; non-fatal.
	res.SyncDirErr = syncRootDir(root)

	// STEP 5 — remove the aside. Non-fatal; see SwapResult.RemoveAsideErr.
	res.RemoveAsideErr = root.RemoveAll(asideName)
	return res, nil
}

// crossDevice restates an EXDEV as a refusal naming both paths.
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
