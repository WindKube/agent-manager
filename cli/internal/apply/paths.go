package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrDest marks a destination this package refuses to touch. It fires before
// anything is opened, because the alternative to refusing a malformed
// destination is deriving an aside and a staging path from it and then
// renaming things next to somebody's files.
var ErrDest = errors.New("unusable install destination")

// dirPerm and markerPerm are requested, not enforced: the umask applies on top,
// and that is deliberate. R4 records the fingerprint mode from lstat on the file
// as written, so a mode this process could not actually produce must never be
// forced here.
const (
	dirPerm    os.FileMode = 0o755
	markerPerm os.FileMode = 0o644
)

// splitDest validates a destination and splits it into the parent directory
// every operation in this package is rooted at, and the leaf name inside it.
//
// The suffix check is not tidiness. An entry installed at `<x>.amctl-old` would
// sit inside the removable set of an entry at `<x>` — RemovablePaths is
// {dest, dest+AsideSuffix} — so pruning the first would delete a live install of
// the second. internal/layout guarantees no package is ever placed there and
// record.Validate refuses to write one; this is the same refusal at the moment
// of the write, where it is cheapest to be sure.
func splitDest(dest string) (parent, name string, err error) {
	switch {
	case dest == "":
		return "", "", fmt.Errorf("%w: the destination is empty", ErrDest)
	case !filepath.IsAbs(dest):
		return "", "", fmt.Errorf("%w: %s is not absolute, so it would resolve against the working directory", ErrDest, dest)
	case filepath.Clean(dest) != dest:
		return "", "", fmt.Errorf("%w: %s is not a clean path", ErrDest, dest)
	case strings.HasSuffix(dest, AsideSuffix):
		return "", "", fmt.Errorf("%w: %s ends in %s, which is the swap's aside name", ErrDest, dest, AsideSuffix)
	}

	parentDir, leaf := filepath.Split(dest)
	parent = filepath.Clean(parentDir)
	if leaf == "" || leaf == "." || leaf == ".." || parent == dest {
		return "", "", fmt.Errorf("%w: %s has no directory name to install into", ErrDest, dest)
	}
	return parent, leaf, nil
}

// relInParent returns p as a name usable against a root opened at parent, and
// refuses anything that is not underneath it.
//
// This is the structural half of gate R3's cross-device finding. An atomic
// install by rename requires the staged tree and the destination on one
// filesystem, and the only construction that guarantees that is a sibling —
// hence layout.StagingRoot. A path elsewhere in the tree may happen to be on the
// same filesystem today and will not be on the machine where ~/.claude is a
// symlink into a dotfiles repo on another mount, so it is refused here rather
// than left to fail as EXDEV on somebody else's laptop.
func relInParent(parent, p, dest string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: no staged tree was given for %s", ErrStagingPlacement, dest)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%w: staged tree %s is not an absolute path", ErrStagingPlacement, p)
	}
	rel, err := filepath.Rel(parent, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf(
			"%w: staged tree %s is not inside %s, the parent of %s; the staged tree must be a sibling of the destination or the install cannot be a rename",
			ErrStagingPlacement, p, parent, dest)
	}
	return rel, nil
}

// syncRootDir fsyncs the directory a root is open on.
//
// On darwin Go's os.File.Sync is fcntl(F_FULLFSYNC) rather than fsync(2) — see
// $GOROOT/src/internal/poll/fd_fsync_darwin.go, citing golang/go#26650 — so the
// same call is a real barrier on linux and darwin both.
//
// On Windows it is a documented no-op: there is no directory handle
// FlushFileBuffers accepts, and NTFS metadata durability is not reachable from
// userspace this way. The mitigation there is the write ordering — the
// installation record is written after the swap — not a syscall.
func syncRootDir(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
