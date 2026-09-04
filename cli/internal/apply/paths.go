package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrDest marks a destination this package refuses to touch, before
// anything is opened and before an aside or staging path is derived from it.
var ErrDest = errors.New("unusable install destination")

// dirPerm and markerPerm are requested, not enforced: the umask applies on
// top, so the fingerprint must record the mode from lstat as written, never
// the mode requested here.
const (
	dirPerm    os.FileMode = 0o755
	markerPerm os.FileMode = 0o644
)

// splitDest validates dest and splits it into the parent every operation in
// this package roots at, and the leaf name. The suffix check matters: an
// entry at `<x>.amctl-old` would fall inside `<x>`'s removable set, {dest,
// dest+AsideSuffix}, so pruning `<x>` would delete a live install.
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

// relInParent returns p as a name usable against a root opened at parent,
// refusing anything not underneath it: an atomic rename-install needs the
// staged tree and the destination on one filesystem, which only a sibling
// path guarantees — a path elsewhere may share a filesystem today and fail
// as EXDEV once ~/.claude is a symlink onto another mount.
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

// syncRootDir fsyncs the directory a root is open on; on darwin
// os.File.Sync is F_FULLFSYNC (golang/go#26650), a real barrier there too.
func syncRootDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
