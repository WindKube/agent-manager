package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/archive"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrStaging marks a staging directory that cannot be prepared, or a request
// this package refuses to stage at all.
var ErrStaging = errors.New("cannot stage bundle")

// StageRequest is one entry's extraction.
type StageRequest struct {
	Dest string // absolute; staging is derived as a sibling for a same-filesystem rename

	Digest record.Digest // names the staging directory so entries can't collide

	Bundle []byte // must already be digest-verified (hub.Bundle.Bytes)

	Limits archive.Limits // zero takes internal/archive's hub-matching defaults

	// Marker and MarkerName write the provenance dotfile into the staged
	// tree; both empty skips it. SKILL.md itself is never touched.
	Marker     []byte
	MarkerName string
}

// Staged is a staged tree ready for Swap.
type Staged struct {
	Path string // <dest-parent>/.amctl-staging/sha256-<hex>
	Root string // the staging directory holding Path
	Dest string

	// Files and Dirs are entry-root-relative paths the fingerprint is taken
	// over; anything inside the entry root and absent from both is what a
	// legitimate prune would delete.
	Files []string
	Dirs  []string

	DecompressedBytes int64
}

// Stage extracts a verified bundle into a staging directory beside the
// destination. It never re-implements archive's extraction or caps, never
// re-verifies the digest, never checks home containment (the caller's job
// before Stage runs), and never touches Dest itself — that's Swap's, so the
// two together are exactly one mutation of the tree.
func Stage(ctx context.Context, req StageRequest) (*Staged, error) {
	parent, _, err := splitDest(req.Dest)
	if err != nil {
		return nil, err
	}
	if req.Digest.IsZero() {
		return nil, fmt.Errorf("%w: %s has no digest, so its staging directory would collide with every other entry's",
			ErrStaging, req.Dest)
	}
	if len(req.Bundle) == 0 {
		return nil, fmt.Errorf("%w: no bundle bytes for %s", ErrStaging, req.Dest)
	}
	if merr := checkMarkerName(req); merr != nil {
		return nil, merr
	}

	name := req.Digest.FileName()
	rootPath := layout.StagingRoot(req.Dest)
	stagedPath := filepath.Join(rootPath, name)

	root, err := openStagingRoot(parent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	// archive.Extract requires its destination absent, so a leftover from an
	// interrupted run must go first.
	if rerr := root.RemoveAll(name); rerr != nil {
		return nil, fmt.Errorf("%w: clear the leftover staged tree at %s: %w", ErrStaging, stagedPath, rerr)
	}

	res, err := archive.Extract(ctx, bytes.NewReader(req.Bundle), stagedPath, req.Limits)
	if err != nil {
		// archive leaves a partial tree on purpose; the removal error is
		// dropped so it can't mask the real refusal.
		_ = root.RemoveAll(name)
		return nil, err
	}

	staged := &Staged{
		Path:              stagedPath,
		Root:              rootPath,
		Dest:              req.Dest,
		Files:             res.Files,
		Dirs:              res.Dirs,
		DecompressedBytes: res.DecompressedBytes,
	}

	if len(req.Marker) > 0 {
		if werr := writeMarker(root, name, req, staged); werr != nil {
			_ = root.RemoveAll(name)
			return nil, werr
		}
	}
	return staged, nil
}

// openStagingRoot creates <parent>/.amctl-staging and returns a root
// confined to it, created and lstat-ed through a root on the parent rather
// than os.OpenRoot on the full path: the latter resolves its own argument
// normally, so a planted `.amctl-staging` symlink would confine extraction
// to wherever it points, outside the home, without ever building that path.
func openStagingRoot(parent string) (*os.Root, error) {
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return nil, fmt.Errorf("%w: create %s: %w", ErrStaging, parent, err)
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrStaging, parent, err)
	}
	defer func() { _ = parentRoot.Close() }()

	if mkErr := parentRoot.Mkdir(layout.StagingDirName, dirPerm); mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
		return nil, fmt.Errorf("%w: create %s: %w", ErrStaging, filepath.Join(parent, layout.StagingDirName), mkErr)
	}
	info, err := parentRoot.Lstat(layout.StagingDirName)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect %s: %w", ErrStaging, filepath.Join(parent, layout.StagingDirName), err)
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%w: %s is a symlink; amctl never creates one there, so extracting through it would write wherever it points",
			ErrStaging, filepath.Join(parent, layout.StagingDirName))
	case !info.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrStaging, filepath.Join(parent, layout.StagingDirName))
	}

	root, err := parentRoot.OpenRoot(layout.StagingDirName)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrStaging, filepath.Join(parent, layout.StagingDirName), err)
	}
	return root, nil
}

// checkMarkerName refuses anything but a single filename: it is joined onto
// the staged tree, and a `../` would put provenance outside the entry.
func checkMarkerName(req StageRequest) error {
	switch {
	case len(req.Marker) == 0 && req.MarkerName == "":
		return nil
	case len(req.Marker) == 0:
		return fmt.Errorf("%w: marker name %q given with no marker bytes", ErrStaging, req.MarkerName)
	case req.MarkerName == "":
		return fmt.Errorf("%w: marker bytes given with no marker name", ErrStaging)
	case req.MarkerName != filepath.Base(req.MarkerName),
		strings.ContainsAny(req.MarkerName, `/\`),
		req.MarkerName == "." || req.MarkerName == "..":
		return fmt.Errorf("%w: marker name %q is not a single filename", ErrStaging, req.MarkerName)
	}
	return nil
}

// writeMarker adds the provenance dotfile to the staged tree. O_EXCL refuses
// loudly rather than overwriting if the bundle itself shipped this name.
func writeMarker(root *os.Root, name string, req StageRequest, staged *Staged) error {
	rel := filepath.Join(name, req.MarkerName)
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, markerPerm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: the bundle for %s already contains %s, which is amctl's provenance marker",
				ErrStaging, req.Dest, req.MarkerName)
		}
		return fmt.Errorf("%w: write %s: %w", ErrStaging, filepath.Join(staged.Path, req.MarkerName), err)
	}
	if _, werr := f.Write(req.Marker); werr != nil {
		_ = f.Close()
		return fmt.Errorf("%w: write %s: %w", ErrStaging, filepath.Join(staged.Path, req.MarkerName), werr)
	}
	// A marker whose bytes might not survive a power cut is not provenance.
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("%w: fsync %s: %w", ErrStaging, filepath.Join(staged.Path, req.MarkerName), serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("%w: close %s: %w", ErrStaging, filepath.Join(staged.Path, req.MarkerName), cerr)
	}
	if d, oerr := root.Open(name); oerr == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	staged.Files = append(staged.Files, req.MarkerName)
	return nil
}

// OpenRoot confines a caller reading the staged tree (e.g. to hash it) so a
// symlink planted after extraction can't walk it back out.
func (s *Staged) OpenRoot() (*os.Root, error) {
	root, err := os.OpenRoot(s.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrStaging, s.Path, err)
	}
	return root, nil
}

// Discard removes a staged tree that will not be installed; a failure is a
// warning, since a leftover is re-staged over by the next run, not read.
func (s *Staged) Discard() error {
	if s == nil {
		return nil
	}
	root, err := os.OpenRoot(s.Root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: open %s: %w", ErrStaging, s.Root, err)
	}
	defer func() { _ = root.Close() }()

	if rerr := root.RemoveAll(filepath.Base(s.Path)); rerr != nil {
		return fmt.Errorf("%w: remove %s: %w", ErrStaging, s.Path, rerr)
	}
	return nil
}

// PruneStagingRoot removes .amctl-staging beside dest, but only when a read
// confirms it holds nothing: it is shared with other entries under the same
// parent, so a rename-based emptiness check would race them.
func PruneStagingRoot(dest string) error {
	parent, _, err := splitDest(dest)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: open %s: %w", ErrStaging, parent, err)
	}
	defer func() { _ = root.Close() }()

	rootPath := layout.StagingRoot(dest)
	d, err := root.Open(layout.StagingDirName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: open %s: %w", ErrStaging, rootPath, err)
	}
	names, rerr := d.Readdirnames(1)
	_ = d.Close()
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		return fmt.Errorf("%w: read %s: %w", ErrStaging, rootPath, rerr)
	}
	if len(names) > 0 {
		return nil
	}
	if remErr := root.Remove(layout.StagingDirName); remErr != nil && !errors.Is(remErr, fs.ErrNotExist) {
		return fmt.Errorf("%w: remove %s: %w", ErrStaging, rootPath, remErr)
	}
	return nil
}
