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
	// Dest is the entry's absolute destination. Staging is derived from it and
	// nothing else: layout.StagingRoot(Dest) is a SIBLING of the destination, per
	// gate R3, because an agent directory is frequently a symlink into a dotfiles
	// repo on another mount and same-filesystem staging is the only thing that
	// makes the install a rename at all.
	Dest string

	// Digest is the bundle digest the hub locked and internal/hub verified. It
	// names the staging directory, which makes staging digest-addressed: two
	// entries in one parent cannot collide, and a re-run after a crash re-stages
	// over its own leftover rather than beside it.
	Digest record.Digest

	// Bundle is the verified bundle bytes, which must be the slice
	// internal/cache hashed (hub.Bundle.Bytes). Stage takes []byte and not an
	// io.Reader on purpose: a reader is something a caller could hand over
	// unverified, and FR-014 requires the digest checked before any byte reaches
	// the tree. Nothing here re-checks it — that check has one home.
	Bundle []byte

	// Limits bounds the extraction. The zero value takes internal/archive's
	// defaults, which are the hub's own caps: a bundle the hub would have refused
	// must not become extractable just because it arrived from the hub.
	Limits archive.Limits

	// Marker and MarkerName write FR-022's provenance dotfile INTO the staged
	// tree, so it arrives with the same single rename the rest of the entry does.
	// Both empty skips it.
	//
	// It has to be written here rather than after the swap: a write into dest
	// after the swap is a second mutation with its own window, which is precisely
	// what FR-024 forbids, and it would also fall outside R4's fingerprint of the
	// tree as installed.
	//
	// SKILL.md is never touched. Stamping provenance into it would rewrite bytes
	// just verified by digest and break that fingerprint; the marker is a
	// separate file, and R2 confirmed by observation that a skill directory
	// carrying one loads normally.
	Marker     []byte
	MarkerName string
}

// Staged is a staged tree ready for Swap.
type Staged struct {
	// Path is the staged tree: <dest-parent>/.amctl-staging/sha256-<hex>. Pass it
	// to Swap, which consumes it.
	Path string

	// Root is the staging directory holding Path, shared by every entry under one
	// destination parent.
	Root string

	// Dest is the destination this tree was staged for.
	Dest string

	// Files and Dirs are entry-root-relative, slash-separated paths, in the order
	// the archive presented them, with the marker appended when one was written.
	// Together they are the closed set R4's fingerprint is taken over — a path
	// inside the entry root and absent from both is work a legitimate prune would
	// delete.
	Files []string
	Dirs  []string

	// DecompressedBytes is what the extraction actually produced, measured on the
	// bytes written rather than taken from any archive header.
	DecompressedBytes int64
}

// Stage extracts a verified bundle into a staging directory beside the
// destination, with every internal/archive cap enforced.
//
// What Stage deliberately does NOT do:
//
//   - It does not re-implement extraction, path validation or the caps.
//     internal/archive owns all of it, including the refusal of symlink,
//     hardlink, device and FIFO members (FR-019) and of the plugin-adopting
//     subdirectories that would change a skill into a plugin.
//   - It does not verify the digest. FR-014 puts that before anything reaches
//     this package, in internal/hub, on the bytes as they are written.
//   - It does not check that Dest is inside the invoking user's home. FR-020 is a
//     check on the RESOLVED path and belongs to the caller, before Stage creates
//     any directory.
//   - It does not touch the destination. Nothing in this function writes, renames
//     or removes anything at Dest or its aside; that is Swap's, and keeping the
//     two apart is what makes the install exactly one mutation of the tree.
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

	// A leftover staged tree from an interrupted run must go before extraction:
	// archive.Extract requires its destination to be absent, which is what makes
	// every path component beneath it one this process created.
	if rerr := root.RemoveAll(name); rerr != nil {
		return nil, fmt.Errorf("%w: clear the leftover staged tree at %s: %w", ErrStaging, stagedPath, rerr)
	}

	res, err := archive.Extract(ctx, bytes.NewReader(req.Bundle), stagedPath, req.Limits)
	if err != nil {
		// internal/archive leaves a partial tree behind on purpose and delegates
		// removal here. The removal error is dropped rather than wrapped: masking
		// a refusal behind an unrelated I/O failure is how a security refusal
		// stops being readable.
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

// openStagingRoot creates <parent>/.amctl-staging and returns a root confined to
// it.
//
// The directory is created THROUGH a root on the parent and then lstat-ed through
// that same root, rather than with os.MkdirAll followed by os.OpenRoot on the
// full path. Those look equivalent and are not: os.OpenRoot resolves its own
// argument normally, so a `.amctl-staging` symlink planted by anything else would
// confine the root to wherever it points and every extracted byte would land
// there — outside the home, with no path outside the home ever constructed. That
// is the FR-020 hole this function closes.
//
// The parent chain itself is created with plain os.MkdirAll, which follows
// symlinks deliberately: ~/.claude is frequently a symlink into a dotfiles repo,
// and refusing that would break the common case rather than protect it. FR-020's
// containment check is the caller's, on the resolved path, before Stage runs.
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

// checkMarkerName refuses anything but a single filename, because the name is
// joined onto the staged tree and a caller-supplied `../` would put provenance
// outside the entry — or over another entry's.
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

// writeMarker adds the provenance dotfile to the staged tree.
//
// O_EXCL is the security half: a bundle that shipped a file of this name would
// be forging its own provenance, and the refusal is loud rather than an
// overwrite. It also cannot follow a symlink at the leaf, though the extractor
// refuses symlink members already.
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
	// Content durability is this package's half of R3's split, so a failed fsync
	// fails the entry: a marker whose bytes may not survive a power cut is not
	// provenance. The staged directory's own entry for it is best-effort, for the
	// same reason internal/archive's directory fsyncs are.
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

// OpenRoot returns a root confined to the staged tree, for a caller that has to
// read what was extracted — R4's fingerprint hashes the staged content, before
// the swap, while the extractor's caps have just bounded it.
//
// It is a root and not a path so the reader is confined to the staged tree: a
// caller handed a path could be walked out of it by a symlink the extractor
// refused to create but a concurrent process planted.
func (s *Staged) OpenRoot() (*os.Root, error) {
	root, err := os.OpenRoot(s.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrStaging, s.Path, err)
	}
	return root, nil
}

// Discard removes a staged tree that will not be installed. Callers treat a
// failure as a warning, not as an entry failure: a staged tree that outlives its
// run is re-staged over, not read, by the next one, since the name is the
// digest.
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

// PruneStagingRoot removes the .amctl-staging directory beside dest when it is
// empty, so a completed sync leaves nothing behind but the entries themselves.
//
// It removes the directory only when it holds nothing, and it establishes that by
// reading it rather than by trusting a rename: another entry under the same
// parent may be staged at the same moment, and .amctl-staging is shared between
// them. A caller treats a failure here as a warning — an empty directory left
// behind is tidiness, not correctness.
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
