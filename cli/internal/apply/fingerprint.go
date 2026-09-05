package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrFingerprintAlgo marks a fingerprint this build does not verify: absent
// (an entry installed before T049, or by a build with Fingerprints unset),
// or written by some later algorithm. record.Fingerprint's own contract is
// that either must refuse naming --force rather than be assumed unmodified.
var ErrFingerprintAlgo = errors.New("fingerprint algorithm not recognised")

// TreeFingerprinter is the production Fingerprinter and Verifier: R4's
// closed-set, content-hash fingerprint over an entry's installed tree.
type TreeFingerprinter struct{}

// Hash takes the content half from the staged tree, before the swap. Mode and
// Kind are left zero; Modes fills them in afterwards, from the entry as
// actually written.
func (TreeFingerprinter) Hash(staged *Staged) (record.Fingerprint, error) {
	fp := record.Fingerprint{Algo: record.FingerprintAlgo}
	if len(staged.Files) > 0 {
		fp.Files = make(map[string]record.FileMark, len(staged.Files))
	}
	if len(staged.Dirs) > 0 {
		fp.Dirs = make(map[string]uint32, len(staged.Dirs))
	}
	for _, rel := range staged.Files {
		sum, size, err := sha256File(filepath.Join(staged.Path, filepath.FromSlash(rel)))
		if err != nil {
			return record.Fingerprint{}, fmt.Errorf("fingerprint %s: %w", rel, err)
		}
		fp.Files[rel] = record.FileMark{SHA256: sum, Size: size}
	}
	for _, rel := range staged.Dirs {
		fp.Dirs[rel] = 0
	}
	return fp, nil
}

// Modes fills in the lstat half, read from dest AFTER the swap — never from
// the archive header, per record.FileMark's own contract.
func (TreeFingerprinter) Modes(dest string, fp record.Fingerprint) (record.Fingerprint, error) {
	for rel, mark := range fp.Files {
		info, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			return record.Fingerprint{}, fmt.Errorf("%s: %w", rel, err)
		}
		mark.Mode = uint32(info.Mode().Perm())
		mark.Kind = kindOf(info)
		fp.Files[rel] = mark
	}
	for rel := range fp.Dirs {
		info, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			return record.Fingerprint{}, fmt.Errorf("%s: %w", rel, err)
		}
		fp.Dirs[rel] = uint32(info.Mode().Perm())
	}
	return fp, nil
}

// Modifications is FR-029: every entry-root-relative path under e.Dest whose
// content, size, mode or kind disagrees with e.Fingerprint, plus every path it
// names that is no longer there and every path there it does not name — the
// closed set record.Fingerprint documents. An empty, nil-error result is the
// only positive "unmodified" verdict; an error means unverifiable.
func (TreeFingerprinter) Modifications(e record.Entry) ([]string, error) {
	if e.Fingerprint.Algo != record.FingerprintAlgo {
		return nil, fmt.Errorf("%w: %q", ErrFingerprintAlgo, e.Fingerprint.Algo)
	}
	return modifiedPaths(e.Dest, e.Fingerprint)
}

func kindOf(info fs.FileInfo) string {
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return record.FileKindSymlink
	case info.Mode().IsRegular():
		return record.FileKindRegular
	default:
		return record.FileKindOther
	}
}

// modifiedPaths walks dest and compares it against fp, both directions: a
// path on disk and absent from fp is an addition, a path in fp and absent
// from disk is a removal, and either is a modification alongside a changed
// hash, size, mode or kind.
func modifiedPaths(dest string, fp record.Fingerprint) ([]string, error) {
	seen := make(map[string]bool, len(fp.Files)+len(fp.Dirs))
	var changed []string

	walkErr := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dest, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		seen[rel] = true

		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if want, ok := fp.Dirs[rel]; !ok || uint32(info.Mode().Perm()) != want {
				changed = append(changed, rel)
			}
			return nil
		}

		want, ok := fp.Files[rel]
		if !ok {
			changed = append(changed, rel)
			return nil
		}
		if kindOf(info) != want.Kind || info.Size() != want.Size || uint32(info.Mode().Perm()) != want.Mode {
			changed = append(changed, rel)
			return nil
		}
		sum, _, err := sha256File(path)
		if err != nil {
			return err
		}
		if sum != want.SHA256 {
			changed = append(changed, rel)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	for rel := range fp.Files {
		if !seen[rel] {
			changed = append(changed, rel)
		}
	}
	for rel := range fp.Dirs {
		if !seen[rel] {
			changed = append(changed, rel)
		}
	}
	slices.Sort(changed)
	return changed, nil
}

func sha256File(path string) (sum string, size int64, err error) {
	f, err := os.Open(path) //nolint:gosec // path is entry-root-relative under a recorded, amctl-owned destination
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
