package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"agent-manager/internal/worker/scanner/rulepack"
)

const BuiltinOrigin = "built-in"

// Builtin loads the pack embedded in this binary.
func Builtin() (*Pack, error) { return Load(rulepack.FS(), BuiltinOrigin) }

// Open loads the pack at dir, falling back to the embedded pack. A missing
// directory only yields a note, so a lost volume does not stall every scan; a
// directory that exists but fails to load is an error, since someone is editing it.
func Open(dir string) (pack *Pack, note string, err error) {
	if dir == "" {
		pack, err = Builtin()
		return pack, "no rule-pack directory configured; running the built-in pack", err
	}

	manifest := filepath.Join(dir, ManifestFile)
	if _, statErr := os.Stat(manifest); statErr != nil {
		if !os.IsNotExist(statErr) {
			return nil, "", fmt.Errorf("%w: stat %s: %w", ErrPack, manifest, statErr)
		}
		pack, err = Builtin()
		return pack, fmt.Sprintf("%s holds no %s; running the built-in pack", dir, ManifestFile), err
	}

	pack, err = Load(os.DirFS(dir), dir)
	if err != nil {
		return nil, "", err
	}
	return pack, "", nil
}

// FixtureFS returns a rule's fixture tree from the pack that declared it.
func (p *Pack) FixtureFS(rulePath string) (fs.FS, error) {
	if rulePath == "" {
		return nil, fmt.Errorf("%w: fixture path is empty", ErrPack)
	}
	sub, err := fs.Sub(p.fsys, rulePath)
	if err != nil {
		return nil, fmt.Errorf("%w: open fixture %s: %w", ErrPack, rulePath, err)
	}
	if _, err := fs.ReadDir(sub, "."); err != nil {
		return nil, fmt.Errorf("%w: fixture %s is not a directory in this pack: %w", ErrPack, rulePath, err)
	}
	return sub, nil
}
