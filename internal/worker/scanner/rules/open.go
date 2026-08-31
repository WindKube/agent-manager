package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"agent-manager/internal/worker/scanner/rulepack"
)

// BuiltinOrigin is what Pack.Origin reports for the embedded pack.
const BuiltinOrigin = "built-in"

// Builtin loads the pack embedded in this binary.
func Builtin() (*Pack, error) { return Load(rulepack.FS(), BuiltinOrigin) }

// Open resolves the pack the scanner will run: the directory named by
// AGENT_MANAGER_RULEPACK_DIR when one is mounted there, the embedded pack
// otherwise.
//
// A configured directory that is absent is a WARNING and not an error, and that
// is a deliberate choice between two bad failures. Refusing to start would take
// the scanner down over a missing volume and leave every imported version at
// `scanning` for ever (FR-124); loading the embedded pack keeps the queue moving
// with the rules this build shipped, and Pack.Origin plus the returned note make
// the substitution visible in the log and in the pack version. A directory that
// EXISTS but does not load is an error: someone is editing rules there, and
// silently running different ones is the failure that costs a real finding.
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

// FixtureFS returns the bundle tree one of a rule's fixtures names, read out of
// the pack that declared it.
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
