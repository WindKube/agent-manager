package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrUnknownTarget marks a target value this build has never heard of. The
// lockfile's `targets` array is advisory to the client, so the hub may add a
// value after this binary shipped.
var ErrUnknownTarget = errors.New("unknown target")

// ErrWithdrawnTarget marks a target the contract names but that nothing can
// ever implement. See withdrawnTargets.
var ErrWithdrawnTarget = errors.New("withdrawn target")

// ErrNoWritableTarget marks a profile whose entire advisory target list is
// unwritable by this build: a sync that installs nothing must never be
// reported as a successful sync of zero packages.
var ErrNoWritableTarget = errors.New("no writable target")

// ErrConfig marks a Config that cannot produce absolute destinations.
var ErrConfig = errors.New("invalid layout config")

// Target is one agent's on-disk convention, as a source of paths. It is
// deliberately tiny: everything a caller needs about an entry comes back in one
// Placement, so no caller ever assembles a path from parts and no caller has to
// know which parts a given target uses.
type Target interface {
	// Name is the contract's target value.
	Name() record.Target

	// Root is the absolute directory this agent scans, at user scope.
	Root() string

	// Place derives and validates every path for one entry. PURE.
	Place(req Request) (Placement, error)
}

// Config is everything the targets need, already resolved by internal/cmd.
// Nothing here is read from the environment (see the package comment).
type Config struct {
	// HomeDir is the invoking user's home directory, absolute. internal/cmd
	// has already refused an unset or unwritable home before this is reached.
	HomeDir string

	// ClaudeConfigDir is the raw CLAUDE_CONFIG_DIR value, empty when unset.
	// It is the only environment variable that relocates claude-code's skills
	// root; XDG_CONFIG_HOME is not read by the agent despite appearing in its
	// binary, so an XDG-first resolver would install where the agent never looks.
	ClaudeConfigDir string
}

// constructors is the registry. Every value is fallible and construction
// happens on demand, since a target's layout may not yet be settled.
var constructors = map[record.Target]func(Config) (Target, error){
	record.TargetClaudeCode: newClaudeCodeTarget,
	record.TargetCodex:      newCodexTarget,
}

// withdrawnTargets are values the frozen contract's `targets` enum still
// carries that nothing will implement, with the reason a caller should print.
// Unlike a gated target awaiting a measurement, a withdrawn one is awaiting a
// design on both sides, so refusing to sync over it is not the answer: the
// contract calls `targets` advisory and expects the client to intersect and
// report the difference, which is what Selection.Withdrawn is for.
var withdrawnTargets = map[record.Target]string{
	"agents-md": "agents-md was withdrawn from the contract: the convention documents only a repository-root " +
		"AGENTS.md and no per-user location, and one shared file cannot be installed per package, marked with a " +
		"package and version, given its own directory, swapped atomically or pruned by path",
}

// Registry resolves a contract target value to something that produces paths.
type Registry struct{ cfg Config }

// NewRegistry validates the config. A relative HomeDir or CLAUDE_CONFIG_DIR is
// refused rather than joined with a working directory, since every
// destination this package returns must be absolute.
func NewRegistry(cfg Config) (*Registry, error) {
	if cfg.HomeDir == "" {
		return nil, fmt.Errorf("%w: home directory is empty", ErrConfig)
	}
	if !filepath.IsAbs(cfg.HomeDir) {
		return nil, fmt.Errorf("%w: home directory %q is not absolute", ErrConfig, cfg.HomeDir)
	}
	if cfg.ClaudeConfigDir != "" && !filepath.IsAbs(cfg.ClaudeConfigDir) {
		return nil, fmt.Errorf("%w: %s is %q, which is not absolute", ErrConfig, ClaudeCodeConfigDirEnv, cfg.ClaudeConfigDir)
	}
	return &Registry{cfg: Config{
		HomeDir:         filepath.Clean(cfg.HomeDir),
		ClaudeConfigDir: cleanIfSet(cfg.ClaudeConfigDir),
	}}, nil
}

func cleanIfSet(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

// Resolve builds one target, or explains why it cannot. There is
// deliberately no (Target, bool) form: a comma-ok lookup lets a target whose
// layout research never finished silently become a target nobody asked
// about, so the only accessor returns an error the caller has to deal with.
func (r *Registry) Resolve(name record.Target) (Target, error) {
	if construct, ok := constructors[name]; ok {
		t, err := construct(r.cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, fmt.Errorf("target %s: constructor returned no target and no error", name)
		}
		return t, nil
	}
	if why, ok := withdrawnTargets[name]; ok {
		return nil, fmt.Errorf("target %s: %w — %s", name, ErrWithdrawnTarget, why)
	}
	return nil, fmt.Errorf("target %s: %w — this build knows %s; the hub may name a target added after it "+
		"shipped, and the lockfile's target list is advisory to the client",
		name, ErrUnknownTarget, strings.Join(KnownTargetNames(), ", "))
}

// Selection is a lockfile's advisory target list intersected with what this
// build can actually write, plus the difference the caller must report. It is
// only ever returned with a nil error, so a caller cannot read Writable
// without having dealt with the refusals.
type Selection struct {
	// Writable is the targets to install under, in the order requested and
	// deduplicated. Never empty in a successful Selection.
	Writable []Target

	// Withdrawn and Unknown are the difference between what the profile
	// named and what was written; Reasons carries the message for each.
	Withdrawn []record.Target
	Unknown   []record.Target

	Reasons map[record.Target]string
}

// Select intersects a lockfile's advisory `targets` array with this build.
// The wire values arrive as strings, not record.Target, since a value this
// build does not know is by definition not a valid one. A target whose
// layout gate is open is a hard refusal wrapping ErrR2Unresolved; a withdrawn
// or unknown target lands in Selection to be reported; an empty writable set
// is ErrNoWritableTarget even if every named target was merely unknown.
func (r *Registry) Select(names []string) (Selection, error) {
	sel := Selection{Reasons: map[record.Target]string{}}
	seen := map[record.Target]struct{}{}
	for _, raw := range names {
		name := record.Target(raw)
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}

		t, err := r.Resolve(name)
		switch {
		case err == nil:
			sel.Writable = append(sel.Writable, t)
		case errors.Is(err, ErrWithdrawnTarget):
			sel.Withdrawn = append(sel.Withdrawn, name)
			sel.Reasons[name] = err.Error()
		case errors.Is(err, ErrUnknownTarget):
			sel.Unknown = append(sel.Unknown, name)
			sel.Reasons[name] = err.Error()
		default:
			// ErrR2Unresolved and anything else a constructor refuses with,
			// returned as-is so the caller surfaces its own explanation.
			return Selection{}, err
		}
	}
	if len(sel.Writable) == 0 {
		return Selection{}, fmt.Errorf("%w: the profile names %v and this build can write %s",
			ErrNoWritableTarget, names, strings.Join(r.writableNames(), ", "))
	}
	return sel, nil
}

// KnownTargetNames is every target value this build has a constructor for,
// sorted, including one whose constructor refuses; it is deliberately not
// the same set as writableNames.
func KnownTargetNames() []string {
	out := make([]string, 0, len(constructors))
	for name := range constructors {
		out = append(out, string(name))
	}
	sort.Strings(out)
	return out
}

// writableNames is the targets that actually construct under this config,
// sorted, computed by trying rather than a second hand-maintained list.
func (r *Registry) writableNames() []string {
	out := make([]string, 0, len(constructors))
	for name := range constructors {
		if _, err := r.Resolve(name); err == nil {
			out = append(out, string(name))
		}
	}
	sort.Strings(out)
	return out
}

// skillTarget serves any agent that reads the Agent Skills directory format —
// `<root>/<dir>/SKILL.md`, one level deep.
type skillTarget struct {
	name record.Target
	root string

	// validateDir is the target's own extra refusals on top of
	// ValidateDirName, nil when none are known. claude-code's excludes
	// `synced` (silently skipped by the agent); codex's is not yet measured.
	validateDir func(string) error
}

func (t *skillTarget) Name() record.Target { return t.name }
func (t *skillTarget) Root() string        { return t.root }

func (t *skillTarget) Place(req Request) (Placement, error) {
	if req.Kind == "" {
		return Placement{}, fmt.Errorf("target %s: entry %s has no kind", t.name, req.ID)
	}
	if req.Kind != record.KindSkill {
		return Placement{}, fmt.Errorf("target %s: entry %s is a %s: %w — a plugin is registered in state the "+
			"agent owns and rewrites, so it can be neither swapped by rename nor pruned by path, and there is no "+
			"directory to derive",
			t.name, req.ID, req.Kind, ErrKindUnsupported)
	}
	pkg, err := ParsePackageID(req.ID)
	if err != nil {
		return Placement{}, fmt.Errorf("target %s: %w", t.name, err)
	}
	dirName := pkg.DirName()
	if err := ValidateDirName(dirName); err != nil {
		return Placement{}, fmt.Errorf("target %s: entry %s: %w", t.name, req.ID, err)
	}
	if t.validateDir != nil {
		if err := t.validateDir(dirName); err != nil {
			return Placement{}, fmt.Errorf("target %s: entry %s: %w", t.name, req.ID, err)
		}
	}

	dest := filepath.Join(t.root, dirName)
	return Placement{
		Target:        t.name,
		Package:       pkg,
		Version:       req.Version,
		Kind:          req.Kind,
		Root:          t.root,
		DirName:       dirName,
		Dest:          dest,
		EntryFilePath: filepath.Join(dest, SkillEntryFile),
		MarkerPath:    filepath.Join(dest, MarkerFileName),
	}, nil
}

func newClaudeCodeTarget(cfg Config) (Target, error) {
	cc, err := NewClaudeCode(cfg.HomeDir, cfg.ClaudeConfigDir, "")
	if err != nil {
		return nil, err
	}
	// Project scope is not an install destination: installs are confined to
	// the invoking user's home, so no project root is passed here.
	return &skillTarget{
		name:        record.TargetClaudeCode,
		root:        cc.UserSkillsRoot,
		validateDir: ValidateClaudeCodeSkillDirName,
	}, nil
}

func newCodexTarget(cfg Config) (Target, error) {
	// NewCodex refuses by design, so the rest of this function is
	// unreachable today; it is written out so shipping codex is a change to
	// NewCodex alone. validateDir stays nil rather than borrowing
	// claude-code's `synced` exclusion, which is a claude.ai-specific convention.
	if _, err := NewCodex(cfg.HomeDir, ""); err != nil {
		return nil, err
	}
	return &skillTarget{name: record.TargetCodex, root: CodexUserSkillsRoot(cfg.HomeDir)}, nil
}
