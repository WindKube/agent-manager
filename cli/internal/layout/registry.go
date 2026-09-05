package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrUnknownTarget: the hub may add a target value after this binary shipped.
var ErrUnknownTarget = errors.New("unknown target")

// ErrWithdrawnTarget marks a target the contract names but nothing implements. See withdrawnTargets.
var ErrWithdrawnTarget = errors.New("withdrawn target")

// ErrNoWritableTarget: a no-op sync must never be reported as a success.
var ErrNoWritableTarget = errors.New("no writable target")

// ErrConfig marks a Config that cannot produce absolute destinations.
var ErrConfig = errors.New("invalid layout config")

// Target is one agent's on-disk convention as a source of paths.
type Target interface {
	Name() record.Target
	Root() string                         // absolute directory this agent scans, user scope
	Place(req Request) (Placement, error) // pure
}

// Config is everything the targets need, already resolved by internal/cmd.
type Config struct {
	HomeDir string // absolute; internal/cmd has already refused unset/unwritable

	// ClaudeConfigDir is the raw CLAUDE_CONFIG_DIR value, empty when unset;
	// XDG_CONFIG_HOME is not read by the agent, so it is not a fallback here either.
	ClaudeConfigDir string
}

var constructors = map[record.Target]func(Config) (Target, error){
	record.TargetClaudeCode: newClaudeCodeTarget,
	record.TargetCodex:      newCodexTarget,
}

// withdrawnTargets are contract values nothing implements, with the reason
// to print; unlike a gated target these await a design change, so
// Selection.Withdrawn reports the gap rather than refusing the sync.
var withdrawnTargets = map[record.Target]string{
	"agents-md": "agents-md was withdrawn from the contract: the convention documents only a repository-root " +
		"AGENTS.md and no per-user location, and one shared file cannot be installed per package, marked with a " +
		"package and version, given its own directory, swapped atomically or pruned by path",
}

type Registry struct{ cfg Config }

// NewRegistry refuses a relative HomeDir or CLAUDE_CONFIG_DIR rather than
// joining it with a working directory, since every destination must be absolute.
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

// Resolve builds one target or explains why not; no comma-ok form, so a
// gated target can't silently become one nobody asked about.
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
// build can write; only ever returned with a nil error.
type Selection struct {
	Writable []Target // in requested order, deduplicated; never empty on success

	Withdrawn []record.Target
	Unknown   []record.Target
	Reasons   map[record.Target]string
}

// Select intersects a lockfile's advisory `targets` array with this build. A
// gated target is a hard refusal; withdrawn/unknown land in Selection to be
// reported; an empty writable set is ErrNoWritableTarget regardless.
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
			return Selection{}, err // constructor's own refusal, surfaced as-is
		}
	}
	if len(sel.Writable) == 0 {
		return Selection{}, fmt.Errorf("%w: the profile names %v and this build can write %s",
			ErrNoWritableTarget, names, strings.Join(r.writableNames(), ", "))
	}
	return sel, nil
}

// KnownTargetNames includes a target whose constructor refuses; not the same set as writableNames.
func KnownTargetNames() []string {
	out := make([]string, 0, len(constructors))
	for name := range constructors {
		out = append(out, string(name))
	}
	sort.Strings(out)
	return out
}

// writableNames is computed by trying, not a second hand-maintained list.
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

// skillTarget serves any agent reading the Agent Skills directory format:
// `<root>/<dir>/SKILL.md`, one level deep.
type skillTarget struct {
	name record.Target
	root string

	validateDir func(string) error // extra refusals beyond ValidateDirName, nil if none
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
	return &skillTarget{ // no project root: installs are confined to the invoking user's home
		name:        record.TargetClaudeCode,
		root:        cc.UserSkillsRoot,
		validateDir: ValidateClaudeCodeSkillDirName,
	}, nil
}

// newCodexTarget is unreachable while NewCodex refuses; written out so
// shipping codex is a change to NewCodex alone.
func newCodexTarget(cfg Config) (Target, error) {
	if _, err := NewCodex(cfg.HomeDir, ""); err != nil {
		return nil, err
	}
	return &skillTarget{name: record.TargetCodex, root: CodexUserSkillsRoot(cfg.HomeDir)}, nil
}
