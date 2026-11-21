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
	Components() ComponentRoots
	AlsoReadsSkillsFrom() []string // other agents' skill roots this agent loads too
}

// ComponentRoots is where an agent reads each kind of plugin component.
type ComponentRoots struct {
	Skills    string
	Agents    string // directory of agent files
	Commands  string // "" when the agent has no command files amctl writes
	ConfigDir string // the agent's own config directory (settings, MCP config)
	MCPConfig string // the file MCP servers are configured in; "" when it is chosen among several
}

// Config is everything the targets need, already resolved by internal/cmd.
type Config struct {
	HomeDir string // absolute; internal/cmd has already refused unset/unwritable

	// ClaudeConfigDir is the raw CLAUDE_CONFIG_DIR value, empty when unset;
	// claude-code does not read XDG_CONFIG_HOME, so it is no fallback here.
	ClaudeConfigDir string

	CodexHome     string // raw CODEX_HOME, empty when unset
	XDGConfigHome string // raw XDG_CONFIG_HOME, empty when unset; only opencode reads it

	// PluginRoot is amctl's own directory for unpacked plugins, one subdirectory
	// per target; empty means this registry routes no plugin.
	PluginRoot string
}

var constructors = map[record.Target]func(Config) (Target, error){
	record.TargetClaudeCode: newClaudeCodeTarget,
	record.TargetCodex:      newCodexTarget,
	record.TargetOpenCode:   newOpenCodeTarget,
}

// withdrawnTargets are contract values nothing implements; Selection reports them rather than refusing the sync.
var withdrawnTargets = map[record.Target]string{
	"agents-md": "agents-md was withdrawn from the contract: the convention documents only a repository-root " +
		"AGENTS.md and no per-user location, and one shared file cannot be installed per package, marked with a " +
		"package and version, given its own directory, swapped atomically or pruned by path",
}

type Registry struct{ cfg Config }

// NewRegistry refuses a relative HomeDir, CLAUDE_CONFIG_DIR or CODEX_HOME since every destination
// must be absolute. A relative XDG_CONFIG_HOME is ignored, as the XDG spec says.
func NewRegistry(cfg Config) (*Registry, error) {
	if cfg.HomeDir == "" {
		return nil, fmt.Errorf("%w: home directory is empty", ErrConfig)
	}
	if !filepath.IsAbs(cfg.HomeDir) {
		return nil, fmt.Errorf("%w: home directory %q is not absolute", ErrConfig, cfg.HomeDir)
	}
	for env, v := range map[string]string{
		ClaudeCodeConfigDirEnv: cfg.ClaudeConfigDir, CodexHomeEnv: cfg.CodexHome, "plugin root": cfg.PluginRoot,
	} {
		if v != "" && !filepath.IsAbs(v) {
			return nil, fmt.Errorf("%w: %s is %q, which is not absolute", ErrConfig, env, v)
		}
	}
	xdg := cfg.XDGConfigHome
	if !filepath.IsAbs(xdg) {
		xdg = ""
	}
	return &Registry{cfg: Config{
		HomeDir:         filepath.Clean(cfg.HomeDir),
		ClaudeConfigDir: cleanIfSet(cfg.ClaudeConfigDir),
		CodexHome:       cleanIfSet(cfg.CodexHome),
		XDGConfigHome:   cleanIfSet(xdg),
		PluginRoot:      cleanIfSet(cfg.PluginRoot),
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

// Select intersects a lockfile's advisory `targets` with this build. Withdrawn and unknown targets
// land in Selection; an empty writable set is ErrNoWritableTarget.
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

	components ComponentRoots
	alsoReads  []string
	pluginRoot string // amctl's unpacked plugins for this target; "" routes none
}

func (t *skillTarget) Name() record.Target           { return t.name }
func (t *skillTarget) Root() string                  { return t.root }
func (t *skillTarget) Components() ComponentRoots    { return t.components }
func (t *skillTarget) AlsoReadsSkillsFrom() []string { return t.alsoReads }

// ValidateSkillDirName applies this target's directory-name rules.
func (t *skillTarget) ValidateSkillDirName(dirName string) error {
	if err := ValidateDirName(dirName); err != nil {
		return err
	}
	if t.validateDir != nil {
		return t.validateDir(dirName)
	}
	return nil
}

// Place routes a skill to its directory under Root, and a plugin to amctl's
// own unpacked copy, from which its components are placed one by one.
func (t *skillTarget) Place(req Request) (Placement, error) {
	if req.Kind == "" {
		return Placement{}, fmt.Errorf("target %s: entry %s has no kind", t.name, req.ID)
	}
	root := t.root
	switch req.Kind {
	case record.KindSkill:
	case record.KindPlugin:
		if t.pluginRoot == "" {
			return Placement{}, fmt.Errorf("target %s: entry %s is a plugin: %w — no plugin directory is configured",
				t.name, req.ID, ErrKindUnsupported)
		}
		root = t.pluginRoot
	default:
		return Placement{}, fmt.Errorf("target %s: entry %s is a %s: %w", t.name, req.ID, req.Kind, ErrKindUnsupported)
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

	dest := filepath.Join(root, dirName)
	return Placement{
		Target:        t.name,
		Package:       pkg,
		Version:       req.Version,
		Kind:          req.Kind,
		Root:          root,
		DirName:       dirName,
		Dest:          dest,
		EntryFilePath: filepath.Join(dest, SkillEntryFile),
		MarkerPath:    filepath.Join(dest, MarkerFileName),
	}, nil
}

func pluginRootFor(cfg Config, t record.Target) string {
	if cfg.PluginRoot == "" {
		return ""
	}
	return filepath.Join(cfg.PluginRoot, string(t))
}

func newClaudeCodeTarget(cfg Config) (Target, error) {
	cc, err := NewClaudeCode(cfg.HomeDir, cfg.ClaudeConfigDir, "")
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(cc.UserSkillsRoot)
	return &skillTarget{ // no project root: installs are confined to the invoking user's home
		name:        record.TargetClaudeCode,
		root:        cc.UserSkillsRoot,
		validateDir: ValidateClaudeCodeSkillDirName,
		components: ComponentRoots{
			Skills:    cc.UserSkillsRoot,
			Agents:    filepath.Join(configDir, "agents"),
			Commands:  filepath.Join(configDir, "commands"),
			ConfigDir: configDir,
			MCPConfig: claudeCodeUserConfigFile(cfg),
		},
		pluginRoot: pluginRootFor(cfg, record.TargetClaudeCode),
	}, nil
}

// claudeCodeUserConfigFile is where `claude mcp add --scope user` writes:
// .claude.json inside CLAUDE_CONFIG_DIR when set, else beside ~/.claude.
func claudeCodeUserConfigFile(cfg Config) string {
	if cfg.ClaudeConfigDir != "" {
		return filepath.Join(cfg.ClaudeConfigDir, ".claude.json")
	}
	return filepath.Join(cfg.HomeDir, ".claude.json")
}

func newCodexTarget(cfg Config) (Target, error) {
	cx, err := NewCodex(cfg.HomeDir, cfg.CodexHome)
	if err != nil {
		return nil, err
	}
	return &skillTarget{
		name: record.TargetCodex,
		root: cx.UserSkillsRoot,
		components: ComponentRoots{
			Skills:    cx.UserSkillsRoot,
			Agents:    filepath.Join(cx.Home, "agents"),
			ConfigDir: cx.Home,
			MCPConfig: filepath.Join(cx.Home, CodexConfigFile),
		},
		pluginRoot: pluginRootFor(cfg, record.TargetCodex),
	}, nil
}

func newOpenCodeTarget(cfg Config) (Target, error) { //nolint:unparam // constructors share one signature
	dir := OpenCodeConfigDir(cfg.HomeDir, cfg.XDGConfigHome)
	skills := filepath.Join(dir, skillsSubdir)
	return &skillTarget{
		name: record.TargetOpenCode,
		root: skills,
		components: ComponentRoots{
			Skills:    skills,
			Agents:    filepath.Join(dir, "agents"),
			Commands:  filepath.Join(dir, "commands"),
			ConfigDir: dir,
		},
		alsoReads:  openCodeAlsoReads(cfg.HomeDir),
		pluginRoot: pluginRootFor(cfg, record.TargetOpenCode),
	}, nil
}
