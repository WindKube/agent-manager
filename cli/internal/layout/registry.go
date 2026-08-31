package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ErrUnknownTarget marks a target value this build has never heard of. It is
// the only one of the four target outcomes that is not this build's fault: the
// lockfile's `targets` array is advisory to the client and the hub may add a
// value after this binary shipped.
var ErrUnknownTarget = errors.New("unknown target")

// ErrWithdrawnTarget marks a target the contract names but that nothing can
// ever implement. See withdrawnTargets.
var ErrWithdrawnTarget = errors.New("withdrawn target")

// ErrNoWritableTarget marks a profile whose entire advisory target list is
// unwritable by this build. It is a hard failure, and the reason is the whole
// point of gate R2: a sync that installs nothing while exiting 0 is the worst
// failure this tool has. "None of the targets you asked for exist here" must
// never be reported as a successful sync of zero packages.
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
	// HomeDir is the invoking user's home directory, absolute. internal/cmd has
	// already refused an unset or unwritable home (FR-039) before this is
	// reached; this package only checks that it is usable for path building.
	HomeDir string

	// ClaudeConfigDir is the raw CLAUDE_CONFIG_DIR value, empty when unset. It
	// is the ONLY environment variable that relocates claude-code's skills
	// root: R2's negative control showed XDG_CONFIG_HOME is not read at all,
	// despite 30 references to it in the agent's binary, so an XDG-first
	// resolver — the obvious thing to write on Linux — installs to a directory
	// the agent never opens.
	ClaudeConfigDir string
}

// constructors is the registry. Every value is FALLIBLE and construction
// happens on demand: gate R2 requires the registry to tolerate a target whose
// layout is not settled, which a package-level init() map of built targets
// cannot do.
//
// SHIPPING CODEX IS A CHANGE TO NewCodex AND NOTHING ELSE. Its row is already
// here, its root is already CodexUserSkillsRoot, and the Target it would return
// is the same skillTarget claude-code uses — both are the same Agent Skills
// directory format. NewCodex returns ErrR2Unresolved until someone plants a
// skill in ~/.agents/skills and watches Codex list it.
var constructors = map[record.Target]func(Config) (Target, error){
	record.TargetClaudeCode: newClaudeCodeTarget,
	record.TargetCodex:      newCodexTarget,
}

// withdrawnTargets are values the frozen contract's `targets` enum still
// carries that nothing will implement, with the reason a caller should print.
//
// `agents-md` is here rather than in constructors because it was never a
// capability that could be built: agents.md documents a repository-root file
// and nested per-package copies with nearest-wins, and no per-user location at
// all — the open proposal to standardise one is itself the proof there is none.
// One shared markdown file cannot be installed per package (FR-020), marked
// with a package and version (FR-022), given a distinct directory per publisher
// (FR-023), swapped by rename (FR-024) or pruned by path (FR-028).
//
// It is NOT a hard failure, and the split from codex is the important decision
// in this file. A gated target is one awaiting a MEASUREMENT: the user asked
// for codex, codex has a plausible layout, and writing to the wrong one of two
// candidate directories would report success and do nothing — so it refuses,
// loudly, and the user can fix it by disabling codex. A withdrawn target is one
// awaiting a DESIGN, on both sides, and there is nothing the user can do about
// it; the lockfile schema's own example targets list is
// `["claude-code", "agents-md"]`, so refusing the sync would make the seeded
// catalogue unsyncable over a value the hub itself suggests. The contract calls
// `targets` advisory to the client and expects the client to intersect and
// report the difference, which is exactly what Selection.Withdrawn is for.
var withdrawnTargets = map[record.Target]string{
	"agents-md": "agents-md was withdrawn from the contract: the convention documents only a repository-root " +
		"AGENTS.md and no per-user location, and one shared file cannot be installed per package, marked with a " +
		"package and version, given its own directory, swapped atomically or pruned by path",
}

// Registry resolves a contract target value to something that produces paths.
type Registry struct{ cfg Config }

// NewRegistry validates the config. A relative HomeDir or CLAUDE_CONFIG_DIR is
// refused rather than joined with a working directory: every destination this
// package returns must be absolute, because the record stores absolute paths
// and a relative one would be resolved against whatever directory a later
// process happened to be in.
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

// Resolve builds one target, or explains why it cannot.
//
// THERE IS DELIBERATELY NO (Target, bool) FORM, here or anywhere in this
// package. A comma-ok lookup says "absent", the caller writes
// `if t, ok := reg.Get(name); ok { install(t) }`, and a target whose layout
// research never finished silently becomes a target nobody asked about — the
// command exits 0 having written nothing under it. That is precisely the
// warn-and-continue failure gate R2 exists to stop, so the only accessor
// returns an error the caller has to deal with, and the error says which class
// of unwritable it is: ErrR2Unresolved, ErrWithdrawnTarget or ErrUnknownTarget.
func (r *Registry) Resolve(name record.Target) (Target, error) {
	if construct, ok := constructors[name]; ok {
		t, err := construct(r.cfg)
		if err != nil {
			return nil, err
		}
		if t == nil {
			// A constructor returning (nil, nil) would hand every caller a nil
			// Target that panics on first use, so it is a bug here rather than
			// a nil check at every call site.
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
// only ever returned with a nil error, so a caller cannot read Writable without
// having dealt with the refusals.
type Selection struct {
	// Writable is the targets to install under, in the order requested and
	// deduplicated. Never empty in a successful Selection.
	Writable []Target

	// Withdrawn and Unknown are the difference between what the profile named
	// and what was written. FR-011's spirit and the contract's "advisory to the
	// client" both require reporting them rather than dropping them, and
	// Reasons carries the message to print for each.
	Withdrawn []record.Target
	Unknown   []record.Target

	// Reasons maps every Withdrawn and Unknown value to the sentence explaining
	// it, so the caller reports the hub's vocabulary with this build's reason
	// and never invents its own wording.
	Reasons map[record.Target]string
}

// Select intersects a lockfile's advisory `targets` array with this build.
//
// The wire values arrive as strings rather than as record.Target because a
// value this build does not know is, by definition, not a valid record.Target —
// typing the input would force the caller to launder an unknown value through
// the type that is supposed to mean "the contract's vocabulary".
//
// Three outcomes, and each is non-silent:
//
//   - A target whose layout gate is open (codex) is a HARD refusal wrapping
//     layout.ErrR2Unresolved and naming the target. Never a skip.
//   - A withdrawn or unknown target lands in Selection and must be reported.
//   - An empty writable set is ErrNoWritableTarget, even if every named target
//     was merely unknown. Installing nothing is not a successful sync.
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
			// ErrR2Unresolved and anything else a constructor refuses with. The
			// error is returned as-is so the caller surfaces the constructor's
			// own explanation, which is where R2's evidence lives.
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
// sorted. It INCLUDES a target whose constructor refuses: the set is this
// build's vocabulary, which is what an error about an unrecognised value has to
// list, and it is deliberately not the same set as writableNames.
func KnownTargetNames() []string {
	out := make([]string, 0, len(constructors))
	for name := range constructors {
		out = append(out, string(name))
	}
	sort.Strings(out)
	return out
}

// writableNames is the targets that actually construct under this config,
// sorted. It is computed by trying, not by a second list of "the ones that
// work": a hand-maintained list is how a message ends up telling a user their
// build writes codex when its constructor refuses.
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
// `<root>/<dir>/SKILL.md`, one level deep — which is both shipped targets and
// the reason codex needs no second implementation of anything in this file.
type skillTarget struct {
	name record.Target
	root string

	// validateDir is the target's own extra refusals on top of ValidateDirName,
	// nil when the target has none measured. claude-code has a measured set
	// (`synced` is silently skipped by the agent); codex's is unknown, and R2's
	// outstanding measurement owes it.
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
	// Project scope is not an install destination. ClaudeCode derives
	// <project>/.claude/skills and the agent does read it, but FR-020 confines
	// installs to the invoking user's home and a project tree usually is not
	// there — so no project root is passed, rather than passing one and hoping
	// the containment check catches it later.
	return &skillTarget{
		name:        record.TargetClaudeCode,
		root:        cc.UserSkillsRoot,
		validateDir: ValidateClaudeCodeSkillDirName,
	}, nil
}

func newCodexTarget(cfg Config) (Target, error) {
	// NewCodex is the R2 gate and refuses by design, so the rest of this
	// function is unreachable today. It is written out anyway because that is
	// what makes shipping codex a change to NewCodex alone: the root is already
	// the documented one and the Target is the same skillTarget claude-code
	// uses. What is still owed when the gate closes is codex's own reserved
	// directory names, which is why validateDir stays nil rather than borrowing
	// claude-code's measured set — `synced` is a claude.ai convention and
	// asserting it of Codex would be a guess dressed as a measurement.
	if _, err := NewCodex(cfg.HomeDir, ""); err != nil {
		return nil, err
	}
	return &skillTarget{name: record.TargetCodex, root: CodexUserSkillsRoot(cfg.HomeDir)}, nil
}
