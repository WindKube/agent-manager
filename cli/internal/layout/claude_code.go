package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Target `claude-code`. A skill is a directory whose entry file is SKILL.md;
// the directory name, not the frontmatter `name`, is the identity Claude
// Code advertises the skill under.
//
//	<root>/<skill-dir>/SKILL.md   required
//	<root>/<skill-dir>/**         any other files; loaded only on demand
//
// Roots, in the two scopes the agent reads:
//
//	user     $CLAUDE_CONFIG_DIR/skills   ($CLAUDE_CONFIG_DIR defaults to ~/.claude)
//	project  <project>/.claude/skills
//
// Verified by observation on Claude Code 2.1.248 (linux/arm64) that
// $XDG_CONFIG_HOME does not relocate the skills root; only CLAUDE_CONFIG_DIR
// does. No darwin observation was possible, but the code path is the same.
//
// Plugins are out of scope for this target: Claude Code installs and tracks
// them in agent-owned shared state, which amctl cannot swap atomically or
// prune safely as a plain directory.
const (
	// ClaudeCodeConfigDirEnv is the only environment variable that relocates
	// the user-scope root.
	ClaudeCodeConfigDirEnv = "CLAUDE_CONFIG_DIR"

	// ClaudeCodeConfigDirName is the config directory relative to the
	// user's home when ClaudeCodeConfigDirEnv is unset.
	ClaudeCodeConfigDirName = ".claude"

	// SkillEntryFile is the entry file every skill directory must contain,
	// case-sensitive on the platforms amctl targets.
	SkillEntryFile = "SKILL.md"

	skillsSubdir = "skills"

	// MarkerFileName is the package/version marker: a dot-prefixed regular
	// file beside SKILL.md, verified by observation to load normally as an
	// on-demand resource. A dotfile avoids colliding with the spec's
	// conventional names (scripts/, references/, assets/) or looking like a
	// reference target for SKILL.md's relative links. It must never be a
	// subdirectory name in claudeCodePluginAdoptingSubdirs, or SKILL.md
	// frontmatter, which would mean rewriting digest-verified bundle bytes.
	// state.json stays the authority for pruning; nothing reads this marker
	// to decide a removal.
	MarkerFileName = ".agent-manager.json"
)

// claudeCodeReservedSkillDirs are directory names that must never be used
// for a skill directory at the user-scope root. `synced` is the claude.ai
// skills-sync root: a skill placed there is silently skipped, verified by
// observation.
var claudeCodeReservedSkillDirs = map[string]struct{}{
	"synced": {},
}

// claudeCodePluginAdoptingSubdirs are subdirectory names that, if present
// inside a skill directory, make Claude Code adopt that directory as a
// plugin — lifecycle hooks, monitors and MCP servers included — rather than
// a plain skill. Read from the agent's own guard on this hazard.
var claudeCodePluginAdoptingSubdirs = map[string]struct{}{
	".claude-plugin": {},
	"agents":         {},
	"output-styles":  {},
	"themes":         {},
	"hooks":          {},
	"monitors":       {},
	"workflows":      {},
}

// ClaudeCode resolves paths for the `claude-code` target. Both roots are
// absolute and neither is derived from anything the hub sends, so a hostile
// lockfile cannot steer a write: only the leaf directory name comes from the
// package.
type ClaudeCode struct {
	// UserSkillsRoot is $CLAUDE_CONFIG_DIR/skills, or ~/.claude/skills.
	UserSkillsRoot string
	// ProjectSkillsRoot is <project>/.claude/skills, empty when no project
	// root was given.
	ProjectSkillsRoot string
}

// NewClaudeCode builds the target from an already-validated home directory
// and an optional CLAUDE_CONFIG_DIR value. It does not read the environment
// itself, and it does not check that either root exists or is contained in
// the home; those checks belong to internal/cmd and internal/apply.
func NewClaudeCode(homeDir, configDirEnv, projectRoot string) (*ClaudeCode, error) {
	if homeDir == "" {
		return nil, fmt.Errorf("claude-code layout: home directory is empty")
	}

	configDir := configDirEnv
	if configDir == "" {
		configDir = filepath.Join(homeDir, ClaudeCodeConfigDirName)
	}

	t := &ClaudeCode{UserSkillsRoot: filepath.Join(configDir, skillsSubdir)}
	if projectRoot != "" {
		t.ProjectSkillsRoot = filepath.Join(projectRoot, ClaudeCodeConfigDirName, skillsSubdir)
	}
	return t, nil
}

// UserSkillDir is the destination directory for one skill at user scope.
func (t *ClaudeCode) UserSkillDir(dirName string) (string, error) {
	if err := ValidateClaudeCodeSkillDirName(dirName); err != nil {
		return "", err
	}
	return filepath.Join(t.UserSkillsRoot, dirName), nil
}

// ValidateClaudeCodeSkillDirName refuses the names that would make a written
// skill unreadable or reinterpreted. It refuses rather than sanitises: a
// name amctl quietly rewrote would not match the record it prunes against.
func ValidateClaudeCodeSkillDirName(dirName string) error {
	switch {
	case dirName == "":
		return fmt.Errorf("skill directory name is empty")
	case dirName != filepath.Base(dirName), strings.ContainsAny(dirName, `/\`):
		return fmt.Errorf("skill directory name %q is a path, not a single directory name", dirName)
	case dirName == "." || dirName == "..":
		return fmt.Errorf("skill directory name %q is a path traversal", dirName)
	case strings.HasPrefix(dirName, "."):
		// Dot-prefixed is how the agent hides its own internals (.system, .curated).
		return fmt.Errorf("skill directory name %q is dot-prefixed and reserved for the agent", dirName)
	}
	if _, reserved := claudeCodeReservedSkillDirs[strings.ToLower(dirName)]; reserved {
		return fmt.Errorf("skill directory name %q is reserved by claude-code and would never load", dirName)
	}
	return nil
}

// IsClaudeCodePluginAdoptingSubdir reports whether a directory of this name
// inside a skill directory would turn the skill into a plugin. The extractor
// uses it to refuse a bundle that would change its own kind on disk.
func IsClaudeCodePluginAdoptingSubdir(name string) bool {
	_, adopting := claudeCodePluginAdoptingSubdirs[strings.ToLower(name)]
	return adopting
}
