package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Target `claude-code`: a skill is a directory named for its own identity
// (not SKILL.md's frontmatter `name`) containing SKILL.md, under
// $CLAUDE_CONFIG_DIR/skills (user scope, default ~/.claude) or
// <project>/.claude/skills. Plugins are out of scope: Claude Code tracks
// them in agent-owned shared state amctl cannot swap or prune as a directory.
const (
	ClaudeCodeConfigDirEnv  = "CLAUDE_CONFIG_DIR" // only env var that relocates the user-scope root
	ClaudeCodeConfigDirName = ".claude"
	SkillEntryFile          = "SKILL.md"
	skillsSubdir            = "skills"

	// MarkerFileName is the package/version marker beside SKILL.md;
	// dot-prefixed to avoid the spec's conventional names and SKILL.md's
	// relative links. Never a plugin-adopting subdir name; state.json, not
	// this marker, is the pruning authority.
	MarkerFileName = ".agent-manager.json"
)

// claudeCodeReservedSkillDirs: `synced` is claude.ai's skills-sync root,
// where a placed skill is silently skipped.
var claudeCodeReservedSkillDirs = map[string]struct{}{
	"synced": {},
}

// claudeCodePluginAdoptingSubdirs turn a skill directory into a plugin if present.
var claudeCodePluginAdoptingSubdirs = map[string]struct{}{
	".claude-plugin": {},
	"agents":         {},
	"output-styles":  {},
	"themes":         {},
	"hooks":          {},
	"monitors":       {},
	"workflows":      {},
}

// ClaudeCode resolves paths for the `claude-code` target; both roots are
// absolute and only the leaf directory name ever comes from the package.
type ClaudeCode struct {
	UserSkillsRoot    string // $CLAUDE_CONFIG_DIR/skills, or ~/.claude/skills
	ProjectSkillsRoot string // <project>/.claude/skills, or "" with no project root
}

// NewClaudeCode does not read the environment itself, and does not check
// that either root exists or is contained in the home.
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

func (t *ClaudeCode) UserSkillDir(dirName string) (string, error) {
	if err := ValidateClaudeCodeSkillDirName(dirName); err != nil {
		return "", err
	}
	return filepath.Join(t.UserSkillsRoot, dirName), nil
}

// ValidateClaudeCodeSkillDirName refuses rather than sanitises: a rewritten
// name would not match the record it later prunes against.
func ValidateClaudeCodeSkillDirName(dirName string) error {
	switch {
	case dirName == "":
		return fmt.Errorf("skill directory name is empty")
	case dirName != filepath.Base(dirName), strings.ContainsAny(dirName, `/\`):
		return fmt.Errorf("skill directory name %q is a path, not a single directory name", dirName)
	case dirName == "." || dirName == "..":
		return fmt.Errorf("skill directory name %q is a path traversal", dirName)
	case strings.HasPrefix(dirName, "."):
		return fmt.Errorf("skill directory name %q is dot-prefixed and reserved for the agent", dirName)
	}
	if _, reserved := claudeCodeReservedSkillDirs[strings.ToLower(dirName)]; reserved {
		return fmt.Errorf("skill directory name %q is reserved by claude-code and would never load", dirName)
	}
	return nil
}

// IsClaudeCodePluginAdoptingSubdir lets the extractor refuse a bundle that
// would change its own kind on disk.
func IsClaudeCodePluginAdoptingSubdir(name string) bool {
	_, adopting := claudeCodePluginAdoptingSubdirs[strings.ToLower(name)]
	return adopting
}
