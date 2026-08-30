package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Target `claude-code` — VERIFIED BY OBSERVATION, both scopes. Ships.
//
// A skill is a directory whose entry file is SKILL.md. The directory name — not
// the frontmatter `name` — is the identity Claude Code advertises the skill
// under, which is what makes FR-023 satisfiable by naming alone.
//
//	<root>/<skill-dir>/SKILL.md   required
//	<root>/<skill-dir>/**         any other files; loaded only on demand
//
// Roots, in the two scopes the agent reads:
//
//	user     $CLAUDE_CONFIG_DIR/skills   ($CLAUDE_CONFIG_DIR defaults to ~/.claude)
//	project  <project>/.claude/skills
//
// Sources (strongest first):
//
//  1. Observed on the machine this gate ran on, Claude Code 2.1.248 (linux/arm64),
//     by planting a skill and asking a headless `claude -p` session to list the
//     skills it could see:
//     - <cwd>/.claude/skills/amctl-probe/SKILL.md      -> listed as `amctl-probe`
//     - $CLAUDE_CONFIG_DIR/skills/amctl-user-probe/    -> listed as `amctl-user-probe`
//     Negative control: $XDG_CONFIG_HOME/claude/skills and $XDG_CONFIG_HOME/skills
//     were NOT read. XDG does not relocate this root; only CLAUDE_CONFIG_DIR does.
//  2. The agent's own help text: `claude plugin init <name>` "Scaffold a new plugin
//     at ~/.claude/skills/<name>/ (auto-loads next session as <name>@skills-dir)".
//  3. The agent's own in-binary documentation: "**Personal** (`~/.claude/skills/<name>/SKILL.md`)
//     — follows you across all repos" / "**This repo** (`.claude/skills/<name>/SKILL.md`)".
//  4. This repository's own working skill, .claude/skills/gh-stack/SKILL.md, which
//     was loaded in the session that wrote this file.
//  5. Format spec: https://agentskills.io/specification — "A skill is a directory
//     containing, at minimum, a `SKILL.md` file" and "A skill directory may contain
//     any files and directories beyond the required `SKILL.md`".
//
// PLUGINS are deliberately out of scope for this target. Claude Code installs them
// under $CLAUDE_CONFIG_DIR/plugins/cache/<marketplace>/<plugin>/<version>/ and
// records each one in $CLAUDE_CONFIG_DIR/plugins/installed_plugins.json, a file the
// agent owns and rewrites. Installing a plugin therefore means editing shared agent
// state, not dropping a directory, so amctl cannot do it atomically (FR-024) or
// prune it safely (FR-028). Skills only, until that is specified.
//
// What this layout does NOT claim: no darwin observation was possible here
// (linux/arm64 only). It is the same code path — CLAUDE_CONFIG_DIR, else the OS
// home dir joined with ".claude" — and no XDG indirection was found for the
// skills root, but SC-009 on darwin is still owed.
const (
	// ClaudeCodeConfigDirEnv is the ONLY environment variable that relocates the
	// user-scope root. Verified: XDG_CONFIG_HOME does not.
	ClaudeCodeConfigDirEnv = "CLAUDE_CONFIG_DIR"

	// ClaudeCodeConfigDirName is the config directory relative to the user's home
	// when ClaudeCodeConfigDirEnv is unset.
	ClaudeCodeConfigDirName = ".claude"

	// SkillEntryFile is the entry file every skill directory must contain. The
	// spelling is case-sensitive on the platforms amctl targets.
	SkillEntryFile = "SKILL.md"

	skillsSubdir = "skills"

	// MarkerFileName answers FR-022 for every target whose unit is a directory: the
	// package/version marker is a dot-prefixed regular file sitting beside SKILL.md,
	// inside the skill directory it describes.
	//
	// Why here and not somewhere else. Verified by observation: a skill directory
	// carrying a sibling `.agent-manager.json` loaded normally, and so did one
	// carrying a `.agent-manager/entry.json` subdirectory — the agent reads SKILL.md
	// and treats everything else as on-demand resources, which the Agent Skills spec
	// also states outright ("A skill directory may contain any files and directories
	// beyond the required `SKILL.md`"). A dotfile additionally never collides with the
	// spec's own conventional names (scripts/, references/, assets/) and never looks
	// like a reference target for SKILL.md's relative links.
	//
	// The three rejected alternatives, and why:
	//   - a subdirectory named hooks/, agents/, workflows/, themes/, monitors/,
	//     output-styles/ or .claude-plugin/ — any of those makes claude-code adopt the
	//     skill as a PLUGIN, granting it lifecycle hooks and MCP servers. See
	//     IsClaudeCodePluginAdoptingSubdir.
	//   - a non-dot file such as MANIFEST.md or VERSION — legal, but it lands in the
	//     same namespace as the skill's own referenced files, so a package that later
	//     ships that name silently loses one of them.
	//   - frontmatter inside SKILL.md (the spec's `metadata` map would take it) —
	//     rejected because amctl would then be rewriting bundle bytes it verified by
	//     digest, which breaks both the digest chain and R4's install fingerprint.
	//
	// The record in ~/.agent-manager/<hub>/state.json stays the authority for pruning
	// (FR-026, FR-028). This marker is the offline, per-directory answer to "where did
	// this come from" and nothing reads it to decide a removal.
	MarkerFileName = ".agent-manager.json"
)

// claudeCodeReservedSkillDirs are directory names that must never be used for a
// skill directory at the user-scope root. `synced` is the claude.ai skills-sync
// root: a skill placed there is silently skipped. Verified — a planted
// .claude/skills/synced/SKILL.md was the one probe of four that did NOT appear in
// the agent's skill list, while its three siblings did.
var claudeCodeReservedSkillDirs = map[string]struct{}{
	"synced": {},
}

// claudeCodePluginAdoptingSubdirs are subdirectory names that, if present inside a
// skill directory, make Claude Code adopt that directory as a *plugin* — lifecycle
// hooks, monitors and MCP servers included — rather than as a plain skill. Read
// from the agent's own guard on exactly this hazard. An FR-022 marker must never be
// placed in one of these, which is why MarkerFileName is a plain dotfile.
var claudeCodePluginAdoptingSubdirs = map[string]struct{}{
	".claude-plugin": {},
	"agents":         {},
	"output-styles":  {},
	"themes":         {},
	"hooks":          {},
	"monitors":       {},
	"workflows":      {},
}

// ClaudeCode resolves paths for the `claude-code` target. Both roots are absolute
// and neither is derived from anything the hub sends, so a hostile lockfile cannot
// steer a write: only the leaf directory name comes from the package.
type ClaudeCode struct {
	// UserSkillsRoot is $CLAUDE_CONFIG_DIR/skills, or ~/.claude/skills.
	UserSkillsRoot string
	// ProjectSkillsRoot is <project>/.claude/skills. Empty when no project root
	// was given: amctl installs per user, and FR-020 forbids writing outside the
	// home directory, so a project root outside the home must be rejected by the
	// caller rather than silently used.
	ProjectSkillsRoot string
}

// NewClaudeCode builds the target from an already-validated home directory and an
// optional CLAUDE_CONFIG_DIR value. It does not read the environment itself and it
// does not check that home is inside the user's home or that either root exists —
// internal/cmd owns home validation (FR-039) and internal/apply owns the
// containment check on the resolved path (FR-020).
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

// ValidateClaudeCodeSkillDirName refuses the names that would make a written skill
// unreadable or reinterpreted. It refuses rather than sanitises: a name amctl
// quietly rewrote would not match the record it prunes against (FR-028).
func ValidateClaudeCodeSkillDirName(dirName string) error {
	switch {
	case dirName == "":
		return fmt.Errorf("skill directory name is empty")
	case dirName != filepath.Base(dirName), strings.ContainsAny(dirName, `/\`):
		return fmt.Errorf("skill directory name %q is a path, not a single directory name", dirName)
	case dirName == "." || dirName == "..":
		return fmt.Errorf("skill directory name %q is a path traversal", dirName)
	case strings.HasPrefix(dirName, "."):
		// A dot-prefixed directory is how the agent hides its own internals
		// (.system, .curated); a package must not be able to write into that space.
		return fmt.Errorf("skill directory name %q is dot-prefixed and reserved for the agent", dirName)
	}
	if _, reserved := claudeCodeReservedSkillDirs[strings.ToLower(dirName)]; reserved {
		return fmt.Errorf("skill directory name %q is reserved by claude-code and would never load", dirName)
	}
	return nil
}

// IsClaudeCodePluginAdoptingSubdir reports whether a directory of this name inside
// a skill directory would turn the skill into a plugin. The extractor uses it to
// refuse a bundle that would change its own kind on disk, and MarkerFileName
// exists so amctl never trips it itself.
func IsClaudeCodePluginAdoptingSubdir(name string) bool {
	_, adopting := claudeCodePluginAdoptingSubdirs[strings.ToLower(name)]
	return adopting
}
