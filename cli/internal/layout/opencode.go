package layout

import "path/filepath"

// Target `opencode`: everything under $XDG_CONFIG_HOME/opencode (default
// ~/.config/opencode): skills/, agents/, commands/ and opencode.json(c).
// OpenCode also reads ~/.claude/skills and ~/.agents/skills, always under
// the home directory regardless of CLAUDE_CONFIG_DIR.
const (
	XDGConfigHomeEnv     = "XDG_CONFIG_HOME"
	openCodeDirName      = "opencode"
	defaultXDGConfigHome = ".config"
)

func OpenCodeConfigDir(homeDir, xdgConfigHome string) string {
	base := xdgConfigHome
	if base == "" {
		base = filepath.Join(homeDir, defaultXDGConfigHome)
	}
	return filepath.Join(base, openCodeDirName)
}

// openCodeAlsoReads are the other skill roots OpenCode loads.
func openCodeAlsoReads(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ClaudeCodeConfigDirName, skillsSubdir),
		CodexUserSkillsRoot(homeDir),
	}
}
