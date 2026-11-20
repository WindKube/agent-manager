package layout

import (
	"fmt"
	"path/filepath"
)

// Target `codex`: skills under $HOME/.agents/skills/<name>/SKILL.md (the
// documented root; ~/.codex/skills is deprecated), confirmed against codex
// 0.170 listing a skill planted there. Everything else Codex reads lives
// under $CODEX_HOME (default ~/.codex): config.toml and agents/*.toml.
const (
	CodexHomeEnv       = "CODEX_HOME" // relocates Codex's config dir, not the skills root
	CodexHomeDirName   = ".codex"
	codexAgentsDirName = ".agents" // cross-tool skills root OpenAI documents
	CodexConfigFile    = "config.toml"
)

func CodexUserSkillsRoot(homeDir string) string {
	return filepath.Join(homeDir, codexAgentsDirName, skillsSubdir)
}

// Codex resolves paths for the `codex` target.
type Codex struct {
	UserSkillsRoot string
	Home           string // $CODEX_HOME, or ~/.codex
}

func NewCodex(homeDir, codexHomeEnv string) (*Codex, error) {
	if homeDir == "" {
		return nil, fmt.Errorf("codex layout: home directory is empty")
	}
	home := codexHomeEnv
	if home == "" {
		home = filepath.Join(homeDir, CodexHomeDirName)
	}
	return &Codex{UserSkillsRoot: CodexUserSkillsRoot(homeDir), Home: home}, nil
}
