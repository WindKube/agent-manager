package layout

import (
	"fmt"
	"path/filepath"
)

// Target `codex` — gated, not shipped: OpenAI documents the user-scope
// skills root as $HOME/.agents/skills/<name>/SKILL.md, but the previously
// documented ~/.codex/skills is still widely published and unconfirmed as
// dead, and no Codex install was available here to test which one loads.
const (
	CodexHomeEnv       = "CODEX_HOME" // relocates Codex's config dir, not the skills root
	CodexHomeDirName   = ".codex"
	codexAgentsDirName = ".agents" // cross-tool skills root OpenAI documents
)

// CodexUserSkillsRoot is a function, not a constant, so closing the gate is one line in NewCodex.
func CodexUserSkillsRoot(homeDir string) string {
	return filepath.Join(homeDir, codexAgentsDirName, skillsSubdir)
}

// Codex resolves paths for the `codex` target, populated only once the gate is closed.
type Codex struct {
	UserSkillsRoot string
}

// NewCodex refuses to build the target until confirmed against a real Codex install.
func NewCodex(string, string) (*Codex, error) {
	return nil, fmt.Errorf(
		"codex: %w — the layout is documented as $HOME/.agents/skills/<name>/SKILL.md "+
			"(https://learn.chatgpt.com/docs/build-skills) but no Codex was available to "+
			"confirm it reads that directory, and the previously documented root "+
			"~/.codex/skills is still the widely published answer; writing to the wrong "+
			"one reports success and does nothing, so ship only after planting a skill in "+
			"~/.agents/skills and seeing Codex list it",
		ErrR2Unresolved,
	)
}
