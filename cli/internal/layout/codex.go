package layout

import (
	"fmt"
	"path/filepath"
)

// Target `codex` — documented but not observed; unshipped, gated on one
// measurement. OpenAI's current documentation places the user-scope skills
// root at $HOME/.agents/skills/<name>/SKILL.md, the same Agent Skills format
// claude-code reads. That is the only in-scope row: the repo-scope roots are
// project trees outside the user's home, and the admin row needs root.
//
// It is gated rather than shipped because the path recently moved and the
// stale answer (~/.codex/skills) is still the widely published one; whether
// that path is still read as a fallback, and which one an installed Codex
// version actually reads, is unconfirmed. Writing to the wrong one would
// report success while installing nothing. Codex was not available in this
// environment to test.
//
// MCP servers are out of scope structurally: a Codex MCP server is a table
// inside ~/.codex/config.toml, a file the user owns and hand-edits, which
// cannot be swapped atomically by rename or pruned without touching a key
// amctl may not have written.
const (
	// CodexHomeEnv relocates Codex's config directory only; it is not the
	// skills root, which is under the OS home directory.
	CodexHomeEnv = "CODEX_HOME"

	// CodexHomeDirName is the config directory relative to the user's home
	// when CodexHomeEnv is unset.
	CodexHomeDirName = ".codex"

	// codexAgentsDirName is the cross-tool skills root documented by OpenAI.
	codexAgentsDirName = ".agents"
)

// CodexUserSkillsRoot is the user-scope skills root OpenAI documents,
// relative to the OS home directory (not under CodexHomeEnv). A real
// function rather than a constant so closing the gate is one line in
// NewCodex.
func CodexUserSkillsRoot(homeDir string) string {
	return filepath.Join(homeDir, codexAgentsDirName, skillsSubdir)
}

// Codex resolves paths for the `codex` target. UserSkillsRoot is populated
// only once the gate is closed; until then NewCodex never returns a value.
type Codex struct {
	// UserSkillsRoot is $HOME/.agents/skills.
	UserSkillsRoot string
}

// NewCodex refuses to build the target until the layout above is confirmed
// against a real Codex installation.
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
