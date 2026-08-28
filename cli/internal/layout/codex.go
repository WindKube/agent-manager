package layout

import (
	"fmt"
	"path/filepath"
)

// Target `codex` — DOCUMENTED, NOT OBSERVED. Unshipped, gated on one measurement.
//
// The layout, from OpenAI's own current documentation. A skill is a directory whose
// entry file is SKILL.md, the same Agent Skills format claude-code reads:
//
//	<root>/<skill-dir>/SKILL.md   required
//
// Roots, by scope, highest precedence first:
//
//	REPO    $CWD/.agents/skills            "teams can check in skills relevant to a working folder"
//	REPO    $CWD/../.agents/skills         "organizations can check in skills relevant to a shared area in a parent folder"
//	REPO    $REPO_ROOT/.agents/skills      "organizations can check in skills relevant to everyone"
//	USER    $HOME/.agents/skills           "skills checked into the user's personal folder"
//	ADMIN   /etc/codex/skills              "skills checked into the machine or container"
//	SYSTEM  bundled with Codex by OpenAI
//
// Only the USER row is a candidate for amctl: the REPO rows are project trees
// outside the user's home (FR-020) and the ADMIN row needs root, which the design
// forbids. So the one path that matters is $HOME/.agents/skills/<name>/SKILL.md.
//
// Sources:
//
//  1. https://learn.chatgpt.com/docs/build-skills (OpenAI; reached via a 308 from
//     https://developers.openai.com/codex/skills) — the scope table quoted above.
//     The page mentions .codex ONLY for the config file.
//  2. https://learn.chatgpt.com/docs/config-file/config-reference (OpenAI) —
//     user config is ~/.codex/config.toml, project config is .codex/config.toml
//     ("loaded only when you trust the project"), profiles are
//     $CODEX_HOME/profile-name.config.toml. `[[skills.config]]` entries take a
//     `path` (path to a skill folder containing SKILL.md) and `enabled` (bool);
//     they enable/disable and point at skills, they are not the discovery root.
//     MCP servers are declared under `mcp_servers.<id>` in that same TOML.
//  3. https://agentskills.io/specification — the skill directory format, shared
//     with claude-code: SKILL.md required, `name` and `description` required in
//     frontmatter, "A skill directory may contain any files and directories beyond
//     the required `SKILL.md`". So MarkerFileName is safe here for the same reason.
//  4. Corroborating first-hand artefact on the machine this gate ran on: the
//     superpowers 6.3.0 plugin ships both .codex-plugin/plugin.json and
//     .agents/plugins/marketplace.json, i.e. the `.agents/` root is a real
//     cross-tool convention and not a documentation artefact.
//
// WHY THIS IS GATED RATHER THAN SHIPPED. The path moved, recently, and the stale
// one is still the top web result. Two independent December-2025 accounts —
// https://blog.fsck.com/2025/12/19/codex-skills/ and
// https://www.mdskills.ai/learn/where-are-codex-cli-skills-stored — both state
// ~/.codex/skills/ (and ./.codex/skills/ for projects) with no hint of deprecation.
// OpenAI's current docs say $HOME/.agents/skills and mention .codex only for
// config.toml. Whether ~/.codex/skills is still read as a fallback is unknown, and
// which of the two a given installed Codex version reads is unknown. A CLI written
// against the December path would today write to a directory Codex does not read
// and report success — precisely the failure FR-021 exists to prevent — so a
// documented path whose predecessor died within nine months does not clear the bar
// on documentation alone.
//
// Codex is not installed on the machine this gate ran on (no ~/.codex, no
// ~/.agents, no `codex` on PATH) and running it needs credentials this environment
// does not have, so the measurement could not be taken here.
//
// WHAT RESOLVES IT — one measurement, on any machine with Codex signed in:
//
//	mkdir -p ~/.agents/skills/amctl-probe
//	printf -- '---\nname: amctl-probe\ndescription: R2 probe. Use when the user says amctl-probe.\n---\n# amctl-probe\n' \
//	  > ~/.agents/skills/amctl-probe/SKILL.md
//	touch ~/.agents/skills/amctl-probe/.agent-manager.json   # the FR-022 marker must not break loading
//	# start codex and confirm amctl-probe appears in its skills list
//
// Then repeat with ~/.codex/skills/amctl-probe to learn whether the old root is
// still live, record the Codex version with both answers, and flip
// CodexUserSkillsRoot / the constructor below. Two further unknowns to settle in
// the same sitting, because each is a silent-failure candidate:
//   - Scan depth. The December accounts say the directory is scanned exactly one
//     level deep and not recursively; OpenAI's current page does not say. If amctl
//     ever nests, a nested skill would silently not load.
//   - Frontmatter. The Agent Skills spec requires YAML frontmatter and OpenAI's page
//     says SKILL.md "must include `name` and `description` metadata", but Claude
//     Code's own Codex importer refuses to translate a Codex SKILL.md that starts
//     with `---`, on the grounds that "Codex treats SKILL.md as plain text, so any
//     YAML frontmatter is Claude-Code-only". Those cannot both be true of the same
//     Codex version; one of them is stale.
//
// PLUGINS / MCP: out of scope, and structurally so. A Codex MCP server is a
// `mcp_servers.<id>` table inside ~/.codex/config.toml — a file the user owns and
// hand-edits. Installing one means a TOML rewrite, which cannot be made atomic by
// rename (FR-024) and cannot be pruned without removing a key amctl may not have
// written (FR-028). Skills only.
const (
	// CodexHomeEnv relocates Codex's config directory. It is NOT the skills root:
	// the skills root is under the OS home directory, not under CODEX_HOME.
	CodexHomeEnv = "CODEX_HOME"

	// CodexHomeDirName is the config directory relative to the user's home when
	// CodexHomeEnv is unset. Config only — config.toml lives here.
	CodexHomeDirName = ".codex"

	// codexAgentsDirName is the cross-tool skills root documented by OpenAI.
	codexAgentsDirName = ".agents"
)

// CodexUserSkillsRoot is the user-scope skills root OpenAI documents, relative to
// the OS home directory. It is a real function rather than a recorded constant so
// that closing the gate is one line in NewCodex and nothing else, and so the path
// can be asserted without constructing a target that refuses to exist. Note it is
// NOT under CodexHomeEnv: the documented root is the cross-tool ~/.agents, and
// CODEX_HOME relocates config.toml only.
func CodexUserSkillsRoot(homeDir string) string {
	return filepath.Join(homeDir, codexAgentsDirName, skillsSubdir)
}

// Codex resolves paths for the `codex` target. UserSkillsRoot is populated only
// once R2 is closed; until then NewCodex never returns a value.
type Codex struct {
	// UserSkillsRoot is $HOME/.agents/skills.
	UserSkillsRoot string
}

// NewCodex refuses to build the target. The path it would use is CodexUserSkillsRoot,
// so closing the gate is a change to this function and nothing else; the layout
// research does not need repeating.
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
