package layout

import (
	"errors"
	"fmt"
)

// ErrR2Unresolved marks a target whose on-disk layout the R2 gate could not
// settle. Every constructor for such a target returns an error wrapping this, so
// the registry can refuse the target by class rather than by string match, and so
// a `sync` for a profile that names it fails loudly instead of writing somewhere
// hopeful. Declared here because internal/layout/layout.go belongs to another
// task; move it there if the registry wants it there.
var ErrR2Unresolved = errors.New("target layout unresolved by research gate R2")

// Target `agents-md` — UNSHIPPED. Not "unverified": unresolvable as specified.
//
// The convention has no per-user directory to install into, and no directory per
// package at all. What is documented is one markdown file per directory of a
// source tree:
//
//	<repo root>/AGENTS.md          the documented location
//	<subdir>/AGENTS.md             nested, nearest file wins
//
// Sources:
//
//  1. https://agents.md/ — "Create an AGENTS.md file at the root of the
//     repository." For monorepos: "Use nested AGENTS.md files for subprojects" /
//     "Place another AGENTS.md inside each package." Precedence: "Agents
//     automatically read the nearest file in the directory tree, so the closest one
//     takes precedence." The page documents no user-level or global location, no
//     skills directory, and no plugin or extension concept — checked explicitly.
//  2. https://github.com/agentsmd/agents.md/issues/91 — "Standardize global
//     user-level AGENTS.md at ~/.config/agents/AGENTS.md", still OPEN. It exists
//     because "Each AI coding tool uses a different global config path", and
//     enumerates them: Claude Code ~/.claude/CLAUDE.md, Codex ~/.codex/AGENTS.md,
//     droid ~/.factory/AGENTS.md, Amp ~/.config/AGENTS.md. An open proposal to
//     standardise a path is proof there is no standard path to write to.
//
// Four requirements block this target, and none of them is a research question:
//
//   - FR-020 — install under the invoking user's home, never outside it. The
//     documented location is a repository root, which is wherever the developer
//     cloned it. amctl would be writing into project trees it does not own.
//   - FR-022 — an installed entry must be identifiable on disk as a specific
//     package and version. A single shared markdown file has nowhere to carry that
//     per package, and no marker file can be added beside it: the convention reads
//     one filename.
//   - FR-023 — packages colliding across publishers must land in distinct
//     directories. There are no directories here.
//   - FR-024/FR-028/FR-029 — atomic per entry, never overwrite a path absent from
//     the record, detect modification. Installing N packages means merging N
//     fragments into one file that the developer also hand-edits. A merge is not a
//     rename, so it is not atomic; and the file is not a path amctl wrote, so
//     touching it is exactly the overwrite FR-028 forbids.
//
// The honest reading: `agents-md` is a *rendering* target, not an install target.
// Shipping it as an install target would mean either writing outside the home or
// rewriting a file the developer owns, and the failure mode of getting it subtly
// wrong is the silent one FR-021 is written to prevent.
//
// What would resolve it: a spec decision, not more reading. Either (a) the spec
// picks one per-user location and accepts that it serves only the agents that read
// it — ~/.config/agents/AGENTS.md if issue 91 lands, or a named per-tool path — and
// defines how N packages compose into one file with delimited, individually
// prunable regions; or (b) the target is dropped from the contract's enum.
func NewAgentsMD(string, string) (*AgentsMD, error) {
	return nil, fmt.Errorf(
		"agents-md: %w — the convention documents only a repository-root AGENTS.md "+
			"(https://agents.md/) and no per-user location (agentsmd/agents.md#91 is "+
			"still open), so there is no path under the user's home to install to and "+
			"no per-package unit to install; resolving it needs a spec decision, not a path",
		ErrR2Unresolved,
	)
}

// AgentsMD exists so the constructor has a return type and so the registry can
// name the target. It has no fields because no field could be filled in honestly.
type AgentsMD struct{}
