package components

import (
	"agent-manager/internal/web/view"
)

// Class names are computed in Go, where they can be read and tested, rather than
// assembled inside an attribute.

// ComponentClass tones the skill / mcp / ext badge; only a skill, what a person
// adopts, gets the filled pill.
func ComponentClass(kind string) string {
	if kind == "skill" {
		return "am-comp-kind am-comp-kind-skill"
	}
	return "am-comp-kind"
}

// LevelClass is a capability level's badge.
func LevelClass(level string) string {
	return "am-level am-level-" + view.LevelTone(level)
}

// StatusClass tones the inferred-versus-expected verdict.
func StatusClass(row view.CapabilityRow) string {
	return "am-cap-status am-cap-status-" + row.Tone()
}

// VersionTagClass fills only `latest`; `archived` reads as retired, not a warning.
func VersionTagClass(tag string) string {
	if tag == "latest" {
		return "am-vtag am-vtag-latest"
	}
	return "am-vtag"
}
