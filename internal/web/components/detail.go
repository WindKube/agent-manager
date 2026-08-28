package components

import (
	"agent-manager/internal/web/view"
)

// Helpers for the package detail screen (US3). They live beside the component
// rather than inside the template so a class name is computed in Go, where it
// can be read and tested, instead of assembled inside an attribute.

// ComponentClass tones the skill / mcp / ext badge. Only `skill` is emphasised:
// the design gives it the filled pill and leaves the other two as plain
// outlines, which is the right emphasis — a skill is what a person adopts, and
// an MCP server or a client extension is how it is wired up.
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

// VersionTagClass is a version row's distribution tag. `latest` is the only one
// the design fills in; `archived` reads as retired rather than as a warning,
// because retiring a version is a normal act.
func VersionTagClass(tag string) string {
	if tag == "latest" {
		return "am-vtag am-vtag-latest"
	}
	return "am-vtag"
}
