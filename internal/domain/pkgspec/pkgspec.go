// Package pkgspec implements the Agent Plugins and Agent Skills specs:
// manifest validation, the layout filter and component derivation. It is the
// single implementation so the api preview and the fetcher agree exactly.
package pkgspec

import "strings"

// The file and directory names the specifications give meaning to.
const (
	PluginManifest = "plugin.json"
	SkillManifest  = "SKILL.md"
	MCPConfigFile  = "mcp.json"
	SkillsDir      = "skills"
)

// Kind is decided by which manifest sits at the package root.
type Kind string

const (
	KindPlugin Kind = "plugin"
	KindSkill  Kind = "skill"
)

func (k Kind) Valid() bool { return k == KindPlugin || k == KindSkill }

func (k Kind) ManifestObject() string {
	if k == KindSkill {
		return SkillManifest
	}
	return PluginManifest
}

// ExtensionNamespace is this project's key inside the manifest's `extensions`.
const ExtensionNamespace = "dev.agent-manager"

func splitPath(p string) []string {
	out := make([]string, 0, 4)
	for _, segment := range strings.Split(p, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func topSegment(p string) string {
	segments := splitPath(p)
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}
