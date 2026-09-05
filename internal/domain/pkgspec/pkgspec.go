// Package pkgspec is this project's reading of the two published package
// specifications: Agent Plugins (`plugin.json`, `mcp.json`) and Agent Skills
// (`SKILL.md` frontmatter). Manifest validation, the spec-layout filter, and
// component derivation all live here and nowhere else, so the api's
// pre-submit preview and the fetcher's authoritative pass agree exactly.
package pkgspec

import "strings"

// The file and directory names the specifications give meaning to.
const (
	PluginManifest = "plugin.json"
	SkillManifest  = "SKILL.md"
	MCPConfigFile  = "mcp.json"
	SkillsDir      = "skills"
)

// Kind is what a registered package is, decided by which manifest sits at
// the package root.
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

// ExtensionNamespace is this project's reverse-domain key inside the
// manifest's `extensions` object: the spec assigns no semantics there, so
// this namespace is ours to define.
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
