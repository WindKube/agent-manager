// Package pkgspec is this project's reading of the two published package
// specifications: Agent Plugins (`plugin.json`, `mcp.json`) and Agent Skills
// (`SKILL.md` frontmatter).
//
// Three things live here and nowhere else, because the API's pre-submit preview
// and the fetcher's authoritative pass must agree exactly:
//
//   - manifest validation against the EMBEDDED published schemas (FR-004),
//   - the spec-layout filter and the report of what it dropped (FR-005),
//   - component derivation from the FILE TREE (FR-017, R1).
//
// research.md R1 is the load-bearing fact: neither specification defines a
// permissions model, so a conformant manifest cannot declare one. The design's
// mockup manifests (`agentPluginsVersion`, `publisher`, `components`,
// `signature`, `network`, `filesystem`) are non-conformant and are rejected by
// `additionalProperties: false`. Nothing here relaxes a schema to admit them.
// An *expected* capability set has exactly one conformant home,
// `extensions["dev.agent-manager"]` (FR-018a).
package pkgspec

import "strings"

// The file and directory names the specifications give meaning to. Everything
// else at the package root is outside the spec layout and is dropped (FR-005).
const (
	// PluginManifest is the Agent Plugins manifest at the package root.
	PluginManifest = "plugin.json"

	// SkillManifest is the Agent Skills manifest: the frontmatter of this file.
	SkillManifest = "SKILL.md"

	// MCPConfigFile is the Agent Plugins MCP server configuration.
	MCPConfigFile = "mcp.json"

	// SkillsDir holds a plugin's contained skills, one directory each.
	SkillsDir = "skills"
)

// Kind is what a registered package is. It is decided by which manifest sits at
// the package root, never by a manifest field: no conformant manifest carries
// one.
type Kind string

const (
	// KindPlugin is a tree rooted at plugin.json.
	KindPlugin Kind = "plugin"

	// KindSkill is a tree rooted at SKILL.md — a skill distributed on its own.
	KindSkill Kind = "skill"
)

func (k Kind) Valid() bool { return k == KindPlugin || k == KindSkill }

// ManifestObject is the object name this kind's manifest is stored under beside
// the bundle (FR-006).
func (k Kind) ManifestObject() string {
	if k == KindSkill {
		return SkillManifest
	}
	return PluginManifest
}

// ExtensionNamespace is this project's reverse-domain key inside the manifest's
// `extensions` object.
//
// FR-018a: an expected capability set has no other conformant home. The Agent
// Plugins spec says it "assigns no semantics to namespace object contents", so
// this namespace is ours to define — and everything the design drew as a
// top-level manifest field lives in here instead, or nowhere.
const ExtensionNamespace = "dev.agent-manager"

// splitPath returns a slash-separated path's segments, dropping empties.
func splitPath(p string) []string {
	out := make([]string, 0, 4)
	for _, segment := range strings.Split(p, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

// topSegment is a path's first segment, or "" for an empty path.
func topSegment(p string) string {
	segments := splitPath(p)
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}
