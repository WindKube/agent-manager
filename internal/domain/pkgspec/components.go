package pkgspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Component derivation (T038, FR-017).
//
// Components come from the FILE TREE and never from the manifest. This is not a
// stylistic choice: no field in either published specification enumerates them
// (R1), and the design's `components` array does not exist. `skills/*/SKILL.md` is
// a skill, an `mcp.json` entry is an MCP server, a reverse-domain directory is a
// client extension. That is the whole vocabulary.
//
// The consequence the spec states as an edge case: a manifest naming a component
// that is not on disk is a MANIFEST VALIDATION FAILURE, not a scan finding. The
// only conformant way a manifest can name one is
// `extensions["dev.agent-manager"].components`, so that is where the check lands.

// ErrTreeInvalid means the file tree does not describe what its shape claims. It
// is an ingestion failure like a bad manifest, not something for the scanner.
var ErrTreeInvalid = errors.New("package tree is not a valid spec layout")

// ComponentKind mirrors the `component_kind` enum. It is duplicated here rather
// than imported because internal/domain may not depend on internal/store
// (internal/archcheck enforces it) — the domain owns the vocabulary and the store
// owns the column.
type ComponentKind string

const (
	ComponentSkill ComponentKind = "skill"
	ComponentMCP   ComponentKind = "mcp"
	ComponentExt   ComponentKind = "ext"
)

// Component is one derived component.
type Component struct {
	Kind ComponentKind
	Name string
	Path string
	Note string
}

// deriveComponents walks the filtered tree.
func (l *layout) deriveComponents(validator *Validator, mcp *MCPConfig) ([]Component, error) {
	components := make([]Component, 0, len(l.skillDirs)+len(l.extDirs)+1)

	for _, dir := range l.skillDirs {
		manifestPath := dir + "/" + SkillManifest
		file, ok := l.files.Lookup(manifestPath)
		if !ok {
			// A directory under skills/ with no SKILL.md is a skill that is not
			// there. Deriving a component for it anyway would put a name in the
			// catalog with nothing behind it, so this fails closed.
			return nil, fmt.Errorf("%w: %s has no %s", ErrTreeInvalid, dir, SkillManifest)
		}

		// A contained skill's frontmatter is validated on the same terms as a
		// standalone one: a plugin cannot ship a skill the hub would refuse to
		// register on its own.
		skill, err := validator.ValidateSkillFrontmatter(file.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", manifestPath, err)
		}

		components = append(components, Component{
			Kind: ComponentSkill,
			Name: skill.Name,
			Path: dir,
			Note: skillNote(l, dir),
		})
	}

	if mcp != nil {
		for _, name := range mcp.ServerNames() {
			components = append(components, Component{
				Kind: ComponentMCP,
				Name: name,
				Path: MCPConfigFile,
				Note: mcp.MCPServers[name].Type,
			})
		}
	}

	for _, ext := range l.extDirs {
		components = append(components, Component{
			Kind: ComponentExt,
			Name: ext.name,
			Path: ext.name,
			Note: extNote(l, ext.name),
		})
	}

	return components, nil
}

// skillNote renders the design's `SKILL.md + scripts/` style: the manifest plus
// whichever support directories the skill actually carries.
func skillNote(l *layout, dir string) string {
	present := make([]string, 0, len(skillSupportDirs))
	for _, support := range skillSupportDirs {
		prefix := dir + "/" + support + "/"
		for _, path := range l.kept {
			if strings.HasPrefix(path, prefix) {
				present = append(present, support+"/")
				break
			}
		}
	}
	if len(present) == 0 {
		return SkillManifest
	}
	return SkillManifest + " + " + strings.Join(present, ", ")
}

// extNote lists the directories inside a client-extension namespace, which is
// what the design's `com.anthropic.claude-code/hooks/` line is showing.
func extNote(l *layout, name string) string {
	seen := make(map[string]struct{})
	children := make([]string, 0, 4)
	for _, path := range l.kept {
		rest, ok := strings.CutPrefix(path, name+"/")
		if !ok {
			continue
		}
		segments := splitPath(rest)
		if len(segments) < 2 {
			continue
		}
		if _, dup := seen[segments[0]]; dup {
			continue
		}
		seen[segments[0]] = struct{}{}
		children = append(children, segments[0]+"/")
	}
	sort.Strings(children)
	if len(children) == 0 {
		return "client extension"
	}
	return "client extension: " + strings.Join(children, ", ")
}

// checkDeclaredComponents is the spec's edge case, expressed against a conformant
// manifest: every path the publisher names under
// `extensions["dev.agent-manager"].components` must exist in the filtered tree,
// and an `mcp.json` stdio server whose working directory points inside the plugin
// must point at something that is there.
func (l *layout) checkDeclaredComponents(schemaID string, ext *AgentManagerExtension, mcp *MCPConfig) error {
	var problems []Problem

	if ext != nil {
		for i, declared := range ext.Components {
			if l.hasPath(declared) {
				continue
			}
			problems = append(problems, Problem{
				SchemaPath: "/properties/extensions/additionalProperties",
				InstancePath: fmt.Sprintf("/extensions/%s/components/%d",
					escapePointer(ExtensionNamespace), i),
				Message: fmt.Sprintf("declares component %q, which is not in the package tree", declared),
			})
		}
	}

	if mcp != nil {
		for _, name := range mcp.ServerNames() {
			server := mcp.MCPServers[name]
			if server.Type != MCPTypeStdio {
				continue
			}
			target, ok := pluginRootRelative(server.Cwd)
			if !ok || l.hasPath(target) {
				continue
			}
			problems = append(problems, Problem{
				SchemaPath:   "/$defs/stdioServer/properties/cwd",
				InstancePath: "/mcpServers/" + escapePointer(name) + "/cwd",
				Message:      fmt.Sprintf("cwd %q is not in the package tree", server.Cwd),
			})
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return manifestError(PluginManifest, schemaID, problems...)
}

// hasPath reports whether the filtered tree holds a file at path or anything
// under it as a directory.
func (l *layout) hasPath(path string) bool {
	clean := strings.Trim(strings.TrimSpace(path), "/")
	if clean == "" {
		return false
	}
	if l.files.Has(clean) {
		return true
	}
	prefix := clean + "/"
	for _, kept := range l.kept {
		if strings.HasPrefix(kept, prefix) {
			return true
		}
	}
	return false
}

// pluginRootRelative resolves the plugin-relative spellings the published mcp
// schema permits for `cwd` into a tree path. `${PLUGIN_DATA}` is not one: it is
// runtime state outside the bundle, so a cwd pointing there says nothing about
// what is on disk here.
func pluginRootRelative(cwd string) (string, bool) {
	switch {
	case cwd == "":
		return "", false
	case strings.HasPrefix(cwd, "${PLUGIN_ROOT}/"):
		return strings.TrimPrefix(cwd, "${PLUGIN_ROOT}/"), true
	case cwd == "${PLUGIN_ROOT}":
		return "", false
	case strings.HasPrefix(cwd, "./"):
		return strings.TrimPrefix(cwd, "./"), true
	default:
		return "", false
	}
}
