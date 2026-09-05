package pkgspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Components come from the file tree and never from the manifest: no field
// in either published specification enumerates them. `skills/*/SKILL.md` is
// a skill, an `mcp.json` entry is an MCP server, a reverse-domain directory
// is a client extension — the whole vocabulary. A manifest naming a
// component that is not on disk is a manifest validation failure, not a scan
// finding; the only conformant way to name one is
// `extensions["dev.agent-manager"].components`.

// ErrTreeInvalid means the file tree does not describe what its shape
// claims. It is an ingestion failure like a bad manifest, not for the scanner.
var ErrTreeInvalid = errors.New("package tree is not a valid spec layout")

// ComponentKind mirrors the `component_kind` enum, duplicated here rather
// than imported because internal/domain may not depend on internal/store —
// the domain owns the vocabulary and the store owns the column.
type ComponentKind string

const (
	ComponentSkill ComponentKind = "skill"
	ComponentMCP   ComponentKind = "mcp"
	ComponentExt   ComponentKind = "ext"
)

type Component struct {
	Kind ComponentKind
	Name string
	Path string
	Note string
}

func (l *layout) deriveComponents(validator *Validator, mcp *MCPConfig) ([]Component, error) {
	components := make([]Component, 0, len(l.skillDirs)+len(l.extDirs)+1)

	for _, dir := range l.skillDirs {
		manifestPath := dir + "/" + SkillManifest
		file, ok := l.files.Lookup(manifestPath)
		if !ok {
			// A directory under skills/ with no SKILL.md is a skill that
			// isn't there; deriving one anyway would put a name in the
			// catalog with nothing behind it.
			return nil, fmt.Errorf("%w: %s has no %s", ErrTreeInvalid, dir, SkillManifest)
		}

		// Validated on the same terms as a standalone skill: a plugin cannot
		// ship a skill the hub would refuse to register on its own.
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
