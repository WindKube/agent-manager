package pkgspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Components come from the file tree, never the manifest, since neither
// published spec enumerates them.

// ErrTreeInvalid means the file tree does not describe what its shape claims.
// It is an ingestion failure, not a scan finding.
var ErrTreeInvalid = errors.New("package tree is not a valid spec layout")

// ComponentKind mirrors the `component_kind` enum; internal/domain may not
// import internal/store.
type ComponentKind string

const (
	ComponentSkill   ComponentKind = "skill"
	ComponentMCP     ComponentKind = "mcp"
	ComponentExt     ComponentKind = "ext"
	ComponentAgent   ComponentKind = "agent"
	ComponentCommand ComponentKind = "command"
	ComponentHook    ComponentKind = "hook"
)

// Component is one thing the tree holds. Path is unique within a version: a
// component inside a JSON document is addressed as `file#/json/pointer`.
type Component struct {
	Kind ComponentKind
	Name string
	Path string
	Note string

	// Event and Matcher are a hook's trigger.
	Event   string
	Matcher string
	// Transport is an MCP server's stdio, http or sse.
	Transport string
	// Target is what runs or is reached: a hook's command, a stdio server's
	// command line, or a remote server's URL host.
	Target string
}

func (l *layout) deriveComponents(validator *Validator) ([]Component, error) {
	components := make([]Component, 0, len(l.skillDirs)+len(l.extDirs)+1)
	surfaces := ReadSurfaces(l.files)

	for _, dir := range l.skillDirs {
		manifestPath := dir + "/" + SkillManifest
		file, ok := l.files.Lookup(manifestPath)
		if !ok {
			return nil, fmt.Errorf("%w: %s has no %s", ErrTreeInvalid, dir, SkillManifest)
		}

		// A plugin cannot ship a skill the hub would refuse on its own.
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

	for i := range surfaces.Servers {
		server := &surfaces.Servers[i]
		target := server.Host()
		if server.Transport == TransportStdio {
			target = server.CommandLine()
		}
		components = append(components, Component{
			Kind:      ComponentMCP,
			Name:      server.Name,
			Path:      server.Location(),
			Note:      server.Type,
			Transport: server.Transport,
			Target:    target,
		})
	}

	for _, hook := range surfaces.Hooks {
		components = append(components, Component{
			Kind:    ComponentHook,
			Name:    hook.Event,
			Path:    hook.Location(),
			Note:    hook.Type,
			Event:   hook.Event,
			Matcher: hook.Matcher,
			Target:  hook.Command,
		})
	}

	for _, prompt := range surfaces.Prompts {
		if prompt.Kind == ComponentSkill {
			continue
		}
		components = append(components, Component{
			Kind: prompt.Kind,
			Name: prompt.Name,
			Path: prompt.Path,
			Note: clipNote(prompt.Description),
		})
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

func clipNote(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	const limit = 120
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut] + "…"
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
