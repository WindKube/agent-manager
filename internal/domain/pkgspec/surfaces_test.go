package pkgspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
)

func claudeCodeTree(t *testing.T) *bundle.Bundle {
	t.Helper()
	files := map[string]string{
		"plugin.json": `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"guard",` +
			`"extensions":{"com.anthropic.claude-code":{` +
			`"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"./bin/start.sh"}]}]},` +
			`"mcpServers":{"docs":{"type":"sse","url":"https://Docs.Example.com/sse"}},` +
			`"commands":["./extra"]}}}`,
		"com.anthropic.claude-code/hooks/hooks.json": `{"description":"guards","hooks":{"PreToolUse":[` +
			`{"matcher":"Bash","hooks":[{"type":"command","command":"guard check"},{"type":"prompt"}]}]}}`,
		"com.anthropic.claude-code/.mcp.json":          `{"mcpServers":{"local":{"command":"npx","args":["-y","pkg@1.2.3","--root","a b"]}}}`,
		"com.anthropic.claude-code/agents/review.md":   "---\nname: reviewer\ndescription: Reviews.\ntools: Read, Bash(git diff:*)\n---\nbody\n",
		"com.anthropic.claude-code/commands/ship.md":   "---\nallowed-tools: [Bash]\n---\nship it\n",
		"com.anthropic.claude-code/extra/lint.md":      "no frontmatter\n",
		"com.anthropic.claude-code/agents/nested/x.md": "---\nname: nested\n---\n",
		"skills/a/SKILL.md":                            "---\nname: a\ndescription: A.\nallowed-tools: [Read]\n---\n",
	}
	tree := bundle.New()
	for filePath, body := range files {
		require.NoError(t, tree.Add(filePath, bundle.FileMode, []byte(body)))
	}
	return tree
}

func TestClaudeCodeSurfacesAreReadFromTheExtensionNamespace(t *testing.T) {
	surfaces := pkgspec.ReadSurfaces(claudeCodeTree(t))

	require.Empty(t, surfaces.Unreadable)
	require.Equal(t, []pkgspec.Hook{
		{Event: "SessionStart", Type: "command", Command: "./bin/start.sh",
			File: "plugin.json", Pointer: "/extensions/com.anthropic.claude-code/hooks/SessionStart/0/hooks/0"},
		{Event: "PreToolUse", Matcher: "Bash", Type: "command", Command: "guard check",
			File: "com.anthropic.claude-code/hooks/hooks.json", Pointer: "/hooks/PreToolUse/0/hooks/0"},
		{Event: "PreToolUse", Matcher: "Bash", Type: "prompt",
			File: "com.anthropic.claude-code/hooks/hooks.json", Pointer: "/hooks/PreToolUse/0/hooks/1"},
	}, surfaces.Hooks)

	require.Len(t, surfaces.Servers, 2)
	remote, local := surfaces.Servers[0], surfaces.Servers[1]
	require.Equal(t, "plugin.json#/extensions/com.anthropic.claude-code/mcpServers/docs", remote.Location())
	require.Equal(t, pkgspec.TransportSSE, remote.Transport)
	require.Equal(t, "docs.example.com", remote.Host())
	require.Equal(t, "com.anthropic.claude-code/.mcp.json#/mcpServers/local", local.Location())
	require.Equal(t, pkgspec.TransportStdio, local.Transport, "no type with a command is stdio")
	require.Equal(t, "npx -y pkg@1.2.3 --root 'a b'", local.CommandLine())

	byPath := map[string]pkgspec.Prompt{}
	for _, prompt := range surfaces.Prompts {
		byPath[prompt.Path] = prompt
	}
	require.Len(t, byPath, 4, "nested agent directories are not agents")
	require.Equal(t, pkgspec.Prompt{Kind: pkgspec.ComponentAgent, Name: "reviewer", Path: "com.anthropic.claude-code/agents/review.md",
		Description: "Reviews.", Tools: []string{"Read", "Bash(git diff:*)"}}, byPath["com.anthropic.claude-code/agents/review.md"])
	require.Equal(t, []string{"Bash"}, byPath["com.anthropic.claude-code/commands/ship.md"].Tools)
	require.Equal(t, "lint", byPath["com.anthropic.claude-code/extra/lint.md"].Name, "a custom command path is honoured")
	require.Equal(t, pkgspec.ComponentSkill, byPath["skills/a/SKILL.md"].Kind)
}

func TestClaudeCodeComponentsCarryTheirTriggerAndTarget(t *testing.T) {
	pkg, err := pkgspec.Inspect(claudeCodeTree(t), ".")
	require.NoError(t, err)

	byKind := map[pkgspec.ComponentKind][]pkgspec.Component{}
	paths := map[string]struct{}{}
	for _, component := range pkg.Components {
		byKind[component.Kind] = append(byKind[component.Kind], component)
		_, dup := paths[component.Path]
		require.False(t, dup, "component path %s is the row key and must be unique", component.Path)
		paths[component.Path] = struct{}{}
	}

	require.Len(t, byKind[pkgspec.ComponentHook], 3)
	require.Equal(t, pkgspec.Component{
		Kind: pkgspec.ComponentHook, Name: "PreToolUse", Note: "command", Event: "PreToolUse", Matcher: "Bash",
		Path: "com.anthropic.claude-code/hooks/hooks.json#/hooks/PreToolUse/0/hooks/0", Target: "guard check",
	}, byKind[pkgspec.ComponentHook][1])
	require.Equal(t, []pkgspec.Component{
		{Kind: pkgspec.ComponentMCP, Name: "docs", Path: "plugin.json#/extensions/com.anthropic.claude-code/mcpServers/docs",
			Note: "sse", Transport: "sse", Target: "docs.example.com"},
		{Kind: pkgspec.ComponentMCP, Name: "local", Path: "com.anthropic.claude-code/.mcp.json#/mcpServers/local",
			Transport: "stdio", Target: "npx -y pkg@1.2.3 --root 'a b'"},
	}, byKind[pkgspec.ComponentMCP])
	require.Len(t, byKind[pkgspec.ComponentAgent], 1)
	require.Len(t, byKind[pkgspec.ComponentCommand], 2)
	require.Len(t, byKind[pkgspec.ComponentSkill], 1)
}

func TestAMalformedSurfaceFileIsReportedNotFatal(t *testing.T) {
	tree := bundle.New()
	require.NoError(t, tree.Add("plugin.json", bundle.FileMode,
		[]byte(`{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"x"}`)))
	require.NoError(t, tree.Add("com.anthropic.claude-code/hooks/hooks.json", bundle.FileMode, []byte(`{"hooks":`)))

	pkg, err := pkgspec.Inspect(tree, ".")
	require.NoError(t, err)
	require.Equal(t, []string{"com.anthropic.claude-code/hooks/hooks.json"}, pkgspec.ReadSurfaces(pkg.Files).Unreadable)
}
