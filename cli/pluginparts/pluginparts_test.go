package pluginparts_test

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/pluginparts"
)

func readKit(t *testing.T) *pluginparts.Plugin {
	t.Helper()
	p, err := pluginparts.Read(os.DirFS("testdata/kit"))
	require.NoError(t, err)
	return p
}

func TestReadDecomposesEveryComponent(t *testing.T) {
	p := readKit(t)

	require.Equal(t, "kit", p.Name)
	require.Empty(t, p.Problems)

	require.Len(t, p.Skills, 2)
	require.Equal(t, pluginparts.Skill{Name: "alpha", Dir: "skills/alpha", Files: []string{"SKILL.md", "scripts/run.sh"}}, p.Skills[0])
	require.Equal(t, "beta", p.Skills[1].Name)

	names := func(servers []pluginparts.Server) []string {
		var out []string
		for _, s := range servers {
			out = append(out, s.Name)
		}
		return out
	}
	require.Equal(t, []string{"api", "docs", "fs", "local"}, names(p.Servers))
	api, docs, fs, local := p.Servers[0], p.Servers[1], p.Servers[2], p.Servers[3]
	require.Equal(t, pluginparts.TransportHTTP, api.Transport)
	require.Equal(t, map[string]string{"X-Team": "core"}, api.Headers)
	require.Equal(t, pluginparts.TransportSSE, docs.Transport)
	require.Equal(t, "plugin.json#/extensions/com.anthropic.claude-code/mcpServers/docs", docs.Source)
	require.Equal(t, pluginparts.TransportStdio, fs.Transport)
	require.Equal(t, []string{"-y", "@mcp/fs@1.2.3"}, fs.Args)
	require.Equal(t, map[string]string{"FS_ROOT": "/srv"}, fs.Env)
	require.False(t, fs.UsesPluginRoot)
	require.Equal(t, pluginparts.TransportStdio, local.Transport, "no type with a command is stdio")
	require.True(t, local.UsesPluginRoot)

	require.Len(t, p.Agents, 1)
	require.Equal(t, "reviewer", p.Agents[0].Name, "an agent is named by its frontmatter")
	require.Equal(t, "Reviews a diff.", p.Agents[0].Description)

	require.Len(t, p.Commands, 2)
	require.Equal(t, "lint", p.Commands[0].Name)
	require.Equal(t, "com.anthropic.claude-code/extra/lint.md", p.Commands[0].Path)
	require.Equal(t, "ship", p.Commands[1].Name)
	require.Equal(t, "---\ndescription: Ship the branch.\n---\nShip $ARGUMENTS\n", string(p.Commands[1].Data))

	require.Len(t, p.Hooks, 3)
	start := p.Hooks[0]
	require.Equal(t, "SessionStart", start.Event)
	require.JSONEq(t, `{"hooks":[{"type":"command","command":"echo started"}]}`, string(start.Group))
	post, pre := p.Hooks[1], p.Hooks[2]
	require.Equal(t, "PostToolUse", post.Event)
	require.True(t, post.UsesPluginRoot)
	require.Equal(t, "PreToolUse", pre.Event)
	require.Equal(t, "Bash", pre.Matcher)
	require.Equal(t, []pluginparts.HookEntry{{Type: "command", Command: "guard check"}}, pre.Entries)
	require.JSONEq(t, `{"matcher":"Bash","hooks":[{"type":"command","command":"guard check","timeout":30}]}`,
		string(pre.Group), "the group is kept verbatim, fields this package does not read included")
}

func TestReadRefusesATreeWithoutAManifest(t *testing.T) {
	_, err := pluginparts.Read(fstest.MapFS{"skills/a/SKILL.md": {Data: []byte("x")}})
	require.ErrorIs(t, err, pluginparts.ErrNotPlugin)
}

func TestMalformedComponentFilesAreProblemsNotFailures(t *testing.T) {
	p, err := pluginparts.Read(fstest.MapFS{
		"plugin.json": {Data: []byte(`{"name":"x"}`)},
		"mcp.json":    {Data: []byte(`{"mcpServers":{"a":{"type":"carrier-pigeon"}}}`)},
		"com.anthropic.claude-code/hooks/hooks.json":   {Data: []byte(`[`)},
		"com.anthropic.claude-code/.mcp.json":          {Data: []byte(`{"mcpServers":{"b":{"command":"x"}}}`)},
		"com.anthropic.claude-code/agents/bad.md":      {Data: []byte("---\nname: [\n---\nbody\n")},
		"skills/no-manifest/README.md":                 {Data: []byte("x")},
		"com.anthropic.claude-code/commands/fine.md":   {Data: []byte("fine\n")},
		"com.anthropic.claude-code/commands/sub/no.md": {Data: []byte("nested commands are not read\n")},
	})
	require.NoError(t, err)
	require.Len(t, p.Problems, 4)
	require.Len(t, p.Servers, 1)
	require.Len(t, p.Agents, 1, "an agent with unreadable frontmatter is still a file to install")
	require.Equal(t, "bad", p.Agents[0].Name)
	require.Len(t, p.Commands, 1)
	require.Empty(t, p.Skills)
}

func TestDuplicateServerNamesKeepTheFirst(t *testing.T) {
	p, err := pluginparts.Read(fstest.MapFS{
		"plugin.json":                         {Data: []byte(`{"name":"x"}`)},
		"mcp.json":                            {Data: []byte(`{"mcpServers":{"a":{"type":"stdio","command":"first"}}}`)},
		"com.anthropic.claude-code/.mcp.json": {Data: []byte(`{"mcpServers":{"a":{"command":"second"}}}`)},
	})
	require.NoError(t, err)
	require.Len(t, p.Servers, 1)
	require.Equal(t, "first", p.Servers[0].Command)
	require.Len(t, p.Problems, 1)
}

func TestSplitFrontmatter(t *testing.T) {
	front, body, err := pluginparts.SplitFrontmatter([]byte("---\nname: a\ndescription: b\nmodel: openai/gpt-5\n---\nbody\n"))
	require.NoError(t, err)
	require.Equal(t, pluginparts.Frontmatter{Name: "a", Description: "b", Model: "openai/gpt-5"}, front)
	require.Equal(t, "body\n", string(body))

	front, body, err = pluginparts.SplitFrontmatter([]byte("no header\n"))
	require.NoError(t, err)
	require.Equal(t, pluginparts.Frontmatter{}, front)
	require.Equal(t, "no header\n", string(body))
}
