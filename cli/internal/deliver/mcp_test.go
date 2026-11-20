package deliver_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/deliver"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const mcpConfig = `{"mcpServers": {
  "fs": {"type": "stdio", "command": "npx", "args": ["-y", "@mcp/fs@1.2.3"], "env": {"FS_ROOT": "/srv"}},
  "api": {"type": "streamable-http", "url": "https://api.example.com/mcp", "headers": {"X-Team": "core"}}
}}`

const codexConfig = `# mine
model = "gpt-5"

[mcp_servers.own]
command = "own-server" # hand-written
`

const openCodeConfig = `{
  // mine
  "theme": "tokyonight",
}
`

func mcpKit(cfg string) map[string]string {
	return kitFiles(map[string]string{"mcp.json": cfg})
}

func (h *harness) claudeServers() map[string]any {
	h.t.Helper()
	var cfg struct {
		MCPServers map[string]any `json:"mcpServers"`
	}
	require.NoError(h.t, json.Unmarshal([]byte(h.read(".claude.json")), &cfg))
	return cfg.MCPServers
}

func TestPluginMCPServersAreConfiguredInEveryTarget(t *testing.T) {
	h := newHarness(t)
	h.write(".codex/config.toml", codexConfig)
	h.write(".config/opencode/opencode.jsonc", openCodeConfig)

	requireNoFailures(t, h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false))

	require.Equal(t, map[string]any{
		"kit-fs": map[string]any{"type": "stdio", "command": "npx", "args": []any{"-y", "@mcp/fs@1.2.3"},
			"env": map[string]any{"FS_ROOT": "/srv"}},
		"kit-api": map[string]any{"type": "http", "url": "https://api.example.com/mcp",
			"headers": map[string]any{"X-Team": "core"}},
	}, h.claudeServers())

	require.Equal(t, codexConfig+`
[mcp_servers.kit-api]
url = "https://api.example.com/mcp"
http_headers = { "X-Team" = "core" }

[mcp_servers.kit-fs]
command = "npx"
args = ["-y", "@mcp/fs@1.2.3"]
env = { "FS_ROOT" = "/srv" }
`, h.read(".codex/config.toml"))

	require.Equal(t, `{
  // mine
  "theme": "tokyonight",
  "mcp": {
    "kit-api": {
      "enabled": true,
      "headers": {
        "X-Team": "core"
      },
      "type": "remote",
      "url": "https://api.example.com/mcp"
    },
    "kit-fs": {
      "command": [
        "npx",
        "-y",
        "@mcp/fs@1.2.3"
      ],
      "enabled": true,
      "environment": {
        "FS_ROOT": "/srv"
      },
      "type": "local"
    }
  },
}
`, h.read(".config/opencode/opencode.jsonc"))
	require.NoFileExists(t, h.path(".config/opencode/opencode.json"))

	cx := h.entry(record.TargetCodex, "acme/kit")
	var servers []record.Component
	for _, c := range cx.Components {
		if c.Kind == record.ComponentMCPServer {
			servers = append(servers, c)
		}
	}
	require.Len(t, servers, 2)
	require.Equal(t, "kit-api", servers[0].Key)
	require.Equal(t, h.path(".codex/config.toml"), servers[0].Path)

	calls := len(h.claude.calls)
	before := h.snapshot()
	res := h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false)
	requireNoFailures(t, res)
	require.Empty(t, res.Installed)
	require.Equal(t, before, h.snapshot())
	require.Len(t, h.claude.calls, calls, "an unchanged server is not re-added")
}

func TestAnUpgradeRewritesChangedServersAndRemovesDroppedOnes(t *testing.T) {
	h := newHarness(t)
	h.write(".codex/config.toml", codexConfig)
	h.write(".config/opencode/opencode.jsonc", openCodeConfig)
	requireNoFailures(t, h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false))

	v2 := `{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs@2.0.0"]}}}`
	requireNoFailures(t, h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "2.0.0", mcpKit(v2))), false))

	require.Equal(t, map[string]any{
		"kit-fs": map[string]any{"type": "stdio", "command": "npx", "args": []any{"-y", "@mcp/fs@2.0.0"}},
	}, h.claudeServers())
	require.Equal(t, codexConfig+"\n[mcp_servers.kit-fs]\ncommand = \"npx\"\nargs = [\"-y\", \"@mcp/fs@2.0.0\"]\n",
		h.read(".codex/config.toml"))
	require.NotContains(t, h.read(".config/opencode/opencode.jsonc"), "kit-api")
	require.Contains(t, h.read(".config/opencode/opencode.jsonc"), "@mcp/fs@2.0.0")
}

func TestRemovingAPluginRestoresEachConfigFile(t *testing.T) {
	h := newHarness(t)
	h.write(".codex/config.toml", codexConfig)
	h.write(".config/opencode/opencode.jsonc", openCodeConfig)
	h.write(".claude.json", `{"numStartups": 4, "mcpServers": {"own": {"command": "x"}}}`)
	requireNoFailures(t, h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false))

	res := h.sync(lockfile("base", allTargets), false)
	requireNoFailures(t, res)
	require.Len(t, res.Removed, 3)
	require.Equal(t, codexConfig, h.read(".codex/config.toml"))
	require.Equal(t, openCodeConfig, h.read(".config/opencode/opencode.jsonc"))
	require.Equal(t, map[string]any{"own": map[string]any{"command": "x"}}, h.claudeServers())
}

func TestAnEditedServerEntryIsNeitherRewrittenNorRemovedWithoutForce(t *testing.T) {
	h := newHarness(t)
	cx := []record.Target{record.TargetCodex}
	requireNoFailures(t, h.sync(lockfile("base", cx, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false))
	edited := `
[mcp_servers.kit-api]
url = "https://api.example.com/mcp"
http_headers = { "X-Team" = "core" }

[mcp_servers.kit-fs]
command = "npx"
args = ["-y", "@mcp/fs@1.2.3", "--verbose"]
env = { "FS_ROOT" = "/srv" }
`
	h.write(".codex/config.toml", edited)

	v2 := `{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs@2.0.0"]}}}`
	upgrade := lockfile("base", cx, h.pluginEntry("acme/kit", "2.0.0", mcpKit(v2)))
	res := h.sync(upgrade, false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrModified)
	require.Contains(t, res.Failed[0].Err.Error(), "kit-fs")
	require.Equal(t, edited, h.read(".codex/config.toml"), "a refused plugin changes nothing, not even the unedited entry")

	requireNoFailures(t, h.sync(upgrade, true))
	require.Equal(t, "\n[mcp_servers.kit-fs]\ncommand = \"npx\"\nargs = [\"-y\", \"@mcp/fs@2.0.0\"]\n", h.read(".codex/config.toml"))
}

func TestAnEntryAmctlDidNotWriteIsRefusedUnlessItIsIdentical(t *testing.T) {
	h := newHarness(t)
	oc := []record.Target{record.TargetOpenCode}
	h.write(".config/opencode/opencode.json", `{"mcp": {"kit-fs": {"type": "local", "command": ["mine"]}}}`)

	res := h.sync(lockfile("base", oc, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrUnrecorded)
	require.Equal(t, `{"mcp": {"kit-fs": {"type": "local", "command": ["mine"]}}}`, h.read(".config/opencode/opencode.json"))

	h.write(".config/opencode/opencode.json", `{"mcp": {"kit-fs": {"type": "local", "enabled": true,
	  "command": ["npx", "-y", "@mcp/fs@1.2.3"], "environment": {"FS_ROOT": "/srv"}}}}`)
	requireNoFailures(t, h.sync(lockfile("base", oc, h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false))
}

func TestWithoutTheClaudeCLIClaudeCodeServersAreSkipped(t *testing.T) {
	h := newHarness(t)
	h.cli = nil
	res := h.sync(lockfile("base", []record.Target{record.TargetClaudeCode, record.TargetCodex},
		h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))), false)
	requireNoFailures(t, res)
	for _, inst := range res.Installed {
		if inst.Change.Target == record.TargetClaudeCode {
			require.Len(t, inst.Skipped, 2)
			require.Equal(t, deliver.SkipNoClaudeCLI, inst.Skipped[0].Reason)
		} else {
			require.Empty(t, inst.Skipped)
		}
	}
	require.NoFileExists(t, h.path(".claude.json"))
	require.Contains(t, h.read(".codex/config.toml"), "[mcp_servers.kit-fs]")
}

func TestServersAnAgentCannotRunAsWrittenAreSkippedForThatAgent(t *testing.T) {
	h := newHarness(t)
	cfg := `{"mcpServers": {
	  "events": {"type": "sse", "url": "https://events.example.com/sse"},
	  "tok": {"command": "srv", "env": {"TOKEN": "${MY_TOKEN}"}},
	  "local": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/server.js"]},
	  "here": {"command": "srv", "cwd": "/srv"}
	}}`
	res := h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", mcpKit(cfg))), false)
	requireNoFailures(t, res)

	got := map[record.Target]map[string]string{}
	for _, inst := range res.Installed {
		got[inst.Change.Target] = map[string]string{}
		for _, s := range inst.Skipped {
			if s.Kind == record.ComponentMCPServer {
				got[inst.Change.Target][s.Name] = s.Reason
			}
		}
	}
	require.Equal(t, map[record.Target]map[string]string{
		record.TargetClaudeCode: {"local": deliver.SkipPluginRoot, "here": deliver.SkipWorkingDir},
		record.TargetCodex:      {"local": deliver.SkipPluginRoot, "events": deliver.SkipSSEOnCodex, "tok": deliver.SkipEnvExpansion},
		record.TargetOpenCode:   {"local": deliver.SkipPluginRoot, "here": deliver.SkipWorkingDir, "tok": deliver.SkipEnvExpansion},
	}, got)
	require.Contains(t, h.read(".codex/config.toml"), "cwd = \"/srv\"")
	require.Contains(t, h.claudeServers(), "kit-events")
}

func TestTwoPluginsWhoseEntriesShareANameDoNotOverwriteEachOther(t *testing.T) {
	h := newHarness(t)
	cx := []record.Target{record.TargetCodex}
	first := h.pluginEntry("acme/kit", "1.0.0", mcpKit(mcpConfig))
	requireNoFailures(t, h.sync(lockfile("base", cx, first), false))
	before := h.read(".codex/config.toml")

	res := h.sync(lockfile("base", cx, first, h.pluginEntry("other/kit", "1.0.0", mcpKit(mcpConfig))), false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrComponentConflict)
	require.Equal(t, before, h.read(".codex/config.toml"))
}
