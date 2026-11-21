package deliver_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/deliver"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const (
	reviewerAgent = "---\nname: reviewer\ndescription: Reviews a diff.\ntools: Read, Grep\nmodel: sonnet\ncolor: blue\n---\nYou review diffs.\n"
	shipCommand   = "---\ndescription: Ship the branch.\n---\nShip $ARGUMENTS\n"
	guardHooks    = `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "guard check"}]}]}}`
)

const claudeSettings = `{
  // mine
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "my-own"}]}
    ]
  }
}
`

func promptKit(extra map[string]string) map[string]string {
	files := map[string]string{
		"com.anthropic.claude-code/agents/reviewer.md": reviewerAgent,
		"com.anthropic.claude-code/commands/ship.md":   shipCommand,
		"com.anthropic.claude-code/hooks/hooks.json":   guardHooks,
	}
	for k, v := range extra {
		files[k] = v
	}
	return kitFiles(files)
}

func skipsOf(res *apply.Result, kinds ...record.ComponentKind) map[record.Target]map[string]string {
	out := map[record.Target]map[string]string{}
	for i := range res.Installed {
		inst := &res.Installed[i]
		out[inst.Change.Target] = map[string]string{}
		for _, s := range inst.Skipped {
			for _, k := range kinds {
				if s.Kind == k {
					out[inst.Change.Target][string(s.Kind)+" "+s.Name] = s.Reason
				}
			}
		}
	}
	return out
}

func TestAgentsCommandsAndHooksGoWhereEachAgentReadsThem(t *testing.T) {
	h := newHarness(t)
	h.write(".claude/settings.json", claudeSettings)
	res := h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false)
	requireNoFailures(t, res)

	require.Equal(t, reviewerAgent, h.read(".claude/agents/reviewer.md"))
	require.Equal(t, shipCommand, h.read(".claude/commands/ship.md"))
	require.Equal(t, "---\ndescription: Reviews a diff.\nmode: subagent\n---\nYou review diffs.\n",
		h.read(".config/opencode/agents/reviewer.md"))
	require.Equal(t, shipCommand, h.read(".config/opencode/commands/ship.md"))
	require.Equal(t, "name = \"reviewer\"\ndescription = \"Reviews a diff.\"\ndeveloper_instructions = '''\nYou review diffs.\n'''\n",
		h.read(".codex/agents/reviewer.toml"))
	require.NoDirExists(t, h.path(".codex/prompts"))

	require.Equal(t, `{
  // mine
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "my-own"}]},
      {
        "hooks": [
          {
            "command": "guard check",
            "type": "command"
          }
        ],
        "matcher": "Bash"
      }
    ]
  }
}
`, h.read(".claude/settings.json"))

	hook := "hook com.anthropic.claude-code/hooks/hooks.json#/hooks/PreToolUse/0"
	require.Equal(t, map[record.Target]map[string]string{
		record.TargetClaudeCode: {},
		record.TargetCodex:      {"command ship": deliver.SkipCodexCommands, hook: deliver.SkipHooksClaudeOnly},
		record.TargetOpenCode:   {hook: deliver.SkipHooksClaudeOnly},
	}, skipsOf(res, record.ComponentAgent, record.ComponentCommand, record.ComponentHook))

	before := h.snapshot()
	again := h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false)
	requireNoFailures(t, again)
	require.Empty(t, again.Installed)
	require.Equal(t, before, h.snapshot())
}

func TestRemovingThePluginRestoresSettingsAndLeavesTheUsersOwnFiles(t *testing.T) {
	h := newHarness(t)
	h.write(".claude/settings.json", claudeSettings)
	h.write(".claude/agents/mine.md", "mine\n")
	requireNoFailures(t, h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false))

	requireNoFailures(t, h.sync(lockfile("base", allTargets), false))
	require.Equal(t, claudeSettings, h.read(".claude/settings.json"))
	require.Equal(t, "mine\n", h.read(".claude/agents/mine.md"))
	for _, p := range []string{".claude/agents/reviewer.md", ".claude/commands/ship.md", ".config/opencode/agents/reviewer.md",
		".config/opencode/commands/ship.md", ".codex/agents/reviewer.toml"} {
		require.NoFileExists(t, h.path(p))
	}
}

func TestAHookGroupIsAddedToAFreshSettingsFileAndRemovedWithIt(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false))
	require.Contains(t, h.read(".claude/settings.json"), `"guard check"`)

	requireNoFailures(t, h.sync(lockfile("base", cc), false))
	require.Equal(t, "{}\n", h.read(".claude/settings.json"))
}

func TestAnUpgradedHookReplacesItsGroupAndAnEditedOneIsLeftAlone(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	h.write(".claude/settings.json", claudeSettings)
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false))

	v2 := promptKit(map[string]string{"com.anthropic.claude-code/hooks/hooks.json": `{"hooks": {"PreToolUse": [
	  {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard check --strict"}]}]}}`})
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "2.0.0", v2)), false))
	settings := h.read(".claude/settings.json")
	require.Contains(t, settings, `"guard check --strict"`)
	require.NotContains(t, settings, `"guard check"`)
	require.Contains(t, settings, `"my-own"`)

	edited := replaceOnce(t, settings, `"guard check --strict"`, `"guard check --strict --mine"`)
	h.write(".claude/settings.json", edited)
	requireNoFailures(t, h.sync(lockfile("base", cc), false))
	require.Equal(t, edited, h.read(".claude/settings.json"), "a group that no longer matches what amctl wrote is not amctl's to remove")
}

func TestAnEditedAgentFileIsRefusedUntilForced(t *testing.T) {
	h := newHarness(t)
	oc := []record.Target{record.TargetOpenCode}
	requireNoFailures(t, h.sync(lockfile("base", oc, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false))
	h.write(".config/opencode/agents/reviewer.md", "mine now\n")

	v2 := promptKit(map[string]string{"com.anthropic.claude-code/agents/reviewer.md": "---\nname: reviewer\ndescription: v2\n---\nv2\n"})
	res := h.sync(lockfile("base", oc, h.pluginEntry("acme/kit", "2.0.0", v2)), false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrModified)
	require.Equal(t, "mine now\n", h.read(".config/opencode/agents/reviewer.md"))

	requireNoFailures(t, h.sync(lockfile("base", oc, h.pluginEntry("acme/kit", "2.0.0", v2)), true))
	require.Equal(t, "---\ndescription: v2\nmode: subagent\n---\nv2\n", h.read(".config/opencode/agents/reviewer.md"))
}

func TestAnAgentFileAmctlDidNotWriteIsRefused(t *testing.T) {
	h := newHarness(t)
	h.write(".claude/agents/reviewer.md", "someone else's\n")
	res := h.sync(lockfile("base", []record.Target{record.TargetClaudeCode}, h.pluginEntry("acme/kit", "1.0.0", promptKit(nil))), false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrUnrecorded)
	require.Equal(t, "someone else's\n", h.read(".claude/agents/reviewer.md"))
}

func TestCommandsOnlyClaudeCodeCanRunAreSkippedElsewhere(t *testing.T) {
	h := newHarness(t)
	kit := promptKit(map[string]string{
		"com.anthropic.claude-code/commands/pick.md":  "Pick $1 then $2\n",
		"com.anthropic.claude-code/commands/fast.md":  "---\nmodel: haiku\n---\nGo\n",
		"com.anthropic.claude-code/commands/wired.md": "---\nmodel: anthropic/claude-haiku-4-5\n---\nGo\n",
		"com.anthropic.claude-code/agents/root.md":    "---\nname: root\ndescription: r\n---\nRun ${CLAUDE_PLUGIN_ROOT}/x\n",
		"com.anthropic.claude-code/agents/bare.md":    "---\nname: bare\n---\nNo description.\n",
	})
	res := h.sync(lockfile("base", []record.Target{record.TargetClaudeCode, record.TargetOpenCode, record.TargetCodex},
		h.pluginEntry("acme/kit", "1.0.0", kit)), false)
	requireNoFailures(t, res)

	got := skipsOf(res, record.ComponentAgent, record.ComponentCommand)
	require.Equal(t, map[string]string{"agent root": deliver.SkipPluginRoot}, got[record.TargetClaudeCode])
	require.Equal(t, map[string]string{
		"agent root": deliver.SkipPluginRoot, "command pick": deliver.SkipPositionalArgs, "command fast": deliver.SkipModelAlias,
	}, got[record.TargetOpenCode])
	require.Equal(t, deliver.SkipCodexNoDescriptor, got[record.TargetCodex]["agent bare"])
	require.FileExists(t, h.path(".claude/commands/pick.md"))
	require.FileExists(t, h.path(".config/opencode/commands/wired.md"))
	require.Equal(t, "---\nmode: subagent\n---\nNo description.\n", h.read(".config/opencode/agents/bare.md"))
}

func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	i := indexOf(s, old)
	require.GreaterOrEqual(t, i, 0, "%q not in %q", old, s)
	return s[:i] + repl + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
