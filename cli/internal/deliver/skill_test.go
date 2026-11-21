package deliver_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

var allTargets = []record.Target{record.TargetClaudeCode, record.TargetCodex, record.TargetOpenCode}

func TestPluginSkillsArePlacedInEveryTargetAndOpenCodeIsServedByTheOthers(t *testing.T) {
	h := newHarness(t)
	res := h.sync(lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false)
	requireNoFailures(t, res)
	require.Len(t, res.Installed, 3)

	for _, root := range []string{".claude/skills", ".agents/skills"} {
		require.Equal(t, "Alpha body\n", lastLine(h.read(root+"/acme--kit--alpha/SKILL.md")))
		require.Equal(t, "#!/bin/sh\necho alpha\n", h.read(root+"/acme--kit--alpha/run.sh"))
		require.FileExists(t, h.path(root+"/acme--kit--beta/SKILL.md"))
	}
	require.NoDirExists(t, h.path(".config/opencode/skills"), "opencode reads ~/.claude/skills and ~/.agents/skills")

	var oc apply.Installed
	for _, inst := range res.Installed {
		if inst.Change.Target == record.TargetOpenCode {
			oc = inst
		}
	}
	require.Len(t, oc.Skipped, 2)
	require.Contains(t, oc.Skipped[0].Reason, "served by")
	require.Contains(t, oc.Skipped[0].Reason, h.path(".claude/skills"))

	cc := h.entry(record.TargetClaudeCode, "acme/kit")
	require.Len(t, cc.Components, 2)
	require.Equal(t, record.ComponentSkill, cc.Components[0].Kind)
	require.Equal(t, h.path(".claude/skills/acme--kit--alpha"), cc.Components[0].Path)
	require.DirExists(t, cc.Dest, "the plugin itself is unpacked under amctl's own directory")
	require.NoDirExists(t, h.path(".claude/skills/.amctl-staging"))
}

func lastLine(s string) string {
	lines := []byte(s)
	i := len(lines) - 2
	for i >= 0 && lines[i] != '\n' {
		i--
	}
	return string(lines[i+1:])
}

func TestASecondSyncOfAPluginChangesNothing(t *testing.T) {
	h := newHarness(t)
	lf := lockfile("base", allTargets, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil)))
	requireNoFailures(t, h.sync(lf, false))
	before := h.snapshot()

	res := h.sync(lf, false)
	requireNoFailures(t, res)
	require.Empty(t, res.Installed)
	require.Zero(t, res.RecordWrites)
	require.Equal(t, before, h.snapshot())
}

func TestOpenCodeAloneGetsItsOwnCopy(t *testing.T) {
	h := newHarness(t)
	requireNoFailures(t, h.sync(lockfile("base", []record.Target{record.TargetOpenCode},
		h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false))
	require.FileExists(t, h.path(".config/opencode/skills/acme--kit--alpha/SKILL.md"))
	require.NoDirExists(t, h.path(".claude/skills"))
}

func TestAnUpgradeReplacesChangedSkillsAndRemovesDroppedOnes(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false))

	v2 := kitFiles(map[string]string{"skills/beta/SKILL.md": "", "skills/alpha/SKILL.md": "---\nname: alpha\n---\nAlpha v2\n"})
	res := h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "2.0.0", v2)), false)
	requireNoFailures(t, res)
	require.Equal(t, "---\nname: alpha\n---\nAlpha v2\n", h.read(".claude/skills/acme--kit--alpha/SKILL.md"))
	require.NoDirExists(t, h.path(".claude/skills/acme--kit--beta"))
	require.Len(t, h.entry(record.TargetClaudeCode, "acme/kit").Components, 1)
}

func TestAnEditedSkillIsNeitherOverwrittenNorRemovedWithoutForce(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false))
	h.write(".claude/skills/acme--kit--alpha/SKILL.md", "my own notes\n")
	before := h.snapshot()

	v2 := kitFiles(map[string]string{"skills/alpha/SKILL.md": "---\nname: alpha\n---\nAlpha v2\n"})
	upgrade := lockfile("base", cc, h.pluginEntry("acme/kit", "2.0.0", v2))
	res := h.sync(upgrade, false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrModified)
	require.True(t, res.Failed[0].Refusal)
	require.Equal(t, before, h.snapshot(), "a refused plugin changes nothing anywhere")
	require.Equal(t, "1.0.0", h.entry(record.TargetClaudeCode, "acme/kit").Version)

	gone := h.sync(lockfile("base", cc), false)
	require.Len(t, gone.Failed, 1)
	require.ErrorIs(t, gone.Failed[0].Err, apply.ErrModified)
	require.Equal(t, "my own notes\n", h.read(".claude/skills/acme--kit--alpha/SKILL.md"))
	require.NoDirExists(t, h.path(".claude/skills/acme--kit--beta"), "the unmodified one is removed")
	require.Len(t, h.entry(record.TargetClaudeCode, "acme/kit").Components, 1, "the record keeps what it could not remove")

	requireNoFailures(t, h.sync(upgrade, true))
	require.Equal(t, "---\nname: alpha\n---\nAlpha v2\n", h.read(".claude/skills/acme--kit--alpha/SKILL.md"))
}

func TestAnUnmanagedDirectoryIsRefusedUnlessItIsIdentical(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	h.write(".claude/skills/acme--kit--beta/SKILL.md", "someone else's\n")

	res := h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false)
	require.Len(t, res.Failed, 1)
	require.ErrorIs(t, res.Failed[0].Err, apply.ErrUnrecorded)
	require.NoDirExists(t, h.path(".claude/skills/acme--kit--alpha"))

	h.write(".claude/skills/acme--kit--beta/SKILL.md", "---\nname: beta\ndescription: Beta.\n---\nBeta body\n")
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false))
	require.Len(t, h.entry(record.TargetClaudeCode, "acme/kit").Components, 2, "identical content is adopted")
}

func TestRemovingAPluginRemovesItsSkillsAndItsUnpackedCopy(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	requireNoFailures(t, h.sync(lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil))), false))
	dest := h.entry(record.TargetClaudeCode, "acme/kit").Dest
	h.write(".claude/skills/mine/SKILL.md", "hand-written\n")

	res := h.sync(lockfile("base", cc), false)
	requireNoFailures(t, res)
	require.Len(t, res.Removed, 1)
	require.NoDirExists(t, h.path(".claude/skills/acme--kit--alpha"))
	require.NoDirExists(t, dest)
	require.FileExists(t, h.path(".claude/skills/mine/SKILL.md"))
	p, ok := h.rec.ProfileBySlug("base")
	require.True(t, ok)
	require.Empty(t, p.Entries)
}

func TestASkillNamingThePluginRootIsSkippedEverywhere(t *testing.T) {
	h := newHarness(t)
	files := kitFiles(map[string]string{"skills/beta/SKILL.md": "---\nname: beta\n---\nRun ${CLAUDE_PLUGIN_ROOT}/x\n"})
	res := h.sync(lockfile("base", []record.Target{record.TargetClaudeCode, record.TargetCodex},
		h.pluginEntry("acme/kit", "1.0.0", files)), false)
	requireNoFailures(t, res)
	for _, inst := range res.Installed {
		require.Len(t, inst.Skipped, 1, inst.Change.Target)
		require.Contains(t, inst.Skipped[0].Reason, "CLAUDE_PLUGIN_ROOT")
	}
	require.NoDirExists(t, h.path(".claude/skills/acme--kit--beta"))
	require.NoDirExists(t, h.path(".agents/skills/acme--kit--beta"))
}

func TestAPartlyPlacedPluginIsReplayedOnTheNextSync(t *testing.T) {
	h := newHarness(t)
	cc := []record.Target{record.TargetClaudeCode}
	lf := lockfile("base", cc, h.pluginEntry("acme/kit", "1.0.0", kitFiles(nil)))
	requireNoFailures(t, h.sync(lf, false))

	// A crash after the first skill landed looks like this in the record.
	for i := range h.rec.Profiles[0].Entries {
		e := &h.rec.Profiles[0].Entries[i]
		e.Partial = true
		e.Components = e.Components[:1]
	}
	require.NoError(t, os.RemoveAll(h.path(".claude/skills/acme--kit--beta")))

	res := h.sync(lf, false)
	requireNoFailures(t, res)
	require.FileExists(t, h.path(".claude/skills/acme--kit--beta/SKILL.md"))
	e := h.entry(record.TargetClaudeCode, "acme/kit")
	require.False(t, e.Partial)
	require.Len(t, e.Components, 2)
	_ = hub.Plugin
}
