package view_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

func TestTheOriginLineDistinguishesThePluginAndSkillVariants(t *testing.T) {
	plugin := view.Package{
		Kind: view.KindPlugin, SpecVersion: "1.0.0",
		Components: []view.Component{
			{Kind: "skill", Name: "a"}, {Kind: "skill", Name: "b"},
			{Kind: "mcp", Name: "registry"},
			{Kind: "ext", Name: "com.anthropic.claude-code"},
		},
	}
	require.Equal(t, "Portable package · Agent Plugins 1.0.0 · 2 skills, 1 MCP server", plugin.Origin())

	t.Run("a standalone skill says so", func(t *testing.T) {
		skill := view.Package{Kind: view.KindSkill}
		require.Equal(t, "Agent Skills spec · standalone skill", skill.Origin())
	})

	// Nothing links a skill's version to the plugin version containing it, so no version is stated.
	t.Run("a contained skill names the parent package and no version", func(t *testing.T) {
		skill := view.Package{Kind: view.KindSkill,
			ParentID: "example/platform-toolkit", ParentName: "platform-toolkit"}
		require.Equal(t, "Agent Skills spec · distributed inside Platform Toolkit", skill.Origin())
		require.NotContains(t, skill.Origin(), "1.3.0")
	})

	t.Run("a plugin whose manifest names no schema still renders a line", func(t *testing.T) {
		require.Equal(t, "Portable package · Agent Plugins · 0 skills, 0 MCP servers",
			view.Package{Kind: view.KindPlugin}.Origin())
	})
}

// A skill gets no contents section at all, not an empty one.
func TestOnlyAPluginHasAContentsSection(t *testing.T) {
	require.True(t, view.Package{Kind: view.KindPlugin}.HasContents())
	require.False(t, view.Package{Kind: view.KindSkill}.HasContents())
	require.Empty(t, view.Package{Kind: view.KindSkill,
		Components: []view.Component{{Kind: "skill", Name: "x"}}}.Tree(),
		"a skill renders no tree even if something handed it components")
}

func TestTheTreeIsDerivedFromTheComponentRows(t *testing.T) {
	plugin := view.Package{
		Kind: view.KindPlugin, Name: "platform-toolkit", ManifestObject: "plugin.json",
		Components: []view.Component{
			{Kind: "skill", Name: "terraform-module-review"},
			{Kind: "skill", Name: "adr-writer"},
			{Kind: "mcp", Name: "terraform-registry", Path: "mcp.json#/mcpServers/terraform-registry"},
			{Kind: "ext", Name: "com.anthropic.claude-code"},
		},
	}

	require.Equal(t, strings.Join([]string{
		"platform-toolkit/",
		"├── plugin.json",
		"├── skills/",
		"│   ├── terraform-module-review/",
		"│   └── adr-writer/",
		"├── mcp.json",
		"└── com.anthropic.claude-code/",
	}, "\n"), plugin.Tree())

	t.Run("an MCP server declared by the Claude Code extension draws no mcp.json", func(t *testing.T) {
		ext := view.Package{Kind: view.KindPlugin, Name: "guard", ManifestObject: "plugin.json",
			Components: []view.Component{{Kind: "mcp", Name: "docs", Path: "com.anthropic.claude-code/.mcp.json#/mcpServers/docs"}}}
		require.NotContains(t, ext.Tree(), "mcp.json")
	})

	t.Run("a plugin with no mcp component draws no mcp.json", func(t *testing.T) {
		bare := view.Package{Kind: view.KindPlugin, Name: "solo", ManifestObject: "plugin.json",
			Components: []view.Component{{Kind: "skill", Name: "only"}}}
		require.NotContains(t, bare.Tree(), "mcp.json")
		require.Contains(t, bare.Tree(), "└── skills/")
	})
}

func TestTheCapabilityComparisonNamesTheRelationshipAndNotADecision(t *testing.T) {
	facet := func(level string) view.CapabilityFacet {
		return view.CapabilityFacet{Present: true, Level: level}
	}

	for _, tc := range []struct {
		name string
		row  view.CapabilityRow
		want string
		tone string
	}{
		{
			// With no expectation recorded, everything is surfaced rather than silently accepted.
			name: "inferred with nothing declared",
			row:  view.CapabilityRow{Name: "network", Inferred: facet("allowlisted")},
			want: view.CapabilityUndeclared, tone: "warn",
		},
		{
			name: "declared but never observed",
			row:  view.CapabilityRow{Name: "shell", Expected: facet("review")},
			want: view.CapabilityUnobserved, tone: "warn",
		},
		{
			name: "the bytes demand more trust than the publisher declared",
			row: view.CapabilityRow{Name: "filesystem.write",
				Inferred: facet("review"), Expected: facet("scoped")},
			want: view.CapabilityExceeds, tone: "dan",
		},
		{
			name: "the two agree",
			row: view.CapabilityRow{Name: "network",
				Inferred: facet("allowlisted"), Expected: facet("allowlisted")},
			want: view.CapabilityWithin, tone: "fg2",
		},
		{
			// Declaring more than the bytes need is not a problem and must not be coloured as one.
			name: "the publisher declared more than the bytes demand",
			row: view.CapabilityRow{Name: "network",
				Inferred: facet("allowlisted"), Expected: facet("review")},
			want: view.CapabilityWithin, tone: "fg2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.row.Status())
			require.Equal(t, tc.tone, tc.row.Tone())
		})
	}
}

// An indefinite target set must never render as a complete one.
func TestTargetsSayWhenTheyAreNotTheWholeSet(t *testing.T) {
	require.Equal(t, "slack.com, and targets not determined",
		view.CapabilityFacet{Present: true, Detail: []string{"slack.com"}, Indefinite: true}.Targets())
	require.Equal(t, "targets not determined",
		view.CapabilityFacet{Present: true, Indefinite: true}.Targets())
	require.Empty(t, view.CapabilityFacet{}.Targets())
}

func TestAVersionShowsItsDistributionTagAndItsDerivedPinCountSeparately(t *testing.T) {
	latest := view.PackageVersion{Version: "2.4.1", DistTag: "latest"}
	require.Equal(t, "latest", latest.Tag())
	require.Empty(t, latest.PinLabel())

	pinned := view.PackageVersion{Version: "2.4.0", DistTag: "none", PinnedBy: 2}
	require.Empty(t, pinned.Tag())
	require.Equal(t, "pinned by 2", pinned.PinLabel())

	both := view.PackageVersion{Version: "3.0.0", DistTag: "latest", PinnedBy: 1}
	require.Equal(t, "latest", both.Tag())
	require.Equal(t, "pinned by 1", both.PinLabel())
}

func TestADependentProfileShowsHowItResolvesThePackage(t *testing.T) {
	require.Equal(t, "latest", view.Dependent{Mode: "latest"}.Resolution())
	require.Equal(t, "2.4.0", view.Dependent{Mode: "pinned", Pin: "2.4.0"}.Resolution())
	require.Equal(t, "^1.2", view.Dependent{Mode: "range", Pin: "^1.2"}.Resolution())
}

// The count is the list's length, never a head count: a membership can name a group.
func TestTheDependentsLineCountsWhatItLists(t *testing.T) {
	require.Equal(t, "No profile you can see uses this package",
		view.Package{}.DependentsLine())
	require.Equal(t, "Used by 1 profile you can see",
		view.Package{Dependents: []view.Dependent{{}}}.DependentsLine())
	require.Equal(t, "Used by 3 profiles you can see",
		view.Package{Dependents: []view.Dependent{{}, {}, {}}}.DependentsLine())

	for _, n := range []int{0, 1, 3} {
		line := view.Package{Dependents: make([]view.Dependent, n)}.DependentsLine()
		require.NotContains(t, line, "people",
			"a head count cannot be computed from membership rows that may name groups")
	}
}

func TestTheManifestIsIndentedForDisplayAndNotReEncoded(t *testing.T) {
	p := view.Package{Manifest: `{"name":"x","keywords":["b","a"],"version":"1.0.0"}`}

	// Key order is preserved, not Go's map order.
	require.Equal(t, "{\n  \"name\": \"x\",\n  \"keywords\": [\n    \"b\",\n    \"a\"\n  ],\n  \"version\": \"1.0.0\"\n}",
		p.ManifestText())

	t.Run("a manifest that cannot be indented is shown verbatim, not replaced", func(t *testing.T) {
		broken := view.Package{Manifest: "not json"}
		require.Equal(t, "not json", broken.ManifestText())
	})
}

func TestTheManifestPanelNamesWhichDocumentItIsShowing(t *testing.T) {
	require.Equal(t, "plugin.json",
		view.Package{Kind: view.KindPlugin, ManifestObject: "plugin.json"}.ManifestPanelTitle())
	require.Equal(t, "SKILL.md frontmatter",
		view.Package{Kind: view.KindSkill, ManifestObject: "SKILL.md"}.ManifestPanelTitle())
}

func TestPackageHrefRefusesAnIdThatIsNotTwoObjectKeySegments(t *testing.T) {
	require.Equal(t, "/packages/example/platform-toolkit",
		view.PackageHref("example/platform-toolkit"))
	require.Equal(t, "/packages/community/aws-cost-explainer",
		view.PackageHref("community/aws-cost-explainer"))

	for _, hostile := range []string{
		"../../etc/passwd",
		"..%2F..%2Fetc",
		"evil/<script>alert(1)</script>",
		"example/platform/toolkit",
		"/leading-slash",
		"example",
		"",
		".hidden/thing",
	} {
		got := view.PackageHref(hostile)
		require.Equalf(t, "/catalog", got, "%q produced %q", hostile, got)
	}
}

func TestProfileHrefRefusesASlugThatCouldClimbOut(t *testing.T) {
	require.Equal(t, "/profiles/platform-engineer", view.ProfileHref("platform-engineer"))
	// A slug may be several segments, and each is checked.
	require.Equal(t, "/profiles/example/platform-engineer", view.ProfileHref("example/platform-engineer"))

	for _, hostile := range []string{"../admin", "", "a/../../b", "/x"} {
		require.Equalf(t, "/profiles", view.ProfileHref(hostile), "%q was not refused", hostile)
	}
}

func TestProfileOptionsGroupByVisibility(t *testing.T) {
	pkg := view.Package{ProfileOptions: []view.ProfileOption{
		{Slug: "kw-private", Visibility: "private"},
		{Slug: "platform-baseline", Visibility: "organisation"},
		{Slug: "sre-oncall", Visibility: "shared"},
		{Slug: "another-private", Visibility: "private"},
	}}

	require.Len(t, pkg.ProfileOptionsFor("private"), 2)
	require.Len(t, pkg.ProfileOptionsFor("shared"), 1)
	require.Len(t, pkg.ProfileOptionsFor("organisation"), 1)
	require.Empty(t, pkg.ProfileOptionsFor("bogus"))
}

func TestProfileOptionsHeldMarksExactlyTheDependentSlugs(t *testing.T) {
	options := []view.ProfileOption{
		{Slug: "platform-engineer", Name: "Platform Engineer"},
		{Slug: "sre-oncall", Name: "SRE On-call"},
	}
	dependents := []view.Dependent{{Slug: "platform-engineer", Mode: "latest"}}

	marked := view.ProfileOptionsHeld(options, dependents)
	require.True(t, marked[0].Held, "the dependent profile is marked held")
	require.False(t, marked[1].Held, "a profile absent from Dependents is not held")

	// The input slice is never mutated.
	require.False(t, options[0].Held)
}

func TestComponentsAreGroupedByKindWithTheirSurface(t *testing.T) {
	p := view.Package{Kind: view.KindPlugin, Components: []view.Component{
		{Kind: "skill", Name: "a"},
		{Kind: "mcp", Name: "local", Note: "stdio", Transport: "stdio", Target: "npx -y pkg@1.2.3"},
		{Kind: "hook", Name: "PreToolUse", Event: "PreToolUse", Target: "./guard.sh"},
		{Kind: "hook", Name: "PostToolUse", Event: "PostToolUse", Matcher: "Edit"},
		{Kind: "hook", Name: "SessionStart", Event: "SessionStart", Target: "./start.sh"},
		{Kind: "agent", Name: "reviewer", Note: "Reviews."},
	}}

	groups := p.ComponentGroups()
	labels := make([]string, 0, len(groups))
	for _, group := range groups {
		labels = append(labels, group.Label)
	}
	require.Equal(t, []string{"Skills", "Agents", "Hooks", "MCP servers"}, labels, "empty kinds are omitted")
	require.Len(t, groups[2].Components, 3)

	require.Equal(t, "PreToolUse · matcher every tool · ./guard.sh", groups[2].Components[0].Detail())
	require.Equal(t, "PostToolUse · matcher Edit", groups[2].Components[1].Detail())
	require.Equal(t, "SessionStart · ./start.sh", groups[2].Components[2].Detail(), "no tool matcher on a session event")
	require.Equal(t, "stdio · npx -y pkg@1.2.3", groups[3].Components[0].Detail())
	require.Equal(t, "Reviews.", groups[1].Components[0].Detail())
	require.Equal(t, "1 skill · 1 MCP · 1 agent · 3 hooks · 0 extensions", p.ContentsNote())
}
