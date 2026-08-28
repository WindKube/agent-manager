package view_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

// The detail screen's derivations (US3). Everything here is a rendering
// decision the api deliberately does not make, so this is where each one is
// pinned.

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

	// US3 scenario 2 asks for a "named plugin VERSION" and the schema cannot
	// supply one: `parent_package_id` points at a package, and nothing links a
	// skill's version to the plugin version containing it. The parent's current
	// latest is the only version available, and it would make the sentence
	// rewrite itself when the parent publishes — so no version is stated.
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

// US3 scenarios 1 and 2 differ STRUCTURALLY. A skill does not get an empty
// contents section; it gets no contents section.
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
			{Kind: "mcp", Name: "terraform-registry"},
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
			// FR-027: with no expectation recorded, everything is surfaced rather
			// than silently accepted.
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
			// Declaring MORE than the bytes do is not a finding. It is a publisher
			// who left themselves room, and colouring it as a problem would train
			// people to ignore the column.
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

// FR-019's tag column, and the one thing about it that is not stored.
func TestAVersionShowsItsDistributionTagAndItsDerivedPinCountSeparately(t *testing.T) {
	latest := view.PackageVersion{Version: "2.4.1", DistTag: "latest"}
	require.Equal(t, "latest", latest.Tag())
	require.Empty(t, latest.PinLabel())

	// The design's middle row: neither latest nor archived, but pinned. `pinned
	// by N` is not a dist_tag value — it is derived from profile pins — so the
	// version carries `none` and a count.
	pinned := view.PackageVersion{Version: "2.4.0", DistTag: "none", PinnedBy: 2}
	require.Empty(t, pinned.Tag())
	require.Equal(t, "pinned by 2", pinned.PinLabel())

	// And a version is routinely both, which the design's single tag column
	// cannot express and two badges can.
	both := view.PackageVersion{Version: "3.0.0", DistTag: "latest", PinnedBy: 1}
	require.Equal(t, "latest", both.Tag())
	require.Equal(t, "pinned by 1", both.PinLabel())
}

func TestADependentProfileShowsHowItResolvesThePackage(t *testing.T) {
	require.Equal(t, "latest", view.Dependent{Mode: "latest"}.Resolution())
	require.Equal(t, "2.4.0", view.Dependent{Mode: "pinned", Pin: "2.4.0"}.Resolution())
	require.Equal(t, "^1.2", view.Dependent{Mode: "range", Pin: "^1.2"}.Resolution())
}

// Decision A, applied: the count beside an enumerable set is that enumeration's
// length. There is no head count, because a membership row can name a group and
// nothing here knows how many people are in one.
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

	// Key order is preserved: json.Indent is textual, so a reviewer reading a
	// manifest precisely because they do not trust it sees the publisher's own
	// ordering rather than Go's.
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
	// The column holds the FRONTMATTER as json, not the SKILL.md file, and the
	// heading says which of the two a reader is looking at.
	require.Equal(t, "SKILL.md frontmatter",
		view.Package{Kind: view.KindSkill, ManifestObject: "SKILL.md"}.ManifestPanelTitle())
}

// The link out of the catalog, and the reason it validates rather than escapes.
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
	// A slug is allowed to be several segments — internal/blob's profile keys say
	// so — and each one is checked.
	require.Equal(t, "/profiles/example/platform-engineer", view.ProfileHref("example/platform-engineer"))

	for _, hostile := range []string{"../admin", "", "a/../../b", "/x"} {
		require.Equalf(t, "/profiles", view.ProfileHref(hostile), "%q was not refused", hostile)
	}
}
