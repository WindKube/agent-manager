package pkgspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
)

// US1 scenario 2's archive, verbatim: "an archive whose root contains
// plugin.json, skills/, mcp.json, com.anthropic.claude-code/hooks/, .github/ and
// README.md".
func scenario2Tree(t *testing.T, prefix string) *bundle.Bundle {
	t.Helper()

	files := map[string]string{
		"plugin.json": conformantPlugin,
		"mcp.json": `{"$schema":"` + pkgspec.MCPSchema100 + `","mcpServers":{` +
			`"terraform-state":{"type":"stdio","command":"terraform-mcp","cwd":"${PLUGIN_ROOT}/skills/terraform-plan-review"}}}`,
		"skills/terraform-plan-review/SKILL.md":         "---\nname: terraform-plan-review\ndescription: Reviews a plan.\n---\n",
		"skills/terraform-plan-review/scripts/plan.sh":  "#!/bin/sh\nterraform plan\n",
		"skills/k8s-manifest-review/SKILL.md":           "---\nname: k8s-manifest-review\ndescription: Reviews manifests.\n---\n",
		"com.anthropic.claude-code/hooks/pre-tool.json": `{"hook":"pre-tool"}`,
		".github/workflows/ci.yml":                      "on: push\n",
		".github/CODEOWNERS":                            "* @platform\n",
		"README.md":                                     "# Platform Toolkit\n",
		"LICENSE":                                       "Apache-2.0\n",
	}

	b := bundle.New()
	for path, body := range files {
		require.NoError(t, b.Add(prefix+path, bundle.FileMode, []byte(body)))
	}
	return b
}

func TestTheSpecLayoutFilterReportsWhatItDropped(t *testing.T) {
	pkg, err := pkgspec.Inspect(scenario2Tree(t, ""), ".")
	require.NoError(t, err)

	t.Run("the stored tree excludes everything outside the spec layout", func(t *testing.T) {
		require.Equal(t, []string{
			"com.anthropic.claude-code/hooks/pre-tool.json",
			"mcp.json",
			"plugin.json",
			"skills/k8s-manifest-review/SKILL.md",
			"skills/terraform-plan-review/SKILL.md",
			"skills/terraform-plan-review/scripts/plan.sh",
		}, pkg.Files.Paths())
	})

	// FR-005's second half. Dropping silently would pass every assertion above.
	t.Run("every dropped path is reported, not merely absent", func(t *testing.T) {
		require.Equal(t, []string{
			".github/CODEOWNERS",
			".github/workflows/ci.yml",
			"LICENSE",
			"README.md",
		}, pkg.Layout.Dropped)
		require.Equal(t, []string{".github/", "LICENSE", "README.md"}, pkg.Layout.DroppedGroups())
	})

	t.Run("the report matches the design's archive-contents panel", func(t *testing.T) {
		require.Equal(t, []pkgspec.LayoutEntry{
			{Path: "plugin.json", Note: "schema valid", Kept: true},
			{Path: "skills/", Note: "2 skills", Kept: true},
			{Path: "mcp.json", Note: "1 server", Kept: true},
			{Path: "com.anthropic.claude-code/hooks/", Note: "client extension", Kept: true},
			{Path: ".github/, LICENSE, README.md", Note: "outside spec, dropped", Kept: false},
		}, pkg.Layout.Entries)
	})
}

func TestTheFilterRerootsToTheRequestedSubdirectory(t *testing.T) {
	tree := scenario2Tree(t, "plugins/platform-toolkit/")
	require.NoError(t, tree.Add("plugins/other/plugin.json", bundle.FileMode, []byte(`{"nope":true}`)))

	pkg, err := pkgspec.Inspect(tree, "plugins/platform-toolkit")
	require.NoError(t, err)
	require.Contains(t, pkg.Files.Paths(), "plugin.json")
	require.NotContains(t, pkg.Files.Paths(), "plugins/other/plugin.json")

	t.Run("an absent subdirectory is an error, not an empty publish", func(t *testing.T) {
		_, err := pkgspec.Inspect(tree, "plugins/does-not-exist")
		require.ErrorIs(t, err, pkgspec.ErrNoManifest)
	})

	t.Run("a traversal in the root is refused", func(t *testing.T) {
		_, err := pkgspec.Inspect(tree, "plugins/../../etc")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parent-directory reference")
	})
}

func TestAStandaloneSkillHasItsOwnLayout(t *testing.T) {
	b := bundle.New()
	require.NoError(t, b.Add("SKILL.md", bundle.FileMode,
		[]byte("---\nname: slack-digest\ndescription: Summarises a channel.\n---\n")))
	require.NoError(t, b.Add("scripts/digest.sh", bundle.ExecMode, []byte("#!/bin/sh\necho hi\n")))
	require.NoError(t, b.Add("references/api.md", bundle.FileMode, []byte("# API\n")))
	require.NoError(t, b.Add("README.md", bundle.FileMode, []byte("# Slack digest\n")))

	pkg, err := pkgspec.Inspect(b, ".")
	require.NoError(t, err)
	require.Equal(t, pkgspec.KindSkill, pkg.Kind)
	require.Equal(t, "slack-digest", pkg.Name)
	require.Equal(t, pkgspec.SkillManifest, pkg.ManifestObject)
	require.Equal(t, []string{"README.md"}, pkg.Layout.Dropped)
	require.Equal(t, []string{"SKILL.md", "references/api.md", "scripts/digest.sh"}, pkg.Files.Paths())

	t.Run("the executable bit survives the filter", func(t *testing.T) {
		file, ok := pkg.Files.Lookup("scripts/digest.sh")
		require.True(t, ok)
		require.Equal(t, bundle.ExecMode, file.Mode)
	})
}

func TestATreeWithNoManifestIsAnIngestionFailure(t *testing.T) {
	b := bundle.New()
	require.NoError(t, b.Add("README.md", bundle.FileMode, []byte("# Nothing here\n")))
	require.NoError(t, b.Add("skills/x/SKILL.md", bundle.FileMode, []byte("---\nname: x\ndescription: y\n---\n")))

	_, err := pkgspec.Inspect(b, ".")
	require.ErrorIs(t, err, pkgspec.ErrNoManifest)
}

func TestReverseDomainDirectoriesAreClientExtensionsAndDottedFilesAreNot(t *testing.T) {
	tree := scenario2Tree(t, "")
	require.NoError(t, tree.Add("dev.agent-manager/notes.md", bundle.FileMode, []byte("x")))
	require.NoError(t, tree.Add("a.b", bundle.FileMode, []byte("x")))
	require.NoError(t, tree.Add("notes.txt", bundle.FileMode, []byte("x")))

	pkg, err := pkgspec.Inspect(tree, ".")
	require.NoError(t, err)

	require.Contains(t, pkg.Files.Paths(), "dev.agent-manager/notes.md")
	require.Contains(t, pkg.Layout.Dropped, "a.b")
	require.Contains(t, pkg.Layout.Dropped, "notes.txt")

	kinds := make([]string, 0, len(pkg.Components))
	for _, component := range pkg.Components {
		if component.Kind == pkgspec.ComponentExt {
			kinds = append(kinds, component.Name)
		}
	}
	require.Equal(t, []string{"com.anthropic.claude-code", "dev.agent-manager"}, kinds)
}

// T038: components come from the file tree, so a manifest that lists them is
// irrelevant to derivation and a manifest that lists a MISSING one is a manifest
// validation failure.
func TestComponentsAreDerivedFromTheFileTree(t *testing.T) {
	pkg, err := pkgspec.Inspect(scenario2Tree(t, ""), ".")
	require.NoError(t, err)

	require.Equal(t, []pkgspec.Component{
		{Kind: pkgspec.ComponentSkill, Name: "k8s-manifest-review", Path: "skills/k8s-manifest-review", Note: "SKILL.md"},
		{Kind: pkgspec.ComponentSkill, Name: "terraform-plan-review", Path: "skills/terraform-plan-review", Note: "SKILL.md + scripts/"},
		{Kind: pkgspec.ComponentMCP, Name: "terraform-state", Path: "mcp.json", Note: "stdio"},
		{Kind: pkgspec.ComponentExt, Name: "com.anthropic.claude-code", Path: "com.anthropic.claude-code", Note: "client extension: hooks/"},
	}, pkg.Components)

	require.Equal(t, 2, pkg.ComponentCount(pkgspec.ComponentSkill))
	require.Equal(t, 1, pkg.ComponentCount(pkgspec.ComponentMCP))
	require.Equal(t, 1, pkg.ComponentCount(pkgspec.ComponentExt))
}

func TestAManifestDeclaringAComponentThatIsNotOnDiskIsAManifestFailure(t *testing.T) {
	// The spec's edge case. A conformant manifest can only name a component under
	// our own extension namespace, so that is where it is checked.
	manifest := withField(t, conformantPlugin, "extensions", `{"dev.agent-manager":{"components":["skills/does-not-exist"]}}`)

	tree := scenario2Tree(t, "")
	require.NoError(t, tree.Add("ignored", bundle.FileMode, nil))
	replaceFile(t, tree, "plugin.json", manifest)

	pkg, err := pkgspec.Inspect(tree, ".")
	require.ErrorIs(t, err, pkgspec.ErrManifestInvalid,
		"a component that is not on disk is a manifest validation failure, never a scan finding")
	require.NotNil(t, pkg, "the preview still needs the entry list")
	require.NotEmpty(t, pkg.Layout.Entries)

	t.Run("a component that IS on disk passes", func(t *testing.T) {
		ok := withField(t, conformantPlugin, "extensions",
			`{"dev.agent-manager":{"components":["skills/terraform-plan-review","mcp.json"]}}`)
		good := scenario2Tree(t, "")
		replaceFile(t, good, "plugin.json", ok)
		_, err := pkgspec.Inspect(good, ".")
		require.NoError(t, err)
	})

	t.Run("an mcp cwd pointing outside the tree is a manifest failure", func(t *testing.T) {
		broken := scenario2Tree(t, "")
		replaceFile(t, broken, "mcp.json", []byte(`{"$schema":"`+pkgspec.MCPSchema100+
			`","mcpServers":{"x":{"type":"stdio","command":"c","cwd":"${PLUGIN_ROOT}/skills/gone"}}}`))
		_, err := pkgspec.Inspect(broken, ".")
		require.ErrorIs(t, err, pkgspec.ErrManifestInvalid)
	})
}

func TestASkillsDirectoryWithNoSkillManifestFailsClosed(t *testing.T) {
	tree := scenario2Tree(t, "")
	require.NoError(t, tree.Add("skills/empty/notes.md", bundle.FileMode, []byte("nothing here")))

	_, err := pkgspec.Inspect(tree, ".")
	require.ErrorIs(t, err, pkgspec.ErrTreeInvalid)
}

func TestAContainedSkillIsValidatedOnTheSameTermsAsAStandaloneOne(t *testing.T) {
	tree := scenario2Tree(t, "")
	replaceFile(t, tree, "skills/k8s-manifest-review/SKILL.md",
		[]byte("---\nname: k8s-manifest-review\ndescription: y\nproviders:\n  - claude-code\n---\n"))

	_, err := pkgspec.Inspect(tree, ".")
	require.ErrorIs(t, err, pkgspec.ErrManifestInvalid)
	require.Contains(t, err.Error(), "skills/k8s-manifest-review/SKILL.md")
}

// replaceFile rebuilds the bundle with one path's contents swapped. Bundle.Add
// refuses a duplicate path by design (a version's identity is its tree), so there
// is no in-place edit.
func replaceFile(t *testing.T, b *bundle.Bundle, path string, body []byte) {
	t.Helper()

	files := b.Files()
	replaced := make([]bundle.File, 0, len(files))
	found := false
	for _, file := range files {
		if file.Path == path {
			file.Data = body
			found = true
		}
		replaced = append(replaced, file)
	}
	require.Truef(t, found, "%s is not in the tree", path)

	*b = *bundle.New()
	for _, file := range replaced {
		require.NoError(t, b.Add(file.Path, file.Mode, file.Data))
	}
}
