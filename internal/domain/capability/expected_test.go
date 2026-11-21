package capability_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/capability"
)

// Every manifest below is schema-conformant; the hub refuses any other at
// registration.

const pluginManifest = `{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "slack-digest",
  "version": "0.5.1",
  "extensions": {
    "dev.agent-manager": {
      "expectedCapabilities": [
        {"name": "network", "level": "allowlisted", "detail": ["slack.com"]},
        {"name": "filesystem.read", "level": "scoped", "detail": ["references/"]}
      ]
    }
  }
}`

// Skill frontmatter refuses an `extensions` key, so the expectation lives
// under the same namespace inside `metadata`.
const skillManifest = `{
  "name": "pii-redactor",
  "description": "Finds and masks personal data.",
  "metadata": {
    "dev.agent-manager": {
      "expectedCapabilities": [{"name": "filesystem.write", "detail": ["out/"]}]
    }
  }
}`

func TestExpectedReadsTheDeclarationFromEitherSpecsNamespaceObject(t *testing.T) {
	t.Run("a plugin declares under extensions", func(t *testing.T) {
		rows, err := capability.Expected([]byte(pluginManifest))
		require.NoError(t, err)
		require.Len(t, rows, 2)

		require.Equal(t, capability.Network, rows[0].Name)
		require.Equal(t, capability.SourceExpected, rows[0].Source)
		require.Equal(t, capability.LevelAllowlisted, rows[0].Level)
		require.Equal(t, []string{"slack.com"}, rows[0].Detail)

		require.Equal(t, capability.FilesystemRead, rows[1].Name)
		require.Equal(t, capability.LevelScoped, rows[1].Level)
	})

	t.Run("a standalone skill declares under metadata", func(t *testing.T) {
		rows, err := capability.Expected([]byte(skillManifest))
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, capability.FilesystemWrite, rows[0].Name)
		require.Equal(t, []string{"out/"}, rows[0].Detail)
	})
}

func TestNoDeclarationIsNoRowsAndNoError(t *testing.T) {
	for _, tc := range []struct{ name, manifest string }{
		{"a manifest with no extensions object at all", `{"name":"adr-writer"}`},
		{"a manifest whose extensions name other namespaces",
			`{"name":"adr-writer","extensions":{"com.example.other":{"x":1}}}`},
		{"an explicitly null namespace", `{"name":"x","extensions":{"dev.agent-manager":null}}`},
		{"an empty manifest", ``},
		{"an empty declaration", `{"name":"x","extensions":{"dev.agent-manager":{}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := capability.Expected([]byte(tc.manifest))
			require.NoError(t, err)
			require.Empty(t, rows)
		})
	}
}

func TestAnUnusableDeclarationIsRefusedRatherThanQuietlyDropped(t *testing.T) {
	for _, tc := range []struct{ name, manifest, wantMessage string }{
		{
			name:        "a misspelled key is not an empty expectation",
			manifest:    `{"extensions":{"dev.agent-manager":{"expectedCapabilties":[]}}}`,
			wantMessage: "expectedCapabilties",
		},
		{
			name:        "a capability name outside the closed set",
			manifest:    `{"extensions":{"dev.agent-manager":{"expectedCapabilities":[{"name":"gpu"}]}}}`,
			wantMessage: `"gpu"`,
		},
		{
			name:        "a level outside the enum",
			manifest:    `{"extensions":{"dev.agent-manager":{"expectedCapabilities":[{"name":"shell","level":"trusted"}]}}}`,
			wantMessage: `"trusted"`,
		},
		{
			name:        "a manifest that is not json",
			manifest:    `not json at all`,
			wantMessage: "read the stored manifest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := capability.Expected([]byte(tc.manifest))
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantMessage)
			require.Empty(t, rows)
		})
	}
}

func TestADeclarationWithNoLevelDefaultsToReview(t *testing.T) {
	rows, err := capability.Expected(
		[]byte(`{"extensions":{"dev.agent-manager":{"expectedCapabilities":[{"name":"network"}]}}}`))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, capability.LevelReview, rows[0].Level)
}

func TestAnExpectedShellCapabilityIsAlsoNeverBelowReview(t *testing.T) {
	for _, declared := range []string{"scoped", "allowlisted", "review"} {
		rows, err := capability.Expected([]byte(
			`{"extensions":{"dev.agent-manager":{"expectedCapabilities":[{"name":"shell","level":"` +
				declared + `"}]}}}`))
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equalf(t, capability.LevelReview, rows[0].Level,
			"declared %q was not raised to review", declared)
	}
}

// Expected and Infer come from different inputs, and the compiler won't
// notice if one grows a name the other cannot produce.
func TestBothSourcesSpeakTheSameVocabulary(t *testing.T) {
	inferred := capability.Infer(capability.Artefacts{
		Files: []capability.File{{Path: "scripts/run.sh", Class: capability.ClassScript}},
		Commands: []capability.Command{
			{Name: "curl", Args: []string{"https://slack.com/api"}},
			{Name: "cat", Args: []string{"references/notes.md"}},
			{Name: "tee", Args: []string{"out/digest.md"}},
		},
	})

	expected, err := capability.Expected([]byte(`{"extensions":{"dev.agent-manager":{
		"expectedCapabilities":[
			{"name":"network","level":"allowlisted","detail":["slack.com"]},
			{"name":"filesystem.read","level":"scoped"},
			{"name":"filesystem.write","level":"scoped"},
			{"name":"shell","level":"review"}]}}}`))
	require.NoError(t, err)

	require.Equal(t, names(inferred), names(expected),
		"the two sides must name the same capabilities in the same order or the panel compares nothing")
	for _, row := range append(append([]capability.Capability{}, inferred...), expected...) {
		require.True(t, row.Level.Valid(), "%+v has a level outside the enum", row)
		require.Contains(t, capability.Names, row.Name)
	}
}
