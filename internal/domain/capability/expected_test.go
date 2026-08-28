package capability_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/domain/capability"
)

// The expected set (T057, FR-018a). Every manifest below is CONFORMANT: the
// design's `network: {allow: []}` and `filesystem: {write: []}` are not fields
// either published specification defines (R1), so nothing here reproduces them
// and a test that did would be asserting against a manifest the hub refuses at
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

// A skill's frontmatter has no `extensions` key — the schema's
// additionalProperties:false refuses one — so its expectation lives under the
// same reverse-domain name inside `metadata`.
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
		// Without this branch a skill could never record an expectation at all, and
		// FR-027's "no expected set, so surface every host" would be permanent for
		// every skill in the catalog rather than a state a publisher can leave.
		rows, err := capability.Expected([]byte(skillManifest))
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, capability.FilesystemWrite, rows[0].Name)
		require.Equal(t, []string{"out/"}, rows[0].Detail)
	})
}

// FR-018a: recording an expectation is optional, and not recording one is not an
// error. It is the case where every discovered host is surfaced for review.
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
			// The one that motivates DisallowUnknownFields: a typo here is an
			// expectation that silently does not exist, and the finding it was meant
			// to suppress never appears.
			name:        "a misspelled key is not an empty expectation",
			manifest:    `{"extensions":{"dev.agent-manager":{"expectedCapabilties":[]}}}`,
			wantMessage: "expectedCapabilties",
		},
		{
			// An unrecognised name can never match anything Infer produces, so
			// keeping it would put a row on the page that suppresses nothing while
			// reading as though it does.
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

// FR-018a says an expectation with no level is still an expectation. The safe
// reading of one that names no level is the one that asks for a human.
func TestADeclarationWithNoLevelDefaultsToReview(t *testing.T) {
	rows, err := capability.Expected(
		[]byte(`{"extensions":{"dev.agent-manager":{"expectedCapabilities":[{"name":"network"}]}}}`))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, capability.LevelReview, rows[0].Level)
}

// FR-018's floor is a claim about how much trust a shell capability demands, not
// about who wrote the level down. A publisher declaring `shell: scoped` beside
// an inferred `shell: review` would read as a disagreement the scanner found,
// rather than as a level this model does not have.
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

// The two sides of FR-027 must be comparable, which means the same names, the
// same levels and the same ordering. A test for it exists because the two are
// produced by different functions from different inputs, and nothing in the
// compiler notices when one of them grows a name the other cannot produce.
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
