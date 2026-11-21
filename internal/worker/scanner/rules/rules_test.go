package rules_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/worker/scanner/rules"
)

func TestTheEmbeddedSchemaIsByteIdenticalToTheContract(t *testing.T) {
	embedded, err := rules.RawSchema()
	require.NoError(t, err)

	contract, err := os.ReadFile("../../../../specs/001-agent-manager-hub/contracts/rulepack.schema.json")
	require.NoError(t, err)

	require.Equal(t, string(contract), string(embedded),
		"internal/worker/scanner/rules/rulepack.schema.json is a copy of the contract; copy the contract over it")
}

func TestTheShippedPackLoadsAndAddressesOnlyKnownChecks(t *testing.T) {
	pack, err := rules.Builtin()
	require.NoError(t, err)

	require.Positive(t, pack.Len())
	require.Equal(t, rules.BuiltinOrigin, pack.Origin())

	// The api compares this shape to answer "rescan needed".
	require.Regexp(t, regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}\+[0-9a-f]{12}$`), pack.Version())
	require.True(t, strings.HasPrefix(pack.Version(), pack.Declared()+"+"))

	for _, rule := range pack.All() {
		require.NotEmpty(t, strings.TrimSpace(rule.Title), "%s has no title", rule.ID)
		require.NotEmpty(t, strings.TrimSpace(rule.Detail),
			"%s has no detail; a finding with no prose cannot be triaged", rule.ID)
		require.NotEmpty(t, rule.Fixtures.Trips, "%s ships no trip fixture", rule.ID)
		require.NotEmpty(t, rule.Fixtures.Clean, "%s ships no clean fixture", rule.ID)

		for _, fixture := range []string{rule.Fixtures.Trips, rule.Fixtures.Clean} {
			_, err := pack.FixtureFS(fixture)
			require.NoErrorf(t, err, "%s names a fixture the pack does not hold", rule.ID)
		}
	}
}

func TestEditingARuleMovesThePackVersion(t *testing.T) {
	first, err := rules.Load(minimalPack(t, "curl"), "test")
	require.NoError(t, err)

	same, err := rules.Load(minimalPack(t, "curl"), "test")
	require.NoError(t, err)
	require.Equal(t, first.Version(), same.Version(),
		"two directories holding the same rules must record the same pack version")

	tuned, err := rules.Load(minimalPack(t, "wget"), "test")
	require.NoError(t, err)
	require.NotEqual(t, first.Version(), tuned.Version(),
		"a tuned rule must move the pack version, or the rescan it needs is suppressed")
	require.Equal(t, first.Declared(), tuned.Declared())
}

func TestLoadRefusesAPackThatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(fstest.MapFS)
		message string
	}{
		{
			name:    "a rule naming a matcher this build does not implement",
			mutate:  func(m fstest.MapFS) { m["rules/SH-NET-002.yaml"] = rule(t, "kind: telepathy") },
			message: "/match/kind",
		},
		{
			name:    "a regex rule with no pattern",
			mutate:  func(m fstest.MapFS) { m["rules/SH-NET-002.yaml"] = rule(t, "kind: regex") },
			message: "match.pattern",
		},
		{
			name: "a condition that compares against a pattern the rule does not carry",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t, "kind: shell-ast\n  command: [curl]\n  condition: value-matches")
			},
			message: "value-matches",
		},
		{
			name: "a condition with no reading under the rule's extractor",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t,
					"kind: shell-ast\n  command: [curl]\n  extract: path-argument\n  condition: host-not-in-expected")
			},
			message: "host-not-in-expected",
		},
		{
			name: "a launcher pin judged on something other than a launched package",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t,
					"kind: shell-ast\n  command: [npx]\n  extract: matched-text\n  condition: launcher-unpinned")
			},
			message: "launcher-unpinned",
		},
		{
			name: "a declared-host check on something other than a host",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t,
					"kind: plugin-surface\n  extract: granted-tool\n  condition: host-not-declared")
			},
			message: "host-not-declared",
		},
		{
			name: "a plugin-surface rule with a shell extractor",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t, "kind: plugin-surface\n  extract: path-argument")
			},
			message: "no reading under match.kind plugin-surface",
		},
		{
			name: "a shell rule that matches every command unconditionally",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = rule(t, "kind: shell-ast\n  extract: matched-text\n  condition: always")
			},
			message: "matches every script",
		},
		{
			name: "a rule whose file name is not its id",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-009.yaml"] = m["rules/SH-NET-002.yaml"]
				delete(m, "rules/SH-NET-002.yaml")
			},
			message: "must be named",
		},
		{
			name: "a rule missing a fixture the constitution requires",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(
					string(m["rules/SH-NET-002.yaml"].Data), "  clean: fixtures/SH-NET-002/benign\n", ""))}
			},
			message: "does not conform",
		},
		{
			name: "a pack with no rules at all",
			mutate: func(m fstest.MapFS) {
				delete(m, "rules/SH-NET-002.yaml")
				m["rules/README.md"] = &fstest.MapFile{Data: []byte("rules go here\n")}
			},
			message: "holds no rules",
		},
		{
			name:    "a pack that declares no version",
			mutate:  func(m fstest.MapFS) { m["pack.yaml"] = &fstest.MapFile{Data: []byte("packVersion: \"\"\n")} },
			message: "declares no packVersion",
		},
		{
			name: "an id that is not a stable rule identifier",
			mutate: func(m fstest.MapFS) {
				m["rules/net-002.yaml"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(
					string(m["rules/SH-NET-002.yaml"].Data), "id: SH-NET-002", "id: net-002"))}
				delete(m, "rules/SH-NET-002.yaml")
			},
			message: "does not conform",
		},
		{
			// Whitespace satisfies the schema's minLength, so Go checks it.
			name: "a title that is whitespace only",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(
					string(m["rules/SH-NET-002.yaml"].Data),
					"title: Undeclared network egress", "title: \"   \""))}
			},
			message: "no title",
		},
		{
			name: "a detail that is whitespace only",
			mutate: func(m fstest.MapFS) {
				m["rules/SH-NET-002.yaml"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(
					string(m["rules/SH-NET-002.yaml"].Data),
					"detail: Prose a reviewer reads.", "detail: \"   \""))}
			},
			message: "no detail",
		},
	} {
		t.Run(tc.name+" is a load failure", func(t *testing.T) {
			pack := minimalPack(t, "curl")
			tc.mutate(pack)

			_, err := rules.Load(pack, "test")
			require.Error(t, err,
				"a pack that cannot do what it says must fail to load; a rule that silently matches nothing is indistinguishable from a clean catalog")
			require.ErrorIs(t, err, rules.ErrPack)
			require.Contains(t, err.Error(), tc.message)
		})
	}
}

func TestPathScopeUnderstandsRecursiveGlobs(t *testing.T) {
	pack, err := rules.Load(minimalPack(t, "curl"), "test")
	require.NoError(t, err)
	loaded := pack.All()[0]

	require.True(t, loaded.Match.InScope("scripts/anything.sh"))

	scoped, err := rules.Load(scopedPack(t, `["**/*.md", "package.json"]`), "test")
	require.NoError(t, err)
	match := scoped.All()[0].Match

	require.True(t, match.InScope("SKILL.md"))
	require.True(t, match.InScope("references/deep/notes.md"))
	require.True(t, match.InScope("package.json"))
	require.False(t, match.InScope("scripts/package.json"), "`*` does not cross a separator; `**/` does")
	require.False(t, match.InScope("notes.txt"))
}

func TestOpenFallsBackToTheBuiltInPackWhenTheDirectoryIsAbsent(t *testing.T) {
	pack, note, err := rules.Open(t.TempDir())
	require.NoError(t, err)
	require.Equal(t, rules.BuiltinOrigin, pack.Origin())
	require.Contains(t, note, "built-in",
		"the substitution has to be visible: a scanner running rules nobody mounted must say so")
}

func TestOpenLoadsAMountedPack(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/pack.yaml", []byte("packVersion: \"2026.01.01\"\n"), 0o600))
	require.NoError(t, os.Mkdir(dir+"/rules", 0o700))
	require.NoError(t, os.WriteFile(dir+"/rules/SH-NET-002.yaml", rule(t, "kind: shell-ast\n  command: [curl]").Data, 0o600))

	pack, note, err := rules.Open(dir)
	require.NoError(t, err)
	require.Equal(t, dir, pack.Origin())
	require.Empty(t, note)
	require.Equal(t, 1, pack.Len())
	require.True(t, strings.HasPrefix(pack.Version(), "2026.01.01+"))
}

func TestOpenFailsOnAMountedPackThatDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/pack.yaml", []byte("packVersion: \"2026.01.01\"\n"), 0o600))
	require.NoError(t, os.Mkdir(dir+"/rules", 0o700))
	require.NoError(t, os.WriteFile(dir+"/rules/SH-NET-002.yaml", []byte("id: SH-NET-002\n"), 0o600))

	_, _, err := rules.Open(dir)
	require.ErrorIs(t, err, rules.ErrPack)
}

func minimalPack(t *testing.T, command string) fstest.MapFS {
	t.Helper()
	return fstest.MapFS{
		"pack.yaml":                            &fstest.MapFile{Data: []byte("packVersion: \"2026.08.31\"\n")},
		"rules/SH-NET-002.yaml":                rule(t, "kind: shell-ast\n  command: ["+command+"]"),
		"fixtures/SH-NET-002/hostile/SKILL.md": &fstest.MapFile{Data: []byte("---\nname: x\ndescription: y\n---\n")},
		"fixtures/SH-NET-002/benign/SKILL.md":  &fstest.MapFile{Data: []byte("---\nname: x\ndescription: y\n---\n")},
	}
}

func scopedPack(t *testing.T, paths string) fstest.MapFS {
	t.Helper()
	pack := minimalPack(t, "curl")
	pack["rules/SH-NET-002.yaml"] = rule(t, "kind: regex\n  pattern: 'x'\n  paths: "+paths)
	return pack
}

// rule renders a valid rule document with the given match block.
func rule(t *testing.T, match string) *fstest.MapFile {
	t.Helper()
	body := `id: SH-NET-002
severity: high
check: network-allowlist
title: Undeclared network egress
detail: Prose a reviewer reads.
match:
  ` + match + `
evidence:
  quote: matched-node
fixtures:
  trips: fixtures/SH-NET-002/hostile
  clean: fixtures/SH-NET-002/benign
`
	if !strings.Contains(match, "extract:") {
		body = strings.Replace(body, "evidence:", "  extract: url-argument\nevidence:", 1)
	}
	if !strings.Contains(match, "condition:") {
		body = strings.Replace(body, "evidence:", "  condition: host-not-in-expected\nevidence:", 1)
	}
	return &fstest.MapFile{Data: []byte(body)}
}
