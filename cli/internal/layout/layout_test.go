package layout_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const (
	home      = "/home/tester"
	digestHex = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testDigest(t *testing.T) record.Digest {
	t.Helper()
	d, err := record.ParseDigest(digestHex)
	require.NoError(t, err)
	return d
}

func registry(t *testing.T, configDir string) *layout.Registry {
	t.Helper()
	reg, err := layout.NewRegistry(layout.Config{HomeDir: home, ClaudeConfigDir: configDir})
	require.NoError(t, err)
	return reg
}

func claudeCode(t *testing.T, configDir string) layout.Target {
	t.Helper()
	target, err := registry(t, configDir).Resolve(record.TargetClaudeCode)
	require.NoError(t, err)
	return target
}

func skill(id, version string) layout.Request {
	return layout.Request{ID: id, Version: version, Kind: record.KindSkill}
}

// Expected paths are hand-written from R2's observation — user scope is
// $CLAUDE_CONFIG_DIR/skills, else ~/.claude/skills, and a skill is
// <root>/<dir>/SKILL.md — not read back from a run.
func TestClaudeCodePlacesAStandaloneSkillWhereTheAgentLooks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configDir string
		req       layout.Request
		dest      string
	}{
		{
			name: "default root is the home config dir, with no XDG indirection",
			req:  skill("acme/code-review", "1.2.3"),
			dest: "/home/tester/.claude/skills/acme--code-review",
		},
		{
			name:      "CLAUDE_CONFIG_DIR relocates the root",
			configDir: "/elsewhere/claude",
			req:       skill("acme/code-review", "1.2.3"),
			dest:      "/elsewhere/claude/skills/acme--code-review",
		},
		{
			name: "a package named after the reserved sync directory is not the reserved directory",
			req:  skill("acme/synced", "0.1.0"),
			dest: "/home/tester/.claude/skills/acme--synced",
		},
		{
			name: "a semver with build metadata is carried verbatim and never parsed",
			req:  skill("acme/tool", "1.0.0+build.5"),
			dest: "/home/tester/.claude/skills/acme--tool",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := claudeCode(t, tc.configDir).Place(tc.req)
			require.NoError(t, err)

			require.Equal(t, record.TargetClaudeCode, got.Target)
			require.Equal(t, filepath.FromSlash(tc.dest), got.Dest)
			require.Equal(t, filepath.Join(got.Dest, "SKILL.md"), got.EntryFilePath)
			require.Equal(t, filepath.Join(got.Dest, ".agent-manager.json"), got.MarkerPath)
			require.Equal(t, filepath.Dir(got.Dest), got.Root)
			require.Equal(t, tc.req.Version, got.Version)
			require.Equal(t, tc.req.ID, got.Package.ID())
		})
	}
}

// R2's negative control, as a regression test: XDG_CONFIG_HOME is not read at
// all, and an XDG-first resolver — the obvious thing to write on Linux —
// installs to a directory the agent never opens. This package reads no
// environment, so the assertion is that setting it changes nothing.
func TestClaudeCodeIgnoresXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/home/tester/.config")

	got, err := claudeCode(t, "").Place(skill("acme/code-review", "1.0.0"))
	require.NoError(t, err)
	require.Equal(t, filepath.FromSlash("/home/tester/.claude/skills/acme--code-review"), got.Dest)
	require.NotContains(t, got.Dest, ".config")
}

// FR-023. The interesting half is not that the two differ but that the mapping
// is injective: a hyphen may appear inside either segment, so a single-character
// separator maps two distinct packages onto one directory.
func TestFR023CollidingNamesAcrossPublishersGetDistinctDirectories(t *testing.T) {
	t.Parallel()

	target := claudeCode(t, "")

	acme, err := target.Place(skill("acme/code-review", "1.0.0"))
	require.NoError(t, err)
	globex, err := target.Place(skill("globex/code-review", "4.0.0"))
	require.NoError(t, err)

	require.NotEqual(t, acme.Dest, globex.Dest)
	require.Equal(t, "acme--code-review", acme.DirName)
	require.Equal(t, "globex--code-review", globex.DirName)
	require.Equal(t, acme.Root, globex.Root, "same root, different directories")

	t.Run("the namespace and name split is unambiguous across the hyphen", func(t *testing.T) {
		shifted, err := target.Place(skill("acme-code/review", "1.0.0"))
		require.NoError(t, err)
		require.Equal(t, "acme-code--review", shifted.DirName)
		require.NotEqual(t, acme.DirName, shifted.DirName,
			"acme/code-review and acme-code/review are different packages and must not share a directory")
	})

	t.Run("neither directory is inside the other's removable set", func(t *testing.T) {
		for _, path := range (record.Entry{Dest: acme.Dest}).RemovablePaths() {
			require.NotEqual(t, globex.Dest, path)
			require.False(t, strings.HasPrefix(globex.Dest, path+string(filepath.Separator)))
		}
	})

	t.Run("the destination does not move when the version does", func(t *testing.T) {
		// A version in the path would turn an upgrade into a write plus a
		// removal — two operations with a window where both or neither exist —
		// instead of R3's single rename of one directory.
		upgraded, err := target.Place(skill("acme/code-review", "9.9.9"))
		require.NoError(t, err)
		require.Equal(t, acme.Dest, upgraded.Dest)
	})

	t.Run("the namespace is present even with no collision to resolve", func(t *testing.T) {
		lonely, err := target.Place(skill("solo/only-one", "1.0.0"))
		require.NoError(t, err)
		require.Equal(t, "solo--only-one", lonely.DirName,
			"disambiguating on demand would move an installed directory when an unrelated package appears")
	})
}

func TestPackageIDRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		id    string
		wants string
	}{
		{"one segment", "code-review", "one segment"},
		{"three segments", "acme/team/code-review", "more than two segments"},
		{"empty namespace", "/code-review", "empty segment"},
		{"empty name", "acme/", "empty segment"},
		{"empty id", "", "one segment"},
		{"just a slash", "/", "empty segment"},
		{"publisher slug mistaken for an id", "example/platform/pii-redactor", "more than two segments"},
		{"traversal in the namespace", "../code-review", "must start with a letter or digit"},
		{"traversal in the name", "acme/..", "must start with a letter or digit"},
		{"nested traversal", "acme/a..b", "parent-directory reference"},
		{"colon, a separator to too many tools", "acme/code:review", `contains ':'`},
		{"backslash", `acme\team/x`, `contains '\\'`},
		{"space", "acme/code review", `contains ' '`},
		{"newline", "acme/code\nreview", `contains '\n'`},
		{"nul", "acme/code\x00review", `contains '\x00'`},
		{"asterisk", "acme/code*", `contains '*'`},
		{"leading dot", "acme/.hidden", "must start with a letter or digit"},
		{"leading hyphen", "-acme/x", "must start with a letter or digit"},
		{"the separator inside a segment", "acme--corp/x", "separates the namespace from the name"},
		{"the separator inside the name", "acme/code--review", "separates the namespace from the name"},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			t.Parallel()

			_, err := layout.ParsePackageID(tc.id)
			require.ErrorIs(t, err, layout.ErrPackageID)
			require.Contains(t, err.Error(), tc.wants)
			require.Contains(t, err.Error(), strconv.Quote(tc.id),
				"the refusal must name the id")

			// The same refusal must reach the caller through the target, so no
			// path is ever derived from an id that only ParsePackageID rejects.
			_, placeErr := claudeCode(t, "").Place(layout.Request{ID: tc.id, Version: "1.0.0", Kind: record.KindSkill})
			require.ErrorIs(t, placeErr, layout.ErrPackageID)
		})
	}
}

func TestPackageIDAcceptsWhatTheHubCanStore(t *testing.T) {
	t.Parallel()

	// Hand-derived from the hub's object-key segment pattern,
	// ^[A-Za-z0-9][A-Za-z0-9._+-]*$: a package whose segments fall outside it
	// has no bundle object and cannot exist in the catalog.
	for _, id := range []string{
		"acme/code-review",
		"com.anthropic.claude-code/pdf-tools",
		"WindKube/agent-manager",
		"acme2/tool_v2",
		"a/b",
		"acme/tool+extras",
	} {
		t.Run(id+" is accepted", func(t *testing.T) {
			t.Parallel()
			pkg, err := layout.ParsePackageID(id)
			require.NoError(t, err)
			require.Equal(t, id, pkg.ID())
			require.NoError(t, layout.ValidateDirName(pkg.DirName()))
		})
	}
}

// R3 requires this of internal/layout by name: the removable set per entry is
// exactly {dest, dest+AsideSuffix}, so a package legitimately installed at
// x.amctl-old would sit inside the removable set of the package at x and prune
// would delete a live install.
func TestNoPackageInstallsToAnAsideOrStagingPath(t *testing.T) {
	t.Parallel()

	t.Run("a directory name ending in the aside suffix is refused", func(t *testing.T) {
		t.Parallel()
		err := layout.ValidateDirName("acme--tool" + record.AsideSuffix)
		require.ErrorIs(t, err, layout.ErrDirName)
		require.Contains(t, err.Error(), record.AsideSuffix)
	})

	t.Run("a package whose name ends in the aside suffix is refused at placement", func(t *testing.T) {
		t.Parallel()
		// Reachable through the hub's charset: `.`, `-` and letters are all legal
		// in a package name, so this is a package the catalog could really hold.
		_, err := claudeCode(t, "").Place(skill("acme/tool.amctl-old", "1.0.0"))
		require.ErrorIs(t, err, layout.ErrDirName)
		require.Contains(t, err.Error(), record.AsideSuffix)
	})

	t.Run("the staging directory name is refused", func(t *testing.T) {
		t.Parallel()
		err := layout.ValidateDirName(layout.StagingDirName)
		require.ErrorIs(t, err, layout.ErrDirName)
	})

	t.Run("staging is a sibling of the destination", func(t *testing.T) {
		t.Parallel()
		got, err := claudeCode(t, "").Place(skill("acme/code-review", "1.0.0"))
		require.NoError(t, err)
		require.Equal(t, filepath.Join(got.Root, layout.StagingDirName), got.StagingRoot(),
			"a central staging directory makes the swap's rollback fail with EXDEV exactly when it is needed")
		require.Equal(t, filepath.Dir(got.Dest), filepath.Dir(got.StagingRoot()))
	})

	t.Run("the aside path is the record's suffix and not a second literal", func(t *testing.T) {
		t.Parallel()
		got, err := claudeCode(t, "").Place(skill("acme/code-review", "1.0.0"))
		require.NoError(t, err)
		require.Equal(t, got.Dest+record.AsideSuffix, got.AsidePath())
		require.ElementsMatch(t, []string{got.Dest, got.AsidePath()},
			(record.Entry{Dest: got.Dest}).RemovablePaths())
	})
}

func TestDirNameRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dirName string
		wants   string
	}{
		{"empty", "", "is empty"},
		{"dot", ".", "path traversal"},
		{"dot dot", "..", "path traversal"},
		{"a path", "acme--tool/nested", "not a single directory name"},
		{"a backslash-separated path", `acme--tool\nested`, "not a single directory name"},
		{"dot-prefixed", ".acme--tool", "dot-prefixed"},
		{"trailing dot", "acme--tool.", "some filesystems strip"},
		{"trailing space", "acme--tool ", "some filesystems strip"},
		{"colon", "acme--to:ol", "not usable in a filename"},
		{"control character", "acme--to\x01ol", "not usable in a filename"},
		{"device name", "nul", "reserved device name"},
		{"device name with an extension", "CON.md", "reserved device name"},
		{"over the length limit", strings.Repeat("a", 256), "over the 255-byte limit"},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			t.Parallel()
			err := layout.ValidateDirName(tc.dirName)
			require.ErrorIs(t, err, layout.ErrDirName)
			require.Contains(t, err.Error(), tc.wants)
		})
	}

	t.Run("the length limit is exactly at the boundary", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, layout.ValidateDirName(strings.Repeat("a", layout.MaxDirNameBytes)))
	})
}

// R2's third finding as a regression test. The marker must not sit in a
// directory that changes the entry's kind on disk.
func TestClaudeCodePluginAdoptingSubdirsAreRefusedAndTheMarkerIsNotOne(t *testing.T) {
	t.Parallel()

	for _, name := range []string{".claude-plugin", "agents", "output-styles", "themes", "hooks", "monitors", "workflows"} {
		require.True(t, layout.IsClaudeCodePluginAdoptingSubdir(name), name)
		require.True(t, layout.IsClaudeCodePluginAdoptingSubdir(strings.ToUpper(name)), "case-insensitive: "+name)
	}
	for _, name := range []string{"scripts", "references", "assets", ".agent-manager"} {
		require.False(t, layout.IsClaudeCodePluginAdoptingSubdir(name), name)
	}
	require.False(t, layout.IsClaudeCodePluginAdoptingSubdir(layout.MarkerFileName),
		"the FR-022 marker must never be a name that turns the skill into a plugin")
	require.True(t, strings.HasPrefix(layout.MarkerFileName, "."),
		"a non-dot marker shares the namespace of the skill's own referenced files")
}

// R2's first finding as a regression test: a skill at .claude/skills/synced/ did
// not load, and it was the one probe of four that failed silently.
func TestClaudeCodeRefusesTheReservedSyncDirectory(t *testing.T) {
	t.Parallel()

	err := layout.ValidateClaudeCodeSkillDirName("synced")
	require.Error(t, err)
	require.Contains(t, err.Error(), "would never load")

	require.NoError(t, layout.ValidateClaudeCodeSkillDirName("acme--synced"),
		"the reserved directory is `synced` itself; a namespaced sibling is a different directory")
}

// R2: plugins are out of scope for every target and structurally so. There is
// no plugin destination to derive, so this is a refusal rather than a path.
func TestPlacingAPluginIsRefusedForEveryTarget(t *testing.T) {
	t.Parallel()

	_, err := claudeCode(t, "").Place(layout.Request{
		ID: "acme/toolkit", Version: "2.0.0", Kind: record.KindPlugin,
	})
	require.ErrorIs(t, err, layout.ErrKindUnsupported)
	require.Contains(t, err.Error(), "acme/toolkit")
	require.Contains(t, err.Error(), "plugin")

	t.Run("an entry with no kind is refused rather than assumed to be a skill", func(t *testing.T) {
		t.Parallel()
		_, err := claudeCode(t, "").Place(layout.Request{ID: "acme/toolkit", Version: "2.0.0"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no kind")
	})

	t.Run("no version is needed to route an entry, and one is required to mark it", func(t *testing.T) {
		t.Parallel()
		got, err := claudeCode(t, "").Place(layout.Request{ID: "acme/toolkit", Kind: record.KindSkill})
		require.NoError(t, err, "the destination is a function of id and kind alone")
		require.Error(t, got.Marker(testDigest(t)).Validate(), "the marker is where a version is required")
	})
}

func TestRegistryResolve(t *testing.T) {
	t.Parallel()

	t.Run("claude-code constructs", func(t *testing.T) {
		t.Parallel()
		target, err := registry(t, "").Resolve(record.TargetClaudeCode)
		require.NoError(t, err)
		require.NotNil(t, target)
		require.Equal(t, record.TargetClaudeCode, target.Name())
		require.Equal(t, filepath.FromSlash("/home/tester/.claude/skills"), target.Root())
	})

	t.Run("codex refuses with the R2 class, naming the target", func(t *testing.T) {
		t.Parallel()
		target, err := registry(t, "").Resolve(record.TargetCodex)
		require.Nil(t, target)
		require.ErrorIs(t, err, layout.ErrR2Unresolved)
		require.Contains(t, err.Error(), "codex")
		require.NotErrorIs(t, err, layout.ErrUnknownTarget, "an unresolved target is not an absent one")
		require.NotErrorIs(t, err, layout.ErrWithdrawnTarget)
	})

	t.Run("a withdrawn target is refused by its own class", func(t *testing.T) {
		t.Parallel()
		_, err := registry(t, "").Resolve(record.Target("agents-md"))
		require.ErrorIs(t, err, layout.ErrWithdrawnTarget)
		require.NotErrorIs(t, err, layout.ErrR2Unresolved, "agents-md awaits a design, not a measurement")
		require.Contains(t, err.Error(), "agents-md")
	})

	t.Run("an unrecognised target names what this build writes", func(t *testing.T) {
		t.Parallel()
		_, err := registry(t, "").Resolve(record.Target("future-agent"))
		require.ErrorIs(t, err, layout.ErrUnknownTarget)
		require.Contains(t, err.Error(), "future-agent")
		require.Contains(t, err.Error(), "claude-code")
	})

	t.Run("every refusal returns a nil target, so no caller can install under one", func(t *testing.T) {
		t.Parallel()
		for _, name := range []record.Target{record.TargetCodex, "agents-md", "future-agent", ""} {
			target, err := registry(t, "").Resolve(name)
			require.Error(t, err, name)
			require.Nil(t, target, name)
		}
	})
}

func TestRegistrySelect(t *testing.T) {
	t.Parallel()

	t.Run("claude-code alone is writable", func(t *testing.T) {
		t.Parallel()
		sel, err := registry(t, "").Select([]string{"claude-code"})
		require.NoError(t, err)
		require.Len(t, sel.Writable, 1)
		require.Equal(t, record.TargetClaudeCode, sel.Writable[0].Name())
		require.Empty(t, sel.Withdrawn)
		require.Empty(t, sel.Unknown)
	})

	t.Run("a profile naming codex is refused, never partially synced", func(t *testing.T) {
		t.Parallel()
		sel, err := registry(t, "").Select([]string{"claude-code", "codex"})
		require.ErrorIs(t, err, layout.ErrR2Unresolved)
		require.Contains(t, err.Error(), "codex")
		require.Empty(t, sel.Writable, "a refused selection must not hand back a partial writable set")
	})

	t.Run("a withdrawn target is reported and does not fail the sync", func(t *testing.T) {
		t.Parallel()
		// The lockfile schema's own example targets list.
		sel, err := registry(t, "").Select([]string{"claude-code", "agents-md"})
		require.NoError(t, err)
		require.Len(t, sel.Writable, 1)
		require.Equal(t, []record.Target{"agents-md"}, sel.Withdrawn)
		require.Contains(t, sel.Reasons[record.Target("agents-md")], "withdrawn")
	})

	t.Run("a target added after this build shipped is reported, not dropped", func(t *testing.T) {
		t.Parallel()
		sel, err := registry(t, "").Select([]string{"claude-code", "future-agent"})
		require.NoError(t, err)
		require.Len(t, sel.Writable, 1)
		require.Equal(t, []record.Target{"future-agent"}, sel.Unknown)
		require.NotEmpty(t, sel.Reasons[record.Target("future-agent")])
	})

	t.Run("nothing writable is a failure, not a sync of zero packages", func(t *testing.T) {
		t.Parallel()
		for _, names := range [][]string{
			{"agents-md"},
			{"future-agent"},
			{"agents-md", "future-agent"},
			{},
		} {
			sel, err := registry(t, "").Select(names)
			require.ErrorIs(t, err, layout.ErrNoWritableTarget, names)
			require.Empty(t, sel.Writable, names)
		}
	})

	t.Run("a repeated target is written once", func(t *testing.T) {
		t.Parallel()
		sel, err := registry(t, "").Select([]string{"claude-code", "claude-code"})
		require.NoError(t, err)
		require.Len(t, sel.Writable, 1)
	})
}

func TestRegistryConfigRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cfg   layout.Config
		wants string
	}{
		{"empty home", layout.Config{}, "home directory is empty"},
		{"relative home", layout.Config{HomeDir: "tester"}, "is not absolute"},
		{"relative CLAUDE_CONFIG_DIR", layout.Config{HomeDir: home, ClaudeConfigDir: "claude"}, "CLAUDE_CONFIG_DIR"},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			t.Parallel()
			reg, err := layout.NewRegistry(tc.cfg)
			require.ErrorIs(t, err, layout.ErrConfig)
			require.Contains(t, err.Error(), tc.wants)
			require.Nil(t, reg)
		})
	}
}

// FR-020 is internal/apply's to enforce on the resolved path, but a destination
// that is not absolute and clean cannot even be checked, and record.Entry
// refuses it.
func TestEveryDestinationIsAbsoluteCleanAndUnderTheRoot(t *testing.T) {
	t.Parallel()

	target := claudeCode(t, "")
	for _, id := range []string{"acme/code-review", "globex/code-review", "com.anthropic.claude-code/pdf-tools"} {
		got, err := target.Place(skill(id, "1.0.0"))
		require.NoError(t, err)
		require.True(t, filepath.IsAbs(got.Dest), got.Dest)
		require.Equal(t, filepath.Clean(got.Dest), got.Dest)
		require.Equal(t, got.Root, filepath.Dir(got.Dest), "one level deep: R2 observed loading at one level only")

		entry := record.Entry{
			ID: id, Version: "1.0.0", Kind: record.KindSkill,
			Target: got.Target, Dest: got.Dest,
			Digest: testDigest(t),
		}
		rec := record.New("https://hub.example.com")
		rec.SetProfile(record.Profile{Slug: "p", Revision: 1, Targets: []record.Target{got.Target}, Entries: []record.Entry{entry}})
		require.NoError(t, rec.Validate(), "a destination this package derives must be recordable")
	}
}

// FR-022: the marker answers "which package and version is this" with no hub.
func TestMarkerIdentifiesThePackageWithoutTheHub(t *testing.T) {
	t.Parallel()

	got, err := claudeCode(t, "").Place(skill("acme/code-review", "1.2.3"))
	require.NoError(t, err)

	marker := got.Marker(testDigest(t))
	bytes, err := marker.Bytes()
	require.NoError(t, err)

	parsed, err := layout.ParseMarker(bytes)
	require.NoError(t, err)
	require.Equal(t, "acme/code-review", parsed.ID)
	require.Equal(t, "1.2.3", parsed.Version)
	require.Equal(t, record.KindSkill, parsed.Kind)
	require.Equal(t, record.TargetClaudeCode, parsed.Target)
	require.Equal(t, digestHex, parsed.Digest.Lockfile())
	require.Equal(t, marker, parsed)

	t.Run("the bytes are deterministic, so a reinstall of one version is byte-identical", func(t *testing.T) {
		again, err := got.Marker(testDigest(t)).Bytes()
		require.NoError(t, err)
		require.Equal(t, bytes, again)
	})

	t.Run("the marker names no profile and no timestamp", func(t *testing.T) {
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(bytes, &fields))
		require.ElementsMatch(t,
			[]string{"schemaVersion", "id", "version", "kind", "target", "digest"},
			keys(fields),
			"a profile would be wrong as soon as a second profile claimed the same destination, and a timestamp "+
				"would make two installs of one version differ")
	})

	t.Run("the marker sits beside SKILL.md and is never inside it", func(t *testing.T) {
		require.Equal(t, filepath.Dir(got.EntryFilePath), filepath.Dir(got.MarkerPath))
		require.NotEqual(t, got.EntryFilePath, got.MarkerPath)
	})
}

func TestMarkerRefusals(t *testing.T) {
	t.Parallel()

	valid := layout.Marker{
		SchemaVersion: layout.MarkerSchemaVersion,
		ID:            "acme/code-review",
		Version:       "1.0.0",
		Kind:          record.KindSkill,
		Target:        record.TargetClaudeCode,
		Digest:        testDigest(t),
	}
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(m *layout.Marker)
		wants  string
	}{
		{"a future schema version", func(m *layout.Marker) { m.SchemaVersion = 2 }, "schema version 2"},
		{"a one-segment id", func(m *layout.Marker) { m.ID = "code-review" }, "one segment"},
		{"no version", func(m *layout.Marker) { m.Version = "" }, "no version"},
		{"a kind outside the contract", func(m *layout.Marker) { m.Kind = "bundle" }, "not a contract kind"},
		{"a target outside the contract", func(m *layout.Marker) { m.Target = "agents-md" }, "not a contract target"},
		{"no digest", func(m *layout.Marker) { m.Digest = record.Digest{} }, "no digest"},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			t.Parallel()
			m := valid
			tc.mutate(&m)
			err := m.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wants)

			_, err = m.Bytes()
			require.Error(t, err, "an invalid marker must not be encodable")
		})
	}

	t.Run("an unknown field is refused rather than ignored", func(t *testing.T) {
		t.Parallel()
		_, err := layout.ParseMarker([]byte(`{"schemaVersion":1,"id":"acme/x","version":"1.0.0","kind":"skill",` +
			`"target":"claude-code","digest":"` + digestHex + `","installedBy":"someone else"}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "installedBy")
	})

	t.Run("a base64 digest spelling is refused, not folded", func(t *testing.T) {
		t.Parallel()
		_, err := layout.ParseMarker([]byte(`{"schemaVersion":1,"id":"acme/x","version":"1.0.0","kind":"skill",` +
			`"target":"claude-code","digest":"sha-256=ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8="}`))
		require.Error(t, err)
	})
}

// The one FR-023 hazard a per-entry function cannot close: APFS folds
// case, so two ids differing only in case share one directory. Recorded here so
// internal/plan has a named thing to compare and the limitation is not
// rediscovered as a bug.
func TestDestCollisionKeyExposesTheCaseFoldingHazard(t *testing.T) {
	t.Parallel()

	target := claudeCode(t, "")
	lower, err := target.Place(skill("acme/tool", "1.0.0"))
	require.NoError(t, err)
	upper, err := target.Place(skill("Acme/tool", "2.0.0"))
	require.NoError(t, err)

	require.NotEqual(t, lower.Dest, upper.Dest, "the names are kept verbatim, never lowercased")
	require.Equal(t, layout.DestCollisionKey(lower.Dest), layout.DestCollisionKey(upper.Dest),
		"on APFS these are one directory; internal/plan must refuse the pair")
}

func TestKnownTargetNamesIsTheVocabularyAndNotTheWritableSet(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"claude-code", "codex"}, layout.KnownTargetNames(),
		"codex is known to this build and is not writable by it; the two sets are different")

	_, err := registry(t, "").Select([]string{"agents-md"})
	require.ErrorIs(t, err, layout.ErrNoWritableTarget)
	require.Contains(t, err.Error(), "can write claude-code")
	require.NotContains(t, err.Error(), "can write claude-code, codex",
		"telling a user this build writes codex when its constructor refuses sends them to fix the wrong thing")
}

func TestPackageIDErrorsAreASingleClass(t *testing.T) {
	t.Parallel()
	_, err := layout.ParsePackageID("nope")
	require.True(t, errors.Is(err, layout.ErrPackageID))
	require.False(t, errors.Is(err, layout.ErrDirName))
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
