package record_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

const (
	hubA = "https://hub.example.com"
	hubB = "https://other.example.com:8443"

	// Hand-written digests, so the expected bytes can be checked by eye.
	digestHex = "abababababababababababababababababababababababababababababababab"
	fileHex   = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

func mustDigest(t *testing.T, hex string) record.Digest {
	t.Helper()
	d, err := record.ParseDigest("sha256:" + hex)
	require.NoError(t, err)
	return d
}

func installedAt() time.Time { return time.Date(2026, 8, 27, 10, 11, 12, 0, time.UTC) }

// Dests must be absolute on this machine. The JSON form is hand-written, not
// json.Marshal'd, so the encoding assertion isn't delegated to the code under test.
const (
	destRoot     = "/home/u"
	destJSONRoot = "/home/u"
	sep          = "/"
)

func skillDest(name string) string {
	return filepath.Join(destRoot, ".claude", "skills", name)
}

func skillDestJSON(name string) string {
	return destJSONRoot + sep + ".claude" + sep + "skills" + sep + name
}

// uncleanDest is built without filepath.Join, which would clean it.
func uncleanDest() string {
	return destRoot + sep + ".." + sep + filepath.Base(destRoot) +
		sep + ".claude" + sep + "skills" + sep + "x"
}

func smallRecord(t *testing.T) *record.Record {
	t.Helper()
	r := record.New(hubA)
	r.SetProfile(record.Profile{
		Slug:        "team-a",
		Revision:    7,
		InstalledAt: installedAt(),
		Targets:     []record.Target{record.TargetClaudeCode},
		Entries: []record.Entry{{
			ID:      "acme/code-review",
			Version: "1.2.0",
			Digest:  mustDigest(t, digestHex),
			Kind:    record.KindSkill,
			Target:  record.TargetClaudeCode,
			Dest:    skillDest("code-review"),
			Fingerprint: record.Fingerprint{
				Algo: record.FingerprintAlgo,
				Files: map[string]record.FileMark{
					"SKILL.md": {SHA256: fileHex, Size: 12, Mode: 0o644, Kind: record.FileKindRegular},
				},
				Dirs: map[string]uint32{"scripts": 0o755},
			},
		}},
	})
	return r
}

// golden is hand-written from the struct tags and encoder rules, never copied
// from output, with only the platform's destination substituted in.
func golden() string {
	return strings.ReplaceAll(goldenSmall, "@DEST@", skillDestJSON("code-review"))
}

const goldenSmall = `{
  "schemaVersion": 1,
  "hub": "https://hub.example.com",
  "profiles": [
    {
      "slug": "team-a",
      "revision": 7,
      "installedAt": "2026-08-27T10:11:12Z",
      "targets": [
        "claude-code"
      ],
      "entries": [
        {
          "id": "acme/code-review",
          "version": "1.2.0",
          "digest": "sha256:abababababababababababababababababababababababababababababababab",
          "kind": "skill",
          "target": "claude-code",
          "dest": "@DEST@",
          "fingerprint": {
            "algo": "sha256-tree-v1",
            "files": {
              "SKILL.md": {
                "h": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "s": 12,
                "m": 420,
                "k": "f"
              }
            },
            "dirs": {
              "scripts": 493
            }
          }
        }
      ]
    }
  ]
}
`

func recordPath(t *testing.T) string {
	t.Helper()
	return record.Path(filepath.Join(t.TempDir(), "hub.example.com-1a2b3c"))
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("a saved record reads back identically", func(t *testing.T) {
		t.Parallel()
		p := recordPath(t)
		want := smallRecord(t)

		wrote, err := record.Save(p, want)
		require.NoError(t, err)
		require.True(t, wrote)

		got, err := record.Load(p, hubA)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("the bytes on disk are the documented shape", func(t *testing.T) {
		t.Parallel()
		p := recordPath(t)
		_, err := record.Save(p, smallRecord(t))
		require.NoError(t, err)

		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.Equal(t, golden(), string(b))
	})

	t.Run("the record file is owner-only", func(t *testing.T) {
		t.Parallel()
		p := recordPath(t)
		_, err := record.Save(p, smallRecord(t))
		require.NoError(t, err)
		st, err := os.Stat(p)
		require.NoError(t, err)

		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	})

	t.Run("an entry with no fingerprint round trips and omits the field", func(t *testing.T) {
		t.Parallel()
		p := recordPath(t)
		r := record.New(hubA)
		r.SetProfile(record.Profile{
			Slug: "team-a", Revision: 1, InstalledAt: installedAt(),
			Targets: []record.Target{record.TargetClaudeCode},
			Entries: []record.Entry{{
				ID: "acme/skill", Version: "1.0.0", Digest: mustDigest(t, digestHex),
				Kind: record.KindSkill, Target: record.TargetClaudeCode, Dest: skillDest("skill"),
			}},
		})
		_, err := record.Save(p, r)
		require.NoError(t, err)

		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.NotContains(t, string(b), "fingerprint")

		got, err := record.Load(p, hubA)
		require.NoError(t, err)
		require.Equal(t, r, got)
	})

	t.Run("profiles entries and targets are written in canonical order", func(t *testing.T) {
		t.Parallel()
		p := recordPath(t)
		r := record.New(hubA)
		r.SetProfile(record.Profile{
			Slug: "zeta", Revision: 1, InstalledAt: installedAt(),
			Targets: []record.Target{record.TargetCodex, record.TargetClaudeCode},
			Entries: []record.Entry{
				{ID: "z/b", Version: "1", Digest: mustDigest(t, digestHex), Kind: record.KindSkill,
					Target: record.TargetClaudeCode, Dest: skillDest("b")},
				{ID: "a/a", Version: "1", Digest: mustDigest(t, digestHex), Kind: record.KindSkill,
					Target: record.TargetClaudeCode, Dest: skillDest("a")},
			},
		})
		r.SetProfile(record.Profile{
			Slug: "alpha", Revision: 1, InstalledAt: installedAt(),
			Targets: []record.Target{record.TargetClaudeCode},
		})
		_, err := record.Save(p, r)
		require.NoError(t, err)

		got, err := record.Load(p, hubA)
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "zeta"}, []string{got.Profiles[0].Slug, got.Profiles[1].Slug})
		require.Equal(t, []string{"a/a", "z/b"},
			[]string{got.Profiles[1].Entries[0].ID, got.Profiles[1].Entries[1].ID})
		require.Equal(t,
			[]record.Target{record.TargetClaudeCode, record.TargetCodex},
			got.Profiles[1].Targets)
	})
}

func TestAbsentFileIsAnEmptyRecordAndNotAnError(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	got, err := record.Load(p, hubA)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.IsEmpty())
	require.Equal(t, hubA, got.Hub, "an empty record must already know its hub, or the first Save writes the wrong one")
	require.Equal(t, record.SchemaVersion, got.SchemaVersion)
	require.Empty(t, got.Refs())

	// `status --offline` on a never-synced machine must not create a hub directory.
	_, statErr := os.Stat(filepath.Dir(p))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestUnknownSchemaVersionIsRefusedWithAMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
	}{
		{"a newer version", `{"schemaVersion": 7, "hub": "https://hub.example.com", "profiles": []}`},
		{"a zero version", `{"schemaVersion": 0, "hub": "https://hub.example.com", "profiles": []}`},
		{"a negative version", `{"schemaVersion": -1, "hub": "https://hub.example.com"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := write(t, tc.body)

			got, err := record.Load(p, hubA)
			require.ErrorIs(t, err, record.ErrSchemaVersion)
			require.Nil(t, got, "a refused record must not also be reported as empty")
			require.Contains(t, err.Error(), p, "the refusal must name the file the user has to fix")
			require.Contains(t, err.Error(), "version 1", "the refusal must say what this build does read")
		})
	}

	t.Run("a missing schemaVersion is corruption, not version zero", func(t *testing.T) {
		t.Parallel()
		p := write(t, `{"hub": "https://hub.example.com", "profiles": []}`)
		got, err := record.Load(p, hubA)
		require.ErrorIs(t, err, record.ErrCorrupt)
		require.Nil(t, got)
		require.Contains(t, err.Error(), p)
	})
}

func TestARecordForOneHubIsRefusedAgainstAnother(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	_, err := record.Save(p, smallRecord(t))
	require.NoError(t, err)

	got, err := record.Load(p, hubB)
	require.ErrorIs(t, err, record.ErrHubMismatch)
	require.Nil(t, got, "the record is the authority for removal; the wrong hub's must not be usable")
	require.Contains(t, err.Error(), hubA, "the refusal must name the hub the record belongs to")
	require.Contains(t, err.Error(), hubB, "and the hub this run is against")

	// Exact equality on purpose: internal/cmd owns hub canonicalisation.
	_, err = record.Load(p, hubA+"/")
	require.ErrorIs(t, err, record.ErrHubMismatch)
}

// An empty record means "prune nothing", which would leave a corrupt record's
// tree permanently unremovable.
func TestACorruptRecordIsRefusedAndNeverTreatedAsEmpty(t *testing.T) {
	t.Parallel()

	valid := `{"schemaVersion":1,"hub":"https://hub.example.com","profiles":[]}`

	for _, tc := range []struct {
		name string
		body string
	}{
		{"truncated mid-document", valid[:len(valid)/2]},
		{"truncated mid-string", `{"schemaVersion":1,"hub":"https://hub.exa`},
		{"an empty file", ""},
		{"whitespace only", "   \n"},
		{"not json at all", "\x00\x01\x02binary garbage"},
		{"a json array", `[{"schemaVersion":1}]`},
		{"a field this build does not know", valid[:len(valid)-1] + `,"surprise":true}`},
		{"trailing content after the record", valid + valid},
		{"a wrongly typed field", `{"schemaVersion":1,"hub":"https://hub.example.com","profiles":"none"}`},
		{"a digest in the wrong encoding", `{"schemaVersion":1,"hub":"https://hub.example.com","profiles":[` +
			`{"slug":"a","revision":1,"installedAt":"2026-08-27T10:11:12Z","targets":["claude-code"],"entries":[` +
			`{"id":"acme/x","version":"1","digest":"sha-256=q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",` +
			`"kind":"skill","target":"claude-code","dest":"/h/x"}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := write(t, tc.body)

			got, err := record.Load(p, hubA)
			require.Error(t, err)
			require.Nil(t, got)
			require.ErrorIs(t, err, record.ErrCorrupt)
			require.Contains(t, err.Error(), p, "the refusal must name the path so the user can delete it")
			require.NotEmpty(t, strings.TrimSpace(err.Error()))
		})
	}
}

func TestAKilledWriteLeavesThePreviousRecordIntact(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	first := smallRecord(t)
	_, err := record.Save(p, first)
	require.NoError(t, err)

	// A partial temp file, as a process killed before the rename leaves; found
	// by name shape so a renamed temp prefix can't make this vacuous.
	dir := filepath.Dir(p)
	partial := filepath.Join(dir, ".state.json.amctl-tmp-3141592")
	require.NoError(t, os.WriteFile(partial, []byte(`{"schemaVersion":1,"hub":"https://hub.exa`), 0o600))

	got, err := record.Load(p, hubA)
	require.NoError(t, err, "a leftover partial write must not affect reading the record")
	require.Equal(t, first, got, "the previous record must be intact, byte for byte")

	// The next successful save collects the leftover.
	second := smallRecord(t)
	second.Profiles[0].Revision = 8
	wrote, err := record.Save(p, second)
	require.NoError(t, err)
	require.True(t, wrote)
	_, statErr := os.Stat(partial)
	require.ErrorIs(t, statErr, os.ErrNotExist, "a dead partial write must be collected")

	got, err = record.Load(p, hubA)
	require.NoError(t, err)
	require.Equal(t, 8, got.Profiles[0].Revision)
	require.Equal(t, []string{p}, names(t, dir), "nothing but the record may be left behind")
}

// A direct write to the final name passes every other test and fails this one.
func TestNoReaderEverObservesATornRecord(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	_, err := record.Save(p, big(t, 1))
	require.NoError(t, err)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for rev := 2; rev < 40; rev++ {
			if _, saveErr := record.Save(p, big(t, rev)); saveErr != nil {
				t.Error(saveErr)
				break
			}
		}
		close(stop)
	}()

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r, loadErr := record.Load(p, hubA)
				if loadErr != nil {
					t.Errorf("a concurrent read saw a partial record: %v", loadErr)
					return
				}
				if len(r.Profiles) != 1 || len(r.Profiles[0].Entries) != 200 {
					t.Errorf("a concurrent read saw an incomplete record: %d profiles", len(r.Profiles))
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSavingAnUnchangedRecordWritesNothing(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	wrote, err := record.Save(p, smallRecord(t))
	require.NoError(t, err)
	require.True(t, wrote)
	before, err := os.Stat(p)
	require.NoError(t, err)

	wrote, err = record.Save(p, smallRecord(t))
	require.NoError(t, err)
	require.False(t, wrote, "an unchanged record must not be rewritten")
	after, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, before.ModTime(), after.ModTime(), "an unchanged record must not be touched")

	changed := smallRecord(t)
	changed.Profiles[0].Revision = 8
	wrote, err = record.Save(p, changed)
	require.NoError(t, err)
	require.True(t, wrote, "a changed record must be written")
}

func TestRemovablePathsIsTheDestinationAndItsDeterministicAside(t *testing.T) {
	t.Parallel()

	require.Equal(t, ".amctl-old", record.AsideSuffix,
		"gate R3 fixed this name; internal/apply's swap and this set must agree on it")

	e := record.Entry{Dest: skillDest("code-review")}
	require.Equal(t, []string{
		skillDest("code-review"),
		skillDest("code-review") + record.AsideSuffix,
	}, e.RemovablePaths())

	// Siblings, so the swap's rollback never hits EXDEV.
	parent := filepath.Dir(e.Dest)
	for _, p := range e.RemovablePaths() {
		require.Equal(t, parent, filepath.Dir(p))
	}
}

func TestTwoProfilesMayClaimOneDestination(t *testing.T) {
	t.Parallel()

	dest := skillDest("code-review")
	entry := record.Entry{
		ID: "acme/code-review", Version: "1.2.0", Digest: mustDigest(t, digestHex),
		Kind: record.KindSkill, Target: record.TargetClaudeCode, Dest: dest,
	}
	r := record.New(hubA)
	for _, slug := range []string{"team-a", "team-b"} {
		r.SetProfile(record.Profile{
			Slug: slug, Revision: 3, InstalledAt: installedAt(),
			Targets: []record.Target{record.TargetClaudeCode},
			Entries: []record.Entry{entry},
		})
	}

	p := recordPath(t)
	_, err := record.Save(p, r)
	require.NoError(t, err, "a destination shared across profiles is valid, not a conflict")

	got, err := record.Load(p, hubA)
	require.NoError(t, err)
	claims := got.ClaimantsOf(dest)
	require.Len(t, claims, 2)
	require.Equal(t, []string{"team-a", "team-b"}, []string{claims[0].Profile, claims[1].Profile})
	require.Empty(t, got.ClaimantsOf(skillDest("something-else")))

	byID := got.ByID("acme/code-review")
	require.Len(t, byID, 2)
	require.Equal(t, "1.2.0", byID[0].Entry.Version)
	require.Empty(t, got.ByID("acme/nothing"))
}

func TestProfileHelpers(t *testing.T) {
	t.Parallel()

	r := smallRecord(t)
	p, ok := r.ProfileBySlug("team-a")
	require.True(t, ok)
	require.Equal(t, 7, p.Revision)

	_, ok = r.ProfileBySlug("absent")
	require.False(t, ok)

	p.Revision = 9
	r.SetProfile(p)
	again, ok := r.ProfileBySlug("team-a")
	require.True(t, ok)
	require.Equal(t, 9, again.Revision)

	require.True(t, r.RemoveProfile("team-a"))
	require.False(t, r.RemoveProfile("team-a"))
	require.True(t, r.IsEmpty())
}

// Each case is a shape amctl could not have written, and asserts the specific
// refusal.
func TestValidateRefusesRecordsAmctlCouldNotHaveWritten(t *testing.T) {
	t.Parallel()

	base := smallRecord

	for _, tc := range []struct {
		name    string
		mutate  func(*record.Record)
		wantMsg string
	}{
		{"no hub url", func(r *record.Record) { r.Hub = "" }, "no hub URL"},
		{"a profile with no slug", func(r *record.Record) { r.Profiles[0].Slug = "" }, "no slug"},
		{"an unresolved revision", func(r *record.Record) { r.Profiles[0].Revision = 0 }, "not a resolved revision"},
		{"a negative revision", func(r *record.Record) { r.Profiles[0].Revision = -3 }, "not a resolved revision"},
		{"a target outside the contract's enum",
			func(r *record.Record) { r.Profiles[0].Targets = []record.Target{"cursor"} },
			"not one of the contract's targets"},
		{"an entry kind outside the contract's enum",
			func(r *record.Record) { r.Profiles[0].Entries[0].Kind = "bundle" },
			"not one of the contract's kinds"},
		{"an entry target outside the contract's enum",
			func(r *record.Record) { r.Profiles[0].Entries[0].Target = "cursor" },
			"not one of the contract's targets"},
		{"a one-segment package id",
			func(r *record.Record) { r.Profiles[0].Entries[0].ID = "code-review" },
			"not exactly two non-empty segments"},
		{"a three-segment package id",
			func(r *record.Record) { r.Profiles[0].Entries[0].ID = "example/platform/code-review" },
			"not exactly two non-empty segments"},
		{"an empty namespace",
			func(r *record.Record) { r.Profiles[0].Entries[0].ID = "/code-review" },
			"not exactly two non-empty segments"},
		{"a dot-dot namespace",
			func(r *record.Record) { r.Profiles[0].Entries[0].ID = "../code-review" },
			"unusable segment"},
		{"no version", func(r *record.Record) { r.Profiles[0].Entries[0].Version = "" }, "no version"},
		{"a version with a path separator",
			func(r *record.Record) { r.Profiles[0].Entries[0].Version = "1.0/../2.0" },
			"not usable as a path segment"},
		{"the zero digest",
			func(r *record.Record) { r.Profiles[0].Entries[0].Digest = record.Digest{} },
			"no digest"},
		{"a relative destination",
			func(r *record.Record) { r.Profiles[0].Entries[0].Dest = filepath.Join(".claude", "skills", "x") },
			"is not absolute"},
		{"an unclean destination",
			func(r *record.Record) { r.Profiles[0].Entries[0].Dest = uncleanDest() },
			"is not a clean path"},
		{"no destination",
			func(r *record.Record) { r.Profiles[0].Entries[0].Dest = "" },
			"no destination"},
		{"a destination ending in the swap's aside name",
			func(r *record.Record) { r.Profiles[0].Entries[0].Dest = skillDest("x") + record.AsideSuffix },
			"which is the swap's aside name"},
		{"the same package twice for one target", func(r *record.Record) {
			e := r.Profiles[0].Entries[0]
			e.Dest += "-2"
			r.Profiles[0].Entries = append(r.Profiles[0].Entries, e)
		}, "appears twice for target"},
		{"two entries in one profile claiming one destination", func(r *record.Record) {
			e := r.Profiles[0].Entries[0]
			e.ID = "acme/other"
			r.Profiles[0].Entries = append(r.Profiles[0].Entries, e)
		}, "claim the same destination"},
		{"a fingerprint with no algorithm",
			func(r *record.Record) { r.Profiles[0].Entries[0].Fingerprint.Algo = "" },
			"fingerprint with no algorithm"},
		{"a fingerprint key that escapes the entry root", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"../../.ssh/authorized_keys": {SHA256: fileHex, Size: 1, Mode: 0o600, Kind: record.FileKindRegular},
			}
		}, "not a clean relative path"},
		{"an absolute fingerprint key", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"/etc/passwd": {SHA256: fileHex, Size: 1, Mode: 0o600, Kind: record.FileKindRegular},
			}
		}, "is absolute"},
		{"a backslash-separated fingerprint key", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				`scripts\helper.sh`: {SHA256: fileHex, Size: 1, Mode: 0o755, Kind: record.FileKindRegular},
			}
		}, "must be slash-separated"},
		{"an unclean fingerprint key", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"scripts/./helper.sh": {SHA256: fileHex, Size: 1, Mode: 0o755, Kind: record.FileKindRegular},
			}
		}, "not a clean relative path"},
		{"an empty fingerprint key", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"": {SHA256: fileHex, Size: 1, Mode: 0o644, Kind: record.FileKindRegular},
			}
		}, "empty fingerprint key"},
		{"a fingerprint directory key that escapes the entry root", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Dirs = map[string]uint32{"..": 0o755}
		}, "not a clean relative path"},
		{"an uppercase fingerprint hash", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"SKILL.md": {SHA256: strings.ToUpper(fileHex), Size: 1, Mode: 0o644, Kind: record.FileKindRegular},
			}
		}, "want 64 lowercase hex characters"},
		{"a short fingerprint hash", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"SKILL.md": {SHA256: "abc", Size: 1, Mode: 0o644, Kind: record.FileKindRegular},
			}
		}, "want 64 lowercase hex characters"},
		{"a mode outside the permission bits", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"SKILL.md": {SHA256: fileHex, Size: 1, Mode: 0o4755, Kind: record.FileKindRegular},
			}
		}, "outside the permission bits"},
		{"a directory mode outside the permission bits", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Dirs = map[string]uint32{"scripts": 0o2755}
		}, "outside the permission bits"},
		{"a negative file size", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"SKILL.md": {SHA256: fileHex, Size: -1, Mode: 0o644, Kind: record.FileKindRegular},
			}
		}, "has size -1"},
		{"an unknown lstat kind", func(r *record.Record) {
			r.Profiles[0].Entries[0].Fingerprint.Files = map[string]record.FileMark{
				"SKILL.md": {SHA256: fileHex, Size: 1, Mode: 0o644, Kind: "regular"},
			}
		}, `has kind "regular"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := base(t)
			tc.mutate(r)

			err := r.Validate()
			require.ErrorIs(t, err, record.ErrInvalid)
			require.Contains(t, err.Error(), tc.wantMsg)

			// Save must refuse it too, leaving no file or temp behind.
			p := recordPath(t)
			wrote, saveErr := record.Save(p, r)
			require.ErrorIs(t, saveErr, record.ErrInvalid)
			require.False(t, wrote)
			_, statErr := os.Stat(p)
			require.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}

	t.Run("a duplicate profile slug is refused", func(t *testing.T) {
		t.Parallel()
		// SetProfile cannot produce this; a hand-edited file can.
		r := smallRecord(t)
		r.Profiles = append(r.Profiles, r.Profiles[0])
		err := r.Validate()
		require.ErrorIs(t, err, record.ErrInvalid)
		require.Contains(t, err.Error(), "appears twice")
	})

	t.Run("the valid record this table mutates really is valid", func(t *testing.T) {
		t.Parallel()
		// Negative control: a valid record passes.
		require.NoError(t, base(t).Validate())
	})
}

func TestSaveRefusesToClobberAValidRecordWithAnInvalidOne(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	_, err := record.Save(p, smallRecord(t))
	require.NoError(t, err)

	bad := smallRecord(t)
	bad.Profiles[0].Entries[0].Dest = "relative/path"
	wrote, err := record.Save(p, bad)
	require.ErrorIs(t, err, record.ErrInvalid)
	require.False(t, wrote)

	got, err := record.Load(p, hubA)
	require.NoError(t, err)
	require.Equal(t, smallRecord(t), got)
}

func TestDigestEncoding(t *testing.T) {
	t.Parallel()

	t.Run("the record's encoding is the lockfile's", func(t *testing.T) {
		t.Parallel()
		d := mustDigest(t, digestHex)
		b, err := json.Marshal(d)
		require.NoError(t, err)
		require.JSONEq(t, `"sha256:`+digestHex+`"`, string(b))
	})

	// Each rejected spelling is a real digest encoding used elsewhere; accepting
	// one would give the field two spellings of one value.
	for _, tc := range []struct{ name, body string }{
		{"the response header's base64 encoding", `"sha-256=q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="`},
		{"the cache's filename encoding", `"sha256-` + digestHex + `"`},
		{"bare hex with no scheme", `"` + digestHex + `"`},
		{"uppercase hex", `"sha256:` + strings.ToUpper(digestHex) + `"`},
		{"a truncated digest", `"sha256:abab"`},
		{"a non-string", `12345`},
		{"the empty string", `""`},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			t.Parallel()
			var d record.Digest
			require.Error(t, json.Unmarshal([]byte(tc.body), &d))
			require.True(t, d.IsZero())
		})
	}
}

func TestPathIsTheRecordInsideTheHubDirectory(t *testing.T) {
	t.Parallel()

	// The per-hub directory is given, never derived from a URL.
	hubDir := filepath.Join(string(filepath.Separator)+"h", ".agent-manager", "hub.example.com-1a2b")
	require.Equal(t, filepath.Join(hubDir, "state.json"), record.Path(hubDir))
	require.Equal(t, "state.json", record.FileName)
}

func TestLoadRefusesWithoutAnExpectedHub(t *testing.T) {
	t.Parallel()

	got, err := record.Load(recordPath(t), "")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "expected hub URL")
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := recordPath(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// big is large enough that a non-atomic write would be observed torn.
func big(t *testing.T, revision int) *record.Record {
	t.Helper()
	entries := make([]record.Entry, 0, 200)
	for i := range 200 {
		entries = append(entries, record.Entry{
			ID:      "acme/skill-" + itoa(i),
			Version: "1.0." + itoa(revision),
			Digest:  mustDigest(t, digestHex),
			Kind:    record.KindSkill,
			Target:  record.TargetClaudeCode,
			Dest:    skillDest("skill-" + itoa(i)),
			Fingerprint: record.Fingerprint{
				Algo: record.FingerprintAlgo,
				Files: map[string]record.FileMark{
					"SKILL.md": {SHA256: fileHex, Size: int64(i), Mode: 0o644, Kind: record.FileKindRegular},
				},
			},
		})
	}
	r := record.New(hubA)
	r.SetProfile(record.Profile{
		Slug: "team-a", Revision: revision, InstalledAt: installedAt(),
		Targets: []record.Target{record.TargetClaudeCode}, Entries: entries,
	})
	return r
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestPluginComponentsRoundTripAndAreValidated(t *testing.T) {
	t.Parallel()
	pluginRecord := func(comps ...record.Component) *record.Record {
		r := record.New(hubA)
		r.SetProfile(record.Profile{Slug: "base", Revision: 1, InstalledAt: installedAt(),
			Targets: []record.Target{record.TargetOpenCode},
			Entries: []record.Entry{{
				ID: "acme/kit", Version: "1.0.0", Digest: mustDigest(t, digestHex), Kind: record.KindPlugin,
				Target: record.TargetOpenCode, Dest: filepath.Join(destRoot, ".agent-manager", "plugins", "acme--kit"),
				Components: comps, Partial: true,
			}},
		})
		return r
	}
	mcp := record.Component{Kind: record.ComponentMCPServer, Name: "fs",
		Path: filepath.Join(destRoot, ".config", "opencode", "opencode.json"), Key: "kit-fs", SHA256: fileHex}

	p := recordPath(t)
	want := pluginRecord(mcp)
	_, err := record.Save(p, want)
	require.NoError(t, err)
	got, err := record.Load(p, hubA)
	require.NoError(t, err)
	require.Equal(t, want, got)

	for name, bad := range map[string]record.Component{
		"unknown kind":  {Kind: "theme", Name: "x", Path: mcp.Path, SHA256: fileHex},
		"relative path": {Kind: record.ComponentAgent, Name: "x", Path: "agents/x.md", SHA256: fileHex},
		"short hash":    {Kind: record.ComponentAgent, Name: "x", Path: mcp.Path, SHA256: "abc"},
		"no name":       {Kind: record.ComponentAgent, Path: mcp.Path, SHA256: fileHex},
	} {
		require.ErrorIs(t, pluginRecord(bad).Validate(), record.ErrInvalid, name)
	}
	require.ErrorIs(t, pluginRecord(mcp, mcp).Validate(), record.ErrInvalid, "one component recorded twice")
}
