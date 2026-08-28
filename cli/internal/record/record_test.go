package record_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

	// Hand-written digests rather than hashes of something: the expected
	// on-disk bytes below are derived from the source of truth (the schema and
	// the struct tags) and not from observing a run, so every value in them
	// has to be one a human can check by eye.
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

// A record's dest is a path on THIS machine, and validation requires it to be
// absolute — filepath.IsAbs, which on Windows means a volume is named. So the
// fixtures cannot hardcode a POSIX path: `/home/u/...` is drive-relative on
// Windows, not absolute, and every Save in this file would be refused for a
// reason that has nothing to do with what the test is about. Eight tests failed
// that way on the Windows CI leg.
//
// Both spellings are hand-written, including the JSON escaping. A Windows dest
// contains backslashes and JSON escapes each as `\\`, so pinning the escaped
// form here asserts something the POSIX-only golden could not: that the encoder
// escapes the separator rather than emitting it raw. Deriving destJSON with
// json.Marshal instead would hand that assertion to the code under test.
var (
	destRoot, destJSONRoot = func() (string, string) {
		if runtime.GOOS == "windows" {
			return `C:\home\u`, `C:\\home\\u`
		}
		return "/home/u", "/home/u"
	}()
	sep = string(filepath.Separator)
)

// skillDest is a fixture destination under the platform's absolute root.
func skillDest(name string) string {
	return filepath.Join(destRoot, ".claude", "skills", name)
}

// skillDestJSON is skillDest spelled as JSON encodes it. Assembled from the
// hand-written escaped root rather than from the encoder.
func skillDestJSON(name string) string {
	s := sep
	if runtime.GOOS == "windows" {
		s = `\\`
	}
	return destJSONRoot + s + ".claude" + s + "skills" + s + name
}

// uncleanDest is skillDest("x") with a `..` left in it, built without
// filepath.Join because Join cleans — which is the whole point of the fixture.
func uncleanDest() string {
	return destRoot + sep + ".." + sep + filepath.Base(destRoot) +
		sep + ".claude" + sep + "skills" + sep + "x"
}

// smallRecord is the record the golden bytes below describe.
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

// goldenSmall is hand-written from the struct tags and the JSON encoder's
// documented rules (field order as declared, map keys sorted, two-space
// indent), NOT copied out of a test run. A golden captured from output encodes
// whatever the encoder happened to do, including a bug.
// golden is goldenSmall with the platform's destination substituted in. The
// shape — field order as declared, map keys sorted, two-space indent, the short
// `h`/`s`/`m`/`k` keys, the decimal modes 420 and 493 — is still entirely
// hand-derived; only the one value that cannot be platform-independent moves.
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
					Target: record.TargetClaudeCode, Dest: "/h/b"},
				{ID: "a/a", Version: "1", Digest: mustDigest(t, digestHex), Kind: record.KindSkill,
					Target: record.TargetClaudeCode, Dest: "/h/a"},
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

	// Reading must not create anything: `status --offline` on a machine that
	// has never synced must not fabricate a hub directory.
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

	// The check is exact string equality on purpose: internal/cmd owns hub
	// identity, and a second canonicalisation here would eventually disagree
	// with the directory naming.
	_, err = record.Load(p, hubA+"/")
	require.ErrorIs(t, err, record.ErrHubMismatch)
}

// A corrupt record must NOT be read as empty. "Empty" means "prune nothing,
// reinstall everything", which leaves an installed tree on disk that FR-028
// then makes permanently unremovable — the directory listing that would find
// it again is exactly what FR-028 forbids.
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

// The write is atomic: a record half-written by a killed process leaves the
// previous record intact. Proven by actually leaving a partial file behind.
func TestAKilledWriteLeavesThePreviousRecordIntact(t *testing.T) {
	t.Parallel()

	p := recordPath(t)
	first := smallRecord(t)
	_, err := record.Save(p, first)
	require.NoError(t, err)

	// What a process killed between the create and the rename leaves: a
	// partial file under the temp name, in the same directory, with a
	// half-written document in it. Discovered by name shape, not by asking the
	// package — a temp name only the package knows would make this test
	// vacuous the day the name changes.
	dir := filepath.Dir(p)
	partial := filepath.Join(dir, ".state.json.amctl-tmp-3141592")
	require.NoError(t, os.WriteFile(partial, []byte(`{"schemaVersion":1,"hub":"https://hub.exa`), 0o600))

	got, err := record.Load(p, hubA)
	require.NoError(t, err, "a leftover partial write must not affect reading the record")
	require.Equal(t, first, got, "the previous record must be intact, byte for byte")

	// The next successful save collects the leftover rather than leaving it to
	// accumulate one per crash forever.
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

// A reader must never observe a torn record. A direct write to the final name
// passes every other test in this file and fails this one.
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

// FR-025: a second run against an unchanged hub makes no filesystem
// modification. That has to be true of the record too, not only of the tree.
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

// FR-028 by construction: the complete set of paths amctl may remove for an
// entry is two literal names derived from one recorded destination. No glob
// exists, and none is needed, because gate R3 fixed the interrupted swap's
// leftover as a deterministic sibling.
func TestRemovablePathsIsTheDestinationAndItsDeterministicAside(t *testing.T) {
	t.Parallel()

	require.Equal(t, ".amctl-old", record.AsideSuffix,
		"gate R3 fixed this name; internal/apply's swap and this set must agree on it")

	e := record.Entry{Dest: skillDest("code-review")}
	require.Equal(t, []string{
		skillDest("code-review"),
		skillDest("code-review") + record.AsideSuffix,
	}, e.RemovablePaths())

	// Both members are siblings under the destination's own parent: a central
	// trash directory would make the swap's rollback fail with EXDEV exactly
	// when it is needed.
	parent := filepath.Dir(e.Dest)
	for _, p := range e.RemovablePaths() {
		require.Equal(t, parent, filepath.Dir(p))
	}
}

// One destination claimed by two profiles is legitimate: the same package at
// the same version in two profiles is one directory. Prune must consult this
// before removing anything.
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

	// ByID names both profiles, which is the shape FR-012's report needs even
	// though the decision itself is internal/plan's.
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

// Every one of these is a shape amctl could not have written, so it is either
// corruption or a hand edit. Each asserts the specific refusal, because a
// negative case that fails for the wrong reason has stopped testing anything.
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

			// Save must refuse the same shape, and must not leave the
			// destination file or any temp behind when it does.
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
		// The negative control. Without it, a table whose every row failed for
		// an unrelated reason would look exactly like this one.
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

	// Every rejected spelling below is a real encoding of a real digest
	// somewhere in this system. Accepting any of them here would make the
	// field able to hold two spellings of one value, which is the thing that
	// turns FR-014's comparison into a check that silently never matches.
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

	// The seam with internal/cmd: this package is GIVEN the per-hub directory
	// and never derives it from a URL, so there is no second opinion here on
	// what makes two hub URLs the same hub.
	hubDir := filepath.Join(string(filepath.Separator)+"h", ".agent-manager", "hub.example.com-1a2b")
	require.Equal(t, filepath.Join(hubDir, "state.json"), record.Path(hubDir))
	require.Equal(t, "state.json", record.FileName)
}

func TestLoadRefusesWithoutAnExpectedHub(t *testing.T) {
	t.Parallel()

	// The hub check is the whole point of Load's second argument; a caller
	// that has not resolved a hub yet must not get a record it cannot check.
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

// big is a record large enough that a non-atomic write would be observed torn
// by a concurrent reader rather than landing in one page.
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
