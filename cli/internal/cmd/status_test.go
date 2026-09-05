package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

func statusDepsFor() statusDeps {
	return statusDeps{backends: fileBackendOnly()}
}

// writeEntry writes content at dest/name and returns the record.Fingerprint
// that describes it as actually written — mode read back from disk, never
// assumed, the same rule internal/record's own comment gives for FileMark.
func writeEntry(t *testing.T, dest, name, content string) record.Fingerprint {
	t.Helper()
	require.NoError(t, os.MkdirAll(dest, 0o700))
	path := filepath.Join(dest, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	info, err := os.Lstat(path)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(content))

	return record.Fingerprint{
		Algo: record.FingerprintAlgo,
		Files: map[string]record.FileMark{
			name: {
				SHA256: hex.EncodeToString(sum[:]),
				Size:   info.Size(),
				Mode:   uint32(info.Mode().Perm()),
				Kind:   record.FileKindRegular,
			},
		},
	}
}

func saveTestRecord(t *testing.T, home, hubURL string, profiles ...record.Profile) {
	t.Helper()
	canonical, err := ParseHub(hubURL)
	require.NoError(t, err)

	rec := record.New(canonical.URL)
	for _, p := range profiles {
		rec.SetProfile(p)
	}
	_, err = record.Save(record.Path(filepath.Join(home, DirName, canonical.Dir)), rec)
	require.NoError(t, err)
}

func TestStatusOnAMachineThatNeverSyncedSaysSoAndExitsClean(t *testing.T) {
	home := testHome(t)
	opts, result, _ := testOptions("https://hub.example.com", output.FormatHuman)

	require.NoError(t, runStatus(opts, statusDepsFor()))
	require.Equal(t, CodeNoChanges, ExitCode(opts.Outcome, nil))
	require.Contains(t, result.String(), "nothing has been synced")
	require.Contains(t, result.String(), "not logged in")
	_ = home
}

func TestStatusReportsTheIdentityLoginStored(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	canonical, err := ParseHub(hubURL)
	require.NoError(t, err)

	store := openTestStore(t, home)
	cred := credentials.Issued(canonical.URL, "a-stored-token", 3600, time.Now())
	cred.Identity = "dev-laptop"
	require.NoError(t, store.Save(cred))

	opts, result, _ := testOptions(hubURL, output.FormatHuman)
	require.NoError(t, runStatus(opts, statusDepsFor()))
	require.Contains(t, result.String(), "dev-laptop")
}

func TestStatusReportsACleanProfileWithNoDrift(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	dest := filepath.Join(home, ".claude", "skills", "acme--code-review")
	fp := writeEntry(t, dest, "SKILL.md", "# managed by amctl")

	saveTestRecord(t, home, hubURL, record.Profile{
		Slug:        "base",
		Revision:    3,
		InstalledAt: time.Now(),
		Targets:     []record.Target{record.TargetClaudeCode},
		Entries: []record.Entry{{
			ID: "acme/code-review", Version: "2.4.1",
			Digest:      mustParseDigest(t, 1),
			Kind:        record.KindSkill,
			Target:      record.TargetClaudeCode,
			Dest:        dest,
			Fingerprint: fp,
		}},
	})

	opts, result, _ := testOptions(hubURL, output.FormatJSON)
	require.NoError(t, runStatus(opts, statusDepsFor()))
	require.Equal(t, CodeNoChanges, ExitCode(opts.Outcome, nil))

	var doc struct {
		Result output.StatusResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.True(t, doc.Result.Synced)
	require.Len(t, doc.Result.Profiles, 1)
	require.Equal(t, "base", doc.Result.Profiles[0].Slug)
	require.Equal(t, "3", doc.Result.Profiles[0].Revision)
	require.Equal(t, []string{"claude-code"}, doc.Result.Profiles[0].Targets)
	require.Equal(t, 1, doc.Result.Profiles[0].Entries)
	require.False(t, doc.Result.Profiles[0].HasDrift)
	require.Empty(t, doc.Result.Drift)
}

func TestStatusReportsAMissingEntryAsDrift(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	dest := filepath.Join(home, ".claude", "skills", "acme--code-review")
	// Never written: the record claims it, the disk does not have it.

	saveTestRecord(t, home, hubURL, record.Profile{
		Slug: "base", Revision: 1, InstalledAt: time.Now(),
		Targets: []record.Target{record.TargetClaudeCode},
		Entries: []record.Entry{{
			ID: "acme/code-review", Version: "2.4.1", Digest: mustParseDigest(t, 1),
			Kind: record.KindSkill, Target: record.TargetClaudeCode, Dest: dest,
		}},
	})

	opts, result, _ := testOptions(hubURL, output.FormatHuman)
	err := runStatus(opts, statusDepsFor())
	require.Error(t, err)
	require.True(t, IsRefusal(err), "drift is something the user can act on")
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
	require.Contains(t, result.String(), "missing")
	require.Contains(t, result.String(), dest)
}

func TestStatusReportsAModifiedEntryAsDrift(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	dest := filepath.Join(home, ".claude", "skills", "acme--code-review")
	fp := writeEntry(t, dest, "SKILL.md", "# managed by amctl")

	// Modified after the fingerprint was taken.
	require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("# edited by hand"), 0o644))

	saveTestRecord(t, home, hubURL, record.Profile{
		Slug: "base", Revision: 1, InstalledAt: time.Now(),
		Targets: []record.Target{record.TargetClaudeCode},
		Entries: []record.Entry{{
			ID: "acme/code-review", Version: "2.4.1", Digest: mustParseDigest(t, 1),
			Kind: record.KindSkill, Target: record.TargetClaudeCode, Dest: dest,
			Fingerprint: fp,
		}},
	})

	opts, result, _ := testOptions(hubURL, output.FormatHuman)
	err := runStatus(opts, statusDepsFor())
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	require.Contains(t, result.String(), "modified")
	require.Contains(t, result.String(), "SKILL.md")
}

func TestStatusReportsAnUnfingerprintedEntryAsUnverifiableDrift(t *testing.T) {
	home := testHome(t)
	hubURL := "https://hub.example.com"
	dest := filepath.Join(home, ".claude", "skills", "acme--code-review")
	require.NoError(t, os.MkdirAll(dest, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("# managed by amctl"), 0o644))

	saveTestRecord(t, home, hubURL, record.Profile{
		Slug: "base", Revision: 1, InstalledAt: time.Now(),
		Targets: []record.Target{record.TargetClaudeCode},
		Entries: []record.Entry{{
			ID: "acme/code-review", Version: "2.4.1", Digest: mustParseDigest(t, 1),
			Kind: record.KindSkill, Target: record.TargetClaudeCode, Dest: dest,
			// No Fingerprint: every entry installed by this build today, since
			// T049's fingerprinter is not wired into a production sync yet.
		}},
	})

	opts, result, _ := testOptions(hubURL, output.FormatHuman)
	err := runStatus(opts, statusDepsFor())
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	require.Contains(t, result.String(), "unverifiable")
}

func TestStatusWorksOfflineWithNoStoredCredential(t *testing.T) {
	home := testHome(t)
	opts, result, _ := testOptions("https://hub.example.com", output.FormatHuman)
	opts.Offline = true

	require.NoError(t, runStatus(opts, statusDepsFor()))
	require.Contains(t, result.String(), "not logged in")
	_ = home
}

func TestStatusWithoutAHubRefusesNamingTheFlag(t *testing.T) {
	opts, _, diag := testOptions("", output.FormatHuman)
	err := runStatus(opts, statusDepsFor())
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	_ = diag
}

// TestStatusReportsAFileEditedAfterSyncAsModified is the end-to-end proof that
// a real sync's fingerprint and status's drift check agree: sync now wires
// apply.TreeFingerprinter into production (cmd/sync.go), so an entry it
// installs is no longer "unverifiable" — editing it by hand afterwards must
// show up as `modified`, naming the edited path.
func TestStatusReportsAFileEditedAfterSyncAsModified(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	entryPath := filepath.Join(env.skillsRoot(), "acme--code-review", layout.SkillEntryFile)
	requireFileExists(t, entryPath)
	f, openErr := os.OpenFile(entryPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, openErr)
	_, writeErr := f.WriteString("\nedited by hand after sync\n")
	require.NoError(t, writeErr)
	require.NoError(t, f.Close())

	opts, result, _ := testOptions(tg.BaseURL, output.FormatHuman)
	statusErr := runStatus(opts, statusDepsFor())
	require.Error(t, statusErr)
	require.True(t, IsRefusal(statusErr))
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, statusErr))
	require.Contains(t, result.String(), "modified")
	require.Contains(t, result.String(), layout.SkillEntryFile)
	require.NotContains(t, result.String(), "unverifiable",
		"a fresh sync fingerprints what it installs, so this entry must be verifiable")
}

func mustParseDigest(t *testing.T, seed int) record.Digest {
	t.Helper()
	d, err := record.ParseDigest("sha256:" + repeatHex(seed))
	require.NoError(t, err)
	return d
}

func repeatHex(seed int) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = hexDigits[(seed+i)%16]
	}
	return string(b)
}
