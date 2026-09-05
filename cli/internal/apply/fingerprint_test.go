package apply

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// installedFixture stages and swaps skillBundle(t) into a fresh destination,
// takes its fingerprint the way cmd/sync.go now does — Hash before the swap,
// Modes after — and returns the entry a Verifier would be asked about.
func installedFixture(t *testing.T) (dest string, entry record.Entry) {
	t.Helper()
	f := newStageFixture(t)
	req := requestFor(t, f, skillBundle(t))

	staged, err := Stage(context.Background(), req)
	require.NoError(t, err)

	tf := TreeFingerprinter{}
	fp, err := tf.Hash(staged)
	require.NoError(t, err)

	_, err = Swap(staged.Path, f.dest)
	require.NoError(t, err)

	fp, err = tf.Modes(f.dest, fp)
	require.NoError(t, err)

	return f.dest, record.Entry{
		ID: "acme/lint-go", Version: "1.0.0", Digest: req.Digest,
		Kind: record.KindSkill, Target: record.TargetClaudeCode,
		Dest: f.dest, Fingerprint: fp,
	}
}

func TestTreeFingerprinterHashAndModesRoundTrip(t *testing.T) {
	dest, entry := installedFixture(t)

	require.Equal(t, record.FingerprintAlgo, entry.Fingerprint.Algo)
	require.Contains(t, entry.Fingerprint.Files, "SKILL.md")
	require.Contains(t, entry.Fingerprint.Files, "references/style.md")
	require.Contains(t, entry.Fingerprint.Dirs, "references")

	mark := entry.Fingerprint.Files["SKILL.md"]
	require.Len(t, mark.SHA256, 64)
	require.Equal(t, record.FileKindRegular, mark.Kind)
	require.NotZero(t, mark.Mode)

	info, err := os.Stat(filepath.Join(dest, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, info.Size(), mark.Size)

	changed, err := (TreeFingerprinter{}).Modifications(entry)
	require.NoError(t, err)
	require.Empty(t, changed, "an entry just installed must verify as unmodified")
}

func TestTreeFingerprinterDetectsAnEditedFile(t *testing.T) {
	dest, entry := installedFixture(t)

	require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("edited by hand"), 0o644))

	changed, err := (TreeFingerprinter{}).Modifications(entry)
	require.NoError(t, err)
	require.Equal(t, []string{"SKILL.md"}, changed)
}

func TestTreeFingerprinterDetectsARemovedAndAnAddedPath(t *testing.T) {
	dest, entry := installedFixture(t)

	require.NoError(t, os.Remove(filepath.Join(dest, "references", "style.md")))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "extra.md"), []byte("not installed by amctl"), 0o644))

	changed, err := (TreeFingerprinter{}).Modifications(entry)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"references/style.md", "extra.md"}, changed)
}

func TestTreeFingerprinterRefusesAnUnrecognisedAlgorithm(t *testing.T) {
	_, entry := installedFixture(t)
	entry.Fingerprint.Algo = "some-future-algorithm"

	_, err := (TreeFingerprinter{}).Modifications(entry)
	require.ErrorIs(t, err, ErrFingerprintAlgo)
}

func TestTreeFingerprinterRefusesAnAbsentFingerprint(t *testing.T) {
	dest, entry := installedFixture(t)
	entry.Fingerprint = record.Fingerprint{}
	_ = dest

	_, err := (TreeFingerprinter{}).Modifications(entry)
	require.ErrorIs(t, err, ErrFingerprintAlgo, "an entry recorded before T049 has no fingerprint at all")
}
