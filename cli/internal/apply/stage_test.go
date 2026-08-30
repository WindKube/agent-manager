// T040's tests. The extractor's own behaviour — caps, refused member kinds,
// path validation — is internal/archive's suite; what is tested here is what
// Stage adds on top: WHERE the tree lands, that a leftover from an interrupted
// run is cleared rather than tripped over, that the provenance marker arrives
// with the same rename the rest of the entry does, and that a planted staging
// directory cannot steer the extraction.

package apply

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/archive"
	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

type tarMember struct {
	name     string
	typeflag byte
	mode     int64
	linkname string
	body     string
}

func file(name, body string) tarMember {
	return tarMember{name: name, typeflag: tar.TypeReg, mode: 0o644, body: body}
}

// pack builds a tar+zstd bundle with the encoder settings the hub's bundle.Pack
// uses, so the decoder meets the frame shape it will actually meet in
// production.
func packBundle(t *testing.T, ms ...tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(1<<20),
	)
	require.NoError(t, err)

	tw := tar.NewWriter(enc)
	for _, m := range ms {
		size := int64(0)
		if m.typeflag == tar.TypeReg {
			size = int64(len(m.body))
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Typeflag: m.typeflag,
			Name:     m.name,
			Mode:     m.mode,
			Size:     size,
			Linkname: m.linkname,
			ModTime:  time.Unix(0, 0).UTC(),
		}))
		if size > 0 {
			_, werr := tw.Write([]byte(m.body))
			require.NoError(t, werr)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

// skillBundle is the shape every target actually installs: SKILL.md plus a
// subdirectory.
func skillBundle(t *testing.T) []byte {
	t.Helper()
	return packBundle(t,
		file("SKILL.md", "---\nname: lint-go\n---\nthe body\n"),
		file("references/style.md", "a reference\n"),
	)
}

type stageFixture struct {
	home   string
	parent string
	dest   string
}

func newStageFixture(t *testing.T) stageFixture {
	t.Helper()
	home := t.TempDir()
	parent := filepath.Join(home, ".claude", "skills")
	return stageFixture{home: home, parent: parent, dest: filepath.Join(parent, "acme--lint-go")}
}

func requestFor(t *testing.T, f stageFixture, bundle []byte) StageRequest {
	t.Helper()
	d, err := record.ParseDigest(cache.Compute(bundle).Lockfile())
	require.NoError(t, err)
	return StageRequest{Dest: f.dest, Digest: d, Bundle: bundle}
}

// TestStageExtractsIntoASiblingOfTheDestination is gate R3's staging decision as
// an assertion: <dest-parent>/.amctl-staging/sha256-<hex>, never a central
// ~/.agent-manager/staging. Same-filesystem staging is the only thing that makes
// the install a rename, and an agent directory is frequently a symlink into a
// dotfiles repo on another mount.
func TestStageExtractsIntoASiblingOfTheDestination(t *testing.T) {
	f := newStageFixture(t)
	bundle := skillBundle(t)
	req := requestFor(t, f, bundle)

	staged, err := Stage(context.Background(), req)
	require.NoError(t, err)

	require.Equal(t, filepath.Join(f.parent, layout.StagingDirName), staged.Root)
	require.Equal(t, filepath.Dir(f.dest), filepath.Dir(staged.Root),
		"the staging root must be a child of the destination's parent")
	require.Equal(t, filepath.Join(staged.Root, req.Digest.FileName()), staged.Path)
	require.Equal(t, "sha256-"+req.Digest.Hex(), filepath.Base(staged.Path),
		"staging is digest-addressed, so two entries in one parent cannot collide")

	body, err := os.ReadFile(filepath.Join(staged.Path, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body))
	require.ElementsMatch(t, []string{"SKILL.md", "references/style.md"}, staged.Files)
	require.ElementsMatch(t, []string{"references"}, staged.Dirs)

	require.NoFileExists(t, f.dest)
	require.NoDirExists(t, f.dest, "Stage must not touch the destination; that is Swap's")
}

// TestStageThenSwapInstallsTheEntry is the two halves together, which is the
// only way to see that the paths Stage produces are the paths Swap accepts.
func TestStageThenSwapInstallsTheEntry(t *testing.T) {
	f := newStageFixture(t)
	req := requestFor(t, f, skillBundle(t))
	marker, err := layout.Marker{
		SchemaVersion: layout.MarkerSchemaVersion,
		ID:            "acme/lint-go",
		Version:       "1.2.3",
		Kind:          record.KindSkill,
		Target:        record.TargetClaudeCode,
		Digest:        req.Digest,
	}.Bytes()
	require.NoError(t, err)
	req.Marker, req.MarkerName = marker, layout.MarkerFileName

	staged, err := Stage(context.Background(), req)
	require.NoError(t, err)

	res, err := Swap(staged.Path, f.dest)
	require.NoError(t, err)
	require.NoError(t, res.SyncDirErr)
	require.NoError(t, res.RemoveAsideErr)

	require.FileExists(t, filepath.Join(f.dest, "SKILL.md"))
	require.FileExists(t, filepath.Join(f.dest, "references", "style.md"))
	require.NoDirExists(t, staged.Path, "the staged tree is consumed by the swap")

	got, err := os.ReadFile(filepath.Join(f.dest, layout.MarkerFileName))
	require.NoError(t, err)
	parsed, err := layout.ParseMarker(got)
	require.NoError(t, err)
	require.Equal(t, "acme/lint-go", parsed.ID)
	require.Equal(t, req.Digest, parsed.Digest)

	require.NoError(t, PruneStagingRoot(f.dest))
	require.NoDirExists(t, staged.Root)
	entries, err := os.ReadDir(f.parent)
	require.NoError(t, err)
	require.Len(t, entries, 1, "a completed install leaves the entry and nothing else")
}

// TestStageClearsALeftoverStagedTree is what makes an interrupted run converge
// (SC-008). The negative control is the second half: internal/archive requires
// its destination to be ABSENT, so without the RemoveAll every re-run of an
// entry that died during extraction would fail forever.
func TestStageClearsALeftoverStagedTree(t *testing.T) {
	f := newStageFixture(t)
	req := requestFor(t, f, skillBundle(t))

	leftover := filepath.Join(layout.StagingRoot(f.dest), req.Digest.FileName())
	require.NoError(t, os.MkdirAll(filepath.Join(leftover, "half-written"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(leftover, "junk"), []byte("partial"), 0o644))

	staged, err := Stage(context.Background(), req)
	require.NoError(t, err)
	require.NoFileExists(t, filepath.Join(staged.Path, "junk"),
		"a partial tree from an interrupted run must be cleared, not merged with")
	require.NoDirExists(t, filepath.Join(staged.Path, "half-written"))
	require.FileExists(t, filepath.Join(staged.Path, "SKILL.md"))

	// The negative control: the extractor alone refuses an existing destination,
	// so the clearing step is load-bearing rather than tidiness.
	_, err = archive.Extract(context.Background(), bytes.NewReader(req.Bundle), staged.Path, archive.Limits{})
	require.ErrorIs(t, err, archive.ErrUnsafeDestination)
	require.Equal(t, archive.RejectDestExists, archive.ReasonOf(err))
}

// TestStageEnforcesTheExtractorsCaps proves the caps are actually plumbed and
// that a refused bundle leaves nothing staged. The specific refusal is asserted,
// not err != nil: a cap case that fails for the wrong reason has stopped testing
// the cap.
func TestStageEnforcesTheExtractorsCaps(t *testing.T) {
	tests := []struct {
		name   string
		bundle func(t *testing.T) []byte
		limits archive.Limits
		class  error
		reason archive.Reason
	}{
		{
			name:   "a member over the single-entry cap",
			bundle: func(t *testing.T) []byte { return packBundle(t, file("SKILL.md", string(make([]byte, 4096)))) },
			limits: archive.Limits{MaxEntryBytes: 512, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			class:  archive.ErrTooLarge,
			reason: archive.CapEntrySize,
		},
		{
			name: "a symlink member",
			bundle: func(t *testing.T) []byte {
				return packBundle(t,
					file("SKILL.md", "body"),
					tarMember{name: "escape", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../../../etc/passwd"},
				)
			},
			class:  archive.ErrRejectedMember,
			reason: archive.RejectSymlink,
		},
		{
			name: "a subdirectory that would make the skill a plugin",
			bundle: func(t *testing.T) []byte {
				return packBundle(t, file("SKILL.md", "body"), file("hooks/pre.sh", "#!/bin/sh\n"))
			},
			class:  archive.ErrRejectedMember,
			reason: archive.RejectPluginAdoptingDir,
		},
		{
			name:   "a member with an absolute path",
			bundle: func(t *testing.T) []byte { return packBundle(t, file("/etc/passwd", "root")) },
			class:  archive.ErrRejectedMember,
			reason: archive.RejectAbsolutePath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newStageFixture(t)
			req := requestFor(t, f, tc.bundle(t))
			req.Limits = tc.limits

			staged, err := Stage(context.Background(), req)
			require.Nil(t, staged)
			require.ErrorIs(t, err, tc.class)
			require.Equal(t, tc.reason, archive.ReasonOf(err))

			require.NoDirExists(t, filepath.Join(layout.StagingRoot(f.dest), req.Digest.FileName()),
				"a refused bundle must leave no partial tree behind")
			require.NoFileExists(t, f.dest)
		})
	}
}

// TestStageWritesTheProvenanceMarkerIntoTheStagedTree — FR-022. It has to be in
// the staged tree: a write into the destination after the swap would be a second
// mutation with its own window, and it would fall outside R4's fingerprint of
// the tree as installed.
func TestStageWritesTheProvenanceMarkerIntoTheStagedTree(t *testing.T) {
	f := newStageFixture(t)
	req := requestFor(t, f, skillBundle(t))
	req.Marker, req.MarkerName = []byte("{\"schemaVersion\":1}\n"), layout.MarkerFileName

	staged, err := Stage(context.Background(), req)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(staged.Path, layout.MarkerFileName))
	require.NoError(t, err)
	require.Equal(t, "{\"schemaVersion\":1}\n", string(got))
	require.Contains(t, staged.Files, layout.MarkerFileName,
		"the marker is inside the entry root, so R4's closed set must include it or a legitimate prune deletes work")

	body, err := os.ReadFile(filepath.Join(staged.Path, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body),
		"SKILL.md must never be edited to stamp provenance: those bytes were just verified by digest")
}

// TestStageRefusesABundleThatShipsItsOwnMarker. A bundle carrying
// .agent-manager.json would be forging its own provenance, and O_EXCL turns that
// into a loud refusal instead of a silent overwrite.
func TestStageRefusesABundleThatShipsItsOwnMarker(t *testing.T) {
	f := newStageFixture(t)
	req := requestFor(t, f, packBundle(t,
		file("SKILL.md", "body"),
		file(layout.MarkerFileName, `{"id":"attacker/x"}`),
	))
	req.Marker, req.MarkerName = []byte("{}"), layout.MarkerFileName

	staged, err := Stage(context.Background(), req)
	require.Nil(t, staged)
	require.ErrorIs(t, err, ErrStaging)
	require.Contains(t, err.Error(), layout.MarkerFileName)
	require.NoDirExists(t, filepath.Join(layout.StagingRoot(f.dest), req.Digest.FileName()))
}

func TestStageRefusesAMarkerNameThatIsNotAFilename(t *testing.T) {
	tests := []struct {
		name       string
		markerName string
		marker     []byte
		want       string
	}{
		{"a traversal", "../" + layout.MarkerFileName, []byte("{}"), "not a single filename"},
		{"a nested path", "sub/" + layout.MarkerFileName, []byte("{}"), "not a single filename"},
		{"a bare dot", ".", []byte("{}"), "not a single filename"},
		{"bytes with no name", "", []byte("{}"), "no marker name"},
		{"a name with no bytes", layout.MarkerFileName, nil, "no marker bytes"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newStageFixture(t)
			req := requestFor(t, f, skillBundle(t))
			req.Marker, req.MarkerName = tc.marker, tc.markerName

			_, err := Stage(context.Background(), req)
			require.ErrorIs(t, err, ErrStaging)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestStageRefusesASymlinkedStagingDirectory is the FR-020 hole that
// os.MkdirAll followed by os.OpenRoot on the full path would leave open:
// os.OpenRoot resolves its own argument normally, so a planted .amctl-staging
// symlink would confine the root to wherever it points and every extracted byte
// would land there, with no path outside the home ever constructed.
func TestStageRefusesASymlinkedStagingDirectory(t *testing.T) {
	outside := t.TempDir()
	f := newStageFixture(t)
	require.NoError(t, os.MkdirAll(f.parent, 0o755))
	gateRequireSymlink(t, outside, filepath.Join(f.parent, layout.StagingDirName))

	req := requestFor(t, f, skillBundle(t))
	staged, err := Stage(context.Background(), req)
	require.Nil(t, staged)
	require.ErrorIs(t, err, ErrStaging)
	require.Contains(t, err.Error(), "is a symlink")

	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	require.Empty(t, entries, "not one byte may be written through the planted link")
}

func TestStageRefusesAnUnusableRequest(t *testing.T) {
	f := newStageFixture(t)
	bundle := skillBundle(t)

	t.Run("a zero digest", func(t *testing.T) {
		req := requestFor(t, f, bundle)
		req.Digest = record.Digest{}
		_, err := Stage(context.Background(), req)
		require.ErrorIs(t, err, ErrStaging)
		require.Contains(t, err.Error(), "no digest")
	})

	t.Run("no bundle bytes", func(t *testing.T) {
		req := requestFor(t, f, bundle)
		req.Bundle = nil
		_, err := Stage(context.Background(), req)
		require.ErrorIs(t, err, ErrStaging)
		require.Contains(t, err.Error(), "no bundle bytes")
	})

	t.Run("a relative destination", func(t *testing.T) {
		req := requestFor(t, f, bundle)
		req.Dest = filepath.Join("skills", "acme--lint-go")
		_, err := Stage(context.Background(), req)
		require.ErrorIs(t, err, ErrDest)
	})

	t.Run("a destination that is the swap's own aside", func(t *testing.T) {
		req := requestFor(t, f, bundle)
		req.Dest = f.dest + AsideSuffix
		_, err := Stage(context.Background(), req)
		require.ErrorIs(t, err, ErrDest)
	})
}

// TestStageCreatesTheAgentDirectoryChain — the skills directory does not exist
// on a machine that has never run the agent, and staging is inside it.
func TestStageCreatesTheAgentDirectoryChain(t *testing.T) {
	f := newStageFixture(t)
	require.NoDirExists(t, f.parent)

	staged, err := Stage(context.Background(), requestFor(t, f, skillBundle(t)))
	require.NoError(t, err)
	require.DirExists(t, f.parent)
	require.DirExists(t, staged.Path)
}

func TestDiscardRemovesTheStagedTree(t *testing.T) {
	f := newStageFixture(t)
	staged, err := Stage(context.Background(), requestFor(t, f, skillBundle(t)))
	require.NoError(t, err)

	require.NoError(t, staged.Discard())
	require.NoDirExists(t, staged.Path)
	require.NoError(t, staged.Discard(), "discarding twice is not an error; the second run re-stages over it anyway")
	require.NoError(t, PruneStagingRoot(f.dest))
	require.NoDirExists(t, staged.Root)
}

// TestPruneStagingRootRemovesOnlyAnEmptyStagingDirectory. The staging root is
// shared by every entry under one parent, so removing it while another entry is
// staged there would delete a tree that is about to be installed.
func TestPruneStagingRootRemovesOnlyAnEmptyStagingDirectory(t *testing.T) {
	f := newStageFixture(t)
	first, err := Stage(context.Background(), requestFor(t, f, skillBundle(t)))
	require.NoError(t, err)

	other := f
	other.dest = filepath.Join(f.parent, "globex--lint-go")
	second, err := Stage(context.Background(), requestFor(t, other, packBundle(t, file("SKILL.md", "another"))))
	require.NoError(t, err)
	require.Equal(t, first.Root, second.Root, "one staging root per destination parent")

	require.NoError(t, PruneStagingRoot(f.dest))
	require.DirExists(t, second.Path, "a staging root holding another entry's tree must be left alone")

	require.NoError(t, first.Discard())
	require.NoError(t, second.Discard())
	require.NoError(t, PruneStagingRoot(f.dest))
	require.NoDirExists(t, first.Root)

	require.NoError(t, PruneStagingRoot(f.dest), "an absent staging root is not an error")
}

// TestStagedOpenRootReadsTheStagedTreeAndCannotEscapeIt. R4 hashes the staged
// content before the swap, and it must read through a root: FILE_SHARE_DELETE is
// granted by whoever OPENS a file, so a plain os.Open of a staged file on
// Windows would deny the swap's own rename the delete access it needs.
func TestStagedOpenRootReadsTheStagedTreeAndCannotEscapeIt(t *testing.T) {
	f := newStageFixture(t)
	staged, err := Stage(context.Background(), requestFor(t, f, skillBundle(t)))
	require.NoError(t, err)

	root, err := staged.OpenRoot()
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	body, err := root.ReadFile("SKILL.md")
	require.NoError(t, err)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body))

	_, err = root.Open(filepath.Join("..", "..", "acme--lint-go"))
	require.Error(t, err, "a root confined to the staged tree must not read outside it")
}

// TestStageRefusesACancelledContext — the caller's cancellation is passed
// through as the caller's, not reported as an archive defect.
func TestStageRefusesACancelledContext(t *testing.T) {
	f := newStageFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Stage(ctx, requestFor(t, f, skillBundle(t)))
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, errors.Is(err, fs.ErrExist))
}
