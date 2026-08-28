package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// Every hostile archive in this file is built here, with archive/tar and a zstd
// writer, rather than committed as a fixture: a binary fixture cannot be reviewed,
// gitleaks scans it, and a reader cannot tell a zip bomb from a skill by looking.
//
// Two rules the suite lives or dies by:
//
//   - Assert the SPECIFIC reason, never err != nil. A symlink-escape case that
//     passes because the total-size cap fired first has stopped testing symlinks and
//     nothing about it looks wrong. requireRefusal is the only assertion used for a
//     negative case, and it compares the Reason for equality.
//   - Every cap case sets the OTHER caps out of the way, so exactly one of them can
//     fire. Where that is not done the case would still pass with the cap under test
//     deleted.

type member struct {
	name     string
	typeflag byte
	mode     int64
	linkname string
	body     []byte
	// zeroBody asks for that many zero bytes without materialising them; the zstd
	// bomb needs 64 MiB of body and no test needs 64 MiB of RAM.
	zeroBody int64
	devmajor int64
	devminor int64
}

func regular(name, body string) member {
	return member{name: name, typeflag: tar.TypeReg, mode: 0o644, body: []byte(body)}
}

func executable(name, body string) member {
	return member{name: name, typeflag: tar.TypeReg, mode: 0o755, body: []byte(body)}
}

func directory(name string) member {
	return member{name: strings.TrimSuffix(name, "/") + "/", typeflag: tar.TypeDir, mode: 0o755}
}

func hasBody(typeflag byte) bool {
	return typeflag == tar.TypeReg
}

// pack builds a tar+zstd archive with the same encoder settings the hub's
// bundle.Pack uses, so the decoder under test faces the frame shape it will actually
// meet in production.
func pack(t *testing.T, ms ...member) []byte {
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
		size := int64(len(m.body)) + m.zeroBody
		if !hasBody(m.typeflag) {
			size = 0
		}
		hdr := &tar.Header{
			Typeflag: m.typeflag,
			Name:     m.name,
			Mode:     m.mode,
			Size:     size,
			Linkname: m.linkname,
			Devmajor: m.devmajor,
			Devminor: m.devminor,
			ModTime:  time.Unix(0, 0).UTC(),
		}
		require.NoError(t, tw.WriteHeader(hdr), "writing header for %q", m.name)
		if len(m.body) > 0 {
			_, wErr := tw.Write(m.body)
			require.NoError(t, wErr)
		}
		if m.zeroBody > 0 {
			writeZeros(t, tw, m.zeroBody)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

func writeZeros(t *testing.T, w io.Writer, n int64) {
	t.Helper()
	block := make([]byte, 1<<20)
	for n > 0 {
		chunk := int64(len(block))
		if chunk > n {
			chunk = n
		}
		written, err := w.Write(block[:chunk])
		require.NoError(t, err)
		n -= int64(written)
	}
}

// newDest returns a path that does not exist inside a parent that does, which is
// Extract's contract.
func newDest(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "skill")
}

func requireRefusal(t *testing.T, err, class error, reason Reason) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, class, "wrong failure class for: %v", err)
	require.Equal(t, reason, ReasonOf(err), "wrong reason for: %v", err)
}

func treeBytes(t *testing.T, root string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		total += info.Size()
		return nil
	})
	if os.IsNotExist(err) {
		return 0
	}
	require.NoError(t, err)
	return total
}

// looseLimits puts every cap except the named one out of reach, so a case can only
// fail for the reason it is testing.
func looseLimits() Limits {
	return Limits{
		MaxCompressedBytes:   1 << 30,
		MaxDecompressedBytes: 1 << 30,
		MaxCompressionRatio:  1 << 20,
		RatioGraceBytes:      1 << 30,
		MaxEntries:           1 << 20,
		MaxEntryBytes:        1 << 30,
		MaxPathDepth:         1024,
		MaxPathBytes:         4096,
		MaxDuration:          time.Minute,
	}
}

func TestExtractWritesTheTree(t *testing.T) {
	t.Parallel()

	// The hub's bundle.Pack emits regular files only, with no directory members at
	// all, so implicit parent creation is the production path and not an edge case.
	data := pack(t,
		regular("SKILL.md", "# skill\n"),
		regular("references/notes.md", "notes\n"),
		executable("scripts/run.sh", "#!/bin/sh\n"),
	)

	dest := newDest(t)
	res, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	require.NoError(t, err)

	require.Equal(t, []string{"SKILL.md", "references/notes.md", "scripts/run.sh"}, res.Files)
	require.Equal(t, []string{"references", "scripts"}, res.Dirs)
	require.Equal(t, dest, res.Dest)
	require.Positive(t, res.CompressedBytes)
	require.EqualValues(t, len("# skill\n")+len("notes\n")+len("#!/bin/sh\n"), res.DecompressedBytes)

	body, err := os.ReadFile(filepath.Join(dest, "references", "notes.md"))
	require.NoError(t, err)
	require.Equal(t, "notes\n", string(body))

	// The archive chooses executable or not and nothing else: no setuid, no sticky,
	// no group-write, whatever the header asked for.
	info, err := os.Lstat(filepath.Join(dest, "scripts", "run.sh"))
	require.NoError(t, err)
	require.Zero(t, info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))

	plain, err := os.Lstat(filepath.Join(dest, "SKILL.md"))
	require.NoError(t, err)

	// Windows has no executable bit. Go synthesises 0666 for every writable file
	// and 0444 for a read-only one, so neither the presence nor the absence of
	// 0o100 carries information there and BOTH assertions below would be
	// meaningless — the second one would even pass for the wrong reason, since
	// 0666&0o111 is 0 whatever the header said.
	//
	// The product consequence is real and is not worked around anywhere: a
	// skill's scripts/run.sh is not executable on Windows, so anything that
	// depends on running it directly depends on an interpreter being named
	// explicitly. Nothing in this feature runs a skill's scripts, so that is a
	// statement rather than a defect — but it stops being one the moment
	// something does.
	if runtime.GOOS == "windows" {
		require.Equal(t, fs.FileMode(0o666), info.Mode().Perm(), "windows synthesises the mode; if that changes, revisit this")
		return
	}
	require.NotZero(t, info.Mode().Perm()&0o100, "executable bit lost")
	require.Zero(t, plain.Mode().Perm()&0o111, "non-executable member became executable")
}

func TestExtractAcceptsExplicitDirectoryMembers(t *testing.T) {
	t.Parallel()

	data := pack(t,
		directory("./"),
		directory("references"),
		regular("references/a.md", "a\n"),
		regular("SKILL.md", "s\n"),
	)

	dest := newDest(t)
	res, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	require.NoError(t, err)
	require.Equal(t, []string{"references/a.md", "SKILL.md"}, res.Files)
	require.Equal(t, []string{"references"}, res.Dirs)
}

func TestExtractCaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members []member
		limits  func(Limits) Limits
		reason  Reason
	}{
		{
			name:    "compressed archive larger than the compressed cap",
			members: []member{regular("SKILL.md", strings.Repeat("payload ", 40_000))},
			limits: func(l Limits) Limits {
				l.MaxCompressedBytes = 64
				return l
			},
			reason: CapCompressedSize,
		},
		{
			name:    "total decompressed size over the cap",
			members: []member{regular("a.md", strings.Repeat("a", 4096)), regular("b.md", strings.Repeat("b", 4096))},
			limits: func(l Limits) Limits {
				l.MaxDecompressedBytes = 5000
				return l
			},
			reason: CapDecompressedSize,
		},
		{
			name:    "one member over the per-entry cap",
			members: []member{regular("SKILL.md", strings.Repeat("a", 4096))},
			limits: func(l Limits) Limits {
				l.MaxEntryBytes = 1000
				return l
			},
			reason: CapEntrySize,
		},
		{
			name:    "more members than the entry-count cap",
			members: []member{regular("a.md", "a"), regular("b.md", "b"), regular("c.md", "c")},
			limits: func(l Limits) Limits {
				l.MaxEntries = 2
				return l
			},
			reason: CapEntryCount,
		},
		{
			name:    "path deeper than the depth cap",
			members: []member{regular("a/b/c/d/SKILL.md", "x")},
			limits: func(l Limits) Limits {
				l.MaxPathDepth = 3
				return l
			},
			reason: CapPathDepth,
		},
		{
			name:    "path longer than the length cap",
			members: []member{regular(strings.Repeat("n", 200)+".md", "x")},
			limits: func(l Limits) Limits {
				l.MaxPathBytes = 32
				return l
			},
			reason: CapPathLength,
		},
		{
			name:    "compression ratio over the cap",
			members: []member{{name: "bomb.bin", typeflag: tar.TypeReg, mode: 0o644, zeroBody: 8 << 20}},
			limits: func(l Limits) Limits {
				l.MaxCompressionRatio = 4
				l.RatioGraceBytes = 4096
				return l
			},
			reason: CapCompressionRatio,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := pack(t, tc.members...)
			_, err := Extract(context.Background(), bytes.NewReader(data), newDest(t), tc.limits(looseLimits()))
			requireRefusal(t, err, ErrTooLarge, tc.reason)
		})
	}
}

func TestExtractRefusedMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members []member
		reason  Reason
		path    string
	}{
		{
			name:    "absolute path",
			members: []member{{name: "/etc/passwd", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectAbsolutePath,
			path:    "/etc/passwd",
		},
		{
			name:    "windows drive letter",
			members: []member{{name: `C:/Windows/system32/x`, typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectAbsolutePath,
			path:    `C:/Windows/system32/x`,
		},
		{
			name:    "leading parent traversal",
			members: []member{{name: "../escaped.md", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectTraversal,
			path:    "../escaped.md",
		},
		{
			// The interesting half: `..` that only escapes after path.Clean folds it.
			name:    "traversal that survives cleaning",
			members: []member{{name: "a/b/../../../escaped.md", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectTraversal,
			path:    "a/b/../../../escaped.md",
		},
		{
			name:    "backslash separator",
			members: []member{{name: `a\..\..\escaped.md`, typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectPathChars,
			path:    `a\..\..\escaped.md`,
		},
		{
			name:    "empty path",
			members: []member{{name: "", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}},
			reason:  RejectEmptyPath,
		},
		{
			name:    "symlink member",
			members: []member{{name: "link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "SKILL.md"}},
			reason:  RejectSymlink,
			path:    "link",
		},
		{
			name:    "hardlink member",
			members: []member{regular("SKILL.md", "s"), {name: "hard", typeflag: tar.TypeLink, linkname: "SKILL.md"}},
			reason:  RejectHardlink,
			path:    "hard",
		},
		{
			name:    "character device member",
			members: []member{{name: "dev/null", typeflag: tar.TypeChar, mode: 0o666, devmajor: 1, devminor: 3}},
			reason:  RejectDevice,
			path:    "dev/null",
		},
		{
			name:    "block device member",
			members: []member{{name: "dev/sda", typeflag: tar.TypeBlock, mode: 0o660, devmajor: 8}},
			reason:  RejectDevice,
			path:    "dev/sda",
		},
		{
			name:    "fifo member",
			members: []member{{name: "pipe", typeflag: tar.TypeFifo, mode: 0o666}},
			reason:  RejectFIFO,
			path:    "pipe",
		},
		{
			// An unrecognised typeflag reports a regular-file mode through
			// tar.Header.FileInfo, so a mode-based type check waves it straight
			// through. This case is what forces the switch to be on the typeflag.
			name:    "unknown member type",
			members: []member{{name: "weird", typeflag: 'z', mode: 0o644}},
			reason:  RejectMemberType,
			path:    "weird",
		},
		{
			name:    "duplicate path",
			members: []member{regular("SKILL.md", "first"), regular("SKILL.md", "second")},
			reason:  RejectDuplicate,
			path:    "SKILL.md",
		},
		{
			name:    "directory colliding with a file",
			members: []member{regular("references", "file"), directory("references")},
			reason:  RejectDuplicate,
			path:    "references/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := pack(t, tc.members...)
			dest := newDest(t)
			_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
			requireRefusal(t, err, ErrRejectedMember, tc.reason)
			if tc.path != "" {
				require.Equal(t, tc.path, PathOf(err), "the refusal must name the offending member")
			}
		})
	}
}

// TestExtractRefusesCaseOnlyCollision answers a question the platforms disagree
// about: a bundle carrying both SKILL.md and Skill.md is ONE file on a
// case-insensitive filesystem (darwin, Windows) and TWO on linux. The extractor
// refuses it everywhere rather than extracting two files on linux and failing on
// O_EXCL on darwin, because a digest that installs a different tree per platform
// breaks FR-024 and R4's install fingerprint.
func TestExtractRefusesCaseOnlyCollision(t *testing.T) {
	t.Parallel()

	data := pack(t, regular("SKILL.md", "first"), regular("Skill.md", "second"))
	_, err := Extract(context.Background(), bytes.NewReader(data), newDest(t), Limits{})
	requireRefusal(t, err, ErrRejectedMember, RejectDuplicate)
	require.Equal(t, "Skill.md", PathOf(err))
	require.Contains(t, err.Error(), "differs only in case from SKILL.md")
}

// TestExtractRefusesPluginAdoptingSubdir covers R2's hazard: the destination root IS
// the skill directory, so a top-level subdirectory with one of these names makes
// claude-code adopt the tree as a plugin, with lifecycle hooks and MCP servers. The
// allow cases matter as much as the refusals — refusing references/hooks/ would
// reject legitimate content and the rule would be wrong in the expensive direction.
func TestExtractRefusesPluginAdoptingSubdir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		members   []member
		refused   bool
		refusedAt string
	}{
		{
			name:      "hooks directory at the skill root",
			members:   []member{regular("SKILL.md", "s"), regular("hooks/hooks.json", "{}")},
			refused:   true,
			refusedAt: "hooks/hooks.json",
		},
		{
			name:      "claude-plugin marker directory",
			members:   []member{regular(".claude-plugin/plugin.json", "{}")},
			refused:   true,
			refusedAt: ".claude-plugin/plugin.json",
		},
		{
			name:      "explicit agents directory member",
			members:   []member{directory("agents")},
			refused:   true,
			refusedAt: "agents/",
		},
		{
			name:      "case-varied adopting name",
			members:   []member{regular("Workflows/w.md", "w")},
			refused:   true,
			refusedAt: "Workflows/w.md",
		},
		{
			// Adoption is decided at the skill root. Deeper is inert.
			name:    "adopting name nested below the root",
			members: []member{regular("SKILL.md", "s"), regular("references/hooks/notes.md", "n")},
		},
		{
			// A file named hooks is a file, not a subdirectory.
			name:    "plain file named hooks at the root",
			members: []member{regular("SKILL.md", "s"), regular("hooks", "not a directory")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := pack(t, tc.members...)
			_, err := Extract(context.Background(), bytes.NewReader(data), newDest(t), Limits{})
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			requireRefusal(t, err, ErrRejectedMember, RejectPluginAdoptingDir)
			require.Equal(t, tc.refusedAt, PathOf(err))
		})
	}
}

// TestExtractSymlinkEscape is the escape a per-entry filepath.Clean check misses.
// Entry one is a directory. Entry two is a symlink at a path INSIDE it pointing
// outside the destination. Entry three writes through that symlink with a path that
// is clean and relative at every step, so nothing about entry three looks wrong.
//
// The design's invariant — no path component under the root that this extraction did
// not itself create — means this is refused at entry TWO. That is what is asserted,
// rather than merely that the whole thing failed.
func TestExtractSymlinkEscape(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	outside := filepath.Join(tmp, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))
	canary := filepath.Join(outside, "canary.txt")
	require.NoError(t, os.WriteFile(canary, []byte("original"), 0o600))

	dest := filepath.Join(tmp, "skill")
	data := pack(t,
		directory("nested"),
		member{name: "nested/link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: outside},
		regular("nested/link/canary.txt", "overwritten"),
	)

	_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	requireRefusal(t, err, ErrRejectedMember, RejectSymlink)
	require.Equal(t, "nested/link", PathOf(err), "must be refused at the symlink, not later")

	// Entry one really was processed, so the refusal happened at entry two rather
	// than before the walk started.
	info, statErr := os.Lstat(filepath.Join(dest, "nested"))
	require.NoError(t, statErr)
	require.True(t, info.IsDir())

	body, readErr := os.ReadFile(canary)
	require.NoError(t, readErr)
	require.Equal(t, "original", string(body), "wrote through the symlink")

	_, statErr = os.Lstat(filepath.Join(dest, "nested", "link"))
	require.True(t, os.IsNotExist(statErr), "a symlink was created inside the destination")
}

// TestExtractSymlinkEscapeRelative is the same escape with a relative link target,
// which is the form os.Root's own containment check would have to catch if the
// member check were removed. Kept separate so a change that only handles absolute
// targets fails one of the two.
func TestExtractSymlinkEscapeRelative(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tmp, "outside"), 0o755))
	canary := filepath.Join(tmp, "outside", "canary.txt")
	require.NoError(t, os.WriteFile(canary, []byte("original"), 0o600))

	dest := filepath.Join(tmp, "skill")
	data := pack(t,
		directory("nested"),
		member{name: "nested/link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../../outside"},
		regular("nested/link/canary.txt", "overwritten"),
	)

	_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	requireRefusal(t, err, ErrRejectedMember, RejectSymlink)
	require.Equal(t, "nested/link", PathOf(err))

	body, readErr := os.ReadFile(canary)
	require.NoError(t, readErr)
	require.Equal(t, "original", string(body))
}

// TestExtractHardlinkEscape: a hardlink needs no symlink resolution and no
// traversal in the written path — the escape is entirely in Linkname, which a path
// check never looks at. Refused on the member kind.
func TestExtractHardlinkEscape(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	secret := filepath.Join(tmp, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))

	dest := filepath.Join(tmp, "skill")
	data := pack(t,
		regular("SKILL.md", "s"),
		member{name: "stolen.txt", typeflag: tar.TypeLink, linkname: "../secret.txt"},
	)

	_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	requireRefusal(t, err, ErrRejectedMember, RejectHardlink)
	require.Equal(t, "stolen.txt", PathOf(err))

	_, statErr := os.Lstat(filepath.Join(dest, "stolen.txt"))
	require.True(t, os.IsNotExist(statErr))
}

// TestExtractDeepPath uses the REAL default depth cap, not a lowered one: a deep
// path is a hostile shape in its own right (it exhausts PATH_MAX on the consumer
// side and can defeat a recursive remove), so the shipped number is the one worth
// proving.
func TestExtractDeepPath(t *testing.T) {
	t.Parallel()

	deep := strings.Repeat("d/", DefaultMaxPathDepth+8) + "SKILL.md"
	data := pack(t, regular(deep, "x"))

	_, err := Extract(context.Background(), bytes.NewReader(data), newDest(t), Limits{})
	requireRefusal(t, err, ErrTooLarge, CapPathDepth)
}

// TestExtractZstdBomb is a real bomb against the REAL default caps: 64 MiB of zeros
// in one member, which zstd squeezes into a couple of kilobytes. The assertion that
// matters is the second one — the refusal has to arrive with barely anything on
// disk. A ratio cap checked after extraction would pass the first assertion and fail
// the second, which is exactly the bug FR-019 is about.
func TestExtractZstdBomb(t *testing.T) {
	t.Parallel()

	const decompressed = 64 << 20
	data := pack(t, member{name: "bomb.bin", typeflag: tar.TypeReg, mode: 0o644, zeroBody: decompressed})
	require.Less(t, len(data), 1<<20, "the bomb must actually be small to be a bomb")

	dest := newDest(t)
	_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
	requireRefusal(t, err, ErrTooLarge, CapCompressionRatio)

	landed := treeBytes(t, dest)
	require.Less(t, landed, int64(4<<20), "the cap fired after the bomb landed: %d bytes written", landed)
}

func TestExtractUnsafeDestination(t *testing.T) {
	t.Parallel()

	data := pack(t, regular("SKILL.md", "s"))

	t.Run("destination already exists", func(t *testing.T) {
		t.Parallel()
		dest := newDest(t)
		require.NoError(t, os.Mkdir(dest, 0o755))
		_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestExists)
	})

	t.Run("destination is a symlink", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		target := filepath.Join(tmp, "elsewhere")
		require.NoError(t, os.Mkdir(target, 0o755))
		dest := filepath.Join(tmp, "skill")
		require.NoError(t, os.Symlink(target, dest))

		_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestSymlink)

		entries, readErr := os.ReadDir(target)
		require.NoError(t, readErr)
		require.Empty(t, entries, "wrote through a symlinked destination")
	})

	t.Run("destination parent does not exist", func(t *testing.T) {
		t.Parallel()
		dest := filepath.Join(t.TempDir(), "missing", "skill")
		_, err := Extract(context.Background(), bytes.NewReader(data), dest, Limits{})
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestUnresolvable)
	})

	t.Run("destination has no directory name", func(t *testing.T) {
		t.Parallel()
		_, err := Extract(context.Background(), bytes.NewReader(data), "/", Limits{})
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestUnresolvable)
	})
}

// trickleReader hands back one byte per Read after a delay: a peer that never stops
// and never stalls inside a single Read. It is the only shape the wall-clock cap can
// actually catch, which is the point of the test.
type trickleReader struct {
	data  []byte
	pos   int
	delay time.Duration
}

func (r *trickleReader) Read(p []byte) (int, error) {
	time.Sleep(r.delay)
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// TestExtractWallClockCapAgainstTricklingReader answers "is MaxDuration enforced or
// is it a field nothing reads": the archive is perfectly valid and every size cap is
// out of reach, so the ONLY thing that can fail this extraction is the clock.
func TestExtractWallClockCapAgainstTricklingReader(t *testing.T) {
	t.Parallel()

	data := pack(t, regular("SKILL.md", strings.Repeat("s", 4096)))
	lim := looseLimits()
	lim.MaxDuration = 150 * time.Millisecond

	start := time.Now()
	_, err := Extract(context.Background(), &trickleReader{data: data, delay: 2 * time.Millisecond}, newDest(t), lim)
	elapsed := time.Since(start)

	requireRefusal(t, err, ErrTimeout, ReasonTimeBudget)
	require.Contains(t, err.Error(), lim.MaxDuration.String())
	require.Less(t, elapsed, 5*time.Second, "the cap did not stop the trickle promptly")
}

// TestExtractCallerCancellationIsNotArchiveFailure: a Ctrl-C or a sync-wide deadline
// is not a defect in the bundle and must not be reported as one, or the publisher
// gets blamed for the operator's own cancellation.
func TestExtractCallerCancellationIsNotArchiveFailure(t *testing.T) {
	t.Parallel()

	data := pack(t, regular("SKILL.md", "s"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Extract(ctx, bytes.NewReader(data), newDest(t), Limits{})
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrTimeout)
	require.NotErrorIs(t, err, ErrMalformed)
}

func TestExtractMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    func(t *testing.T) []byte
		message string
	}{
		{
			name:    "empty input",
			body:    func(*testing.T) []byte { return nil },
			message: "empty archive",
		},
		{
			name:    "plain tar without compression",
			body:    func(t *testing.T) []byte { return rawTar(t, regular("SKILL.md", "s")) },
			message: "unrecognised archive format",
		},
		{
			// The hub's own ingestion accepts .tar.gz; this package accepts one format.
			name: "gzip instead of zstd",
			body: func(t *testing.T) []byte {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				_, err := gz.Write(rawTar(t, regular("SKILL.md", "s")))
				require.NoError(t, err)
				require.NoError(t, gz.Close())
				return buf.Bytes()
			},
			message: "unrecognised archive format",
		},
		{
			name: "zip instead of zstd",
			body: func(*testing.T) []byte {
				return append([]byte("PK\x03\x04"), make([]byte, 64)...)
			},
			message: "unrecognised archive format",
		},
		{
			name: "truncated zstd frame",
			body: func(t *testing.T) []byte {
				full := pack(t, regular("SKILL.md", strings.Repeat("s", 8192)))
				return full[:len(full)/2]
			},
			message: "",
		},
		{
			name:    "valid zstd holding an empty tar",
			body:    func(t *testing.T) []byte { return pack(t) },
			message: "no members",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Extract(context.Background(), bytes.NewReader(tc.body(t)), newDest(t), Limits{})
			require.ErrorIs(t, err, ErrMalformed, "got: %v", err)
			if tc.message != "" {
				require.Contains(t, err.Error(), tc.message)
			}
		})
	}
}

func rawTar(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Typeflag: m.typeflag,
			Name:     m.name,
			Mode:     m.mode,
			Size:     int64(len(m.body)),
			ModTime:  time.Unix(0, 0).UTC(),
		}))
		_, err := tw.Write(m.body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// TestValidatePathRejectsNUL is the one case asserted below Extract rather than
// through it, and the reason is worth recording: Go's archive/tar trims the ustar
// name field at the first NUL and rejects a PAX record containing one, so a NUL
// CANNOT reach the extractor through this decoder — verified, a hand-built header
// carrying "a\x00b" reads back as "a". The check is kept because it is one stdlib
// change or one hand-rolled reader away from mattering and it costs nothing, and it
// is tested here so it is not dead code nobody can prove.
func TestValidatePathRejectsNUL(t *testing.T) {
	t.Parallel()

	e, cancel := newExtractor(context.Background(), DefaultLimits())
	defer cancel()

	_, _, err := e.validatePath("refs/a\x00b.md")
	requireRefusal(t, err, ErrRejectedMember, RejectPathChars)
}

func TestZeroLimitsTakeTheStrictDefault(t *testing.T) {
	t.Parallel()

	// A caller that forgets a field must get the strict answer, not an unlimited one.
	require.Equal(t, DefaultLimits(), Limits{}.withDefaults())
	require.Equal(t, DefaultLimits(), Limits{MaxEntries: -1, MaxDuration: -time.Second}.withDefaults())
}

// TestOnlyComponentsWeCreated tests the second, independent layer directly.
//
// The symlink-escape cases above are refused on the member kind, which means they
// prove nothing about the containment invariant — with the member check deleted they
// fail on this instead, which was confirmed by deleting it. These cases exercise the
// invariant with no hostile member involved at all: something is already on disk
// where an extracted path has to go, and the rule is that anything this extraction
// did not itself create is refused rather than reused.
func TestOnlyComponentsWeCreated(t *testing.T) {
	t.Parallel()

	newRoot := func(t *testing.T) (*extractor, string) {
		t.Helper()
		tmp := t.TempDir()
		dest := filepath.Join(tmp, "skill")
		require.NoError(t, os.Mkdir(dest, 0o755))
		root, err := os.OpenRoot(dest)
		require.NoError(t, err)
		t.Cleanup(func() { _ = root.Close() })

		e, cancel := newExtractor(context.Background(), DefaultLimits())
		t.Cleanup(cancel)
		e.root = root
		return e, dest
	}

	t.Run("directory component is a planted symlink", func(t *testing.T) {
		t.Parallel()
		e, dest := newRoot(t)
		outside := filepath.Join(filepath.Dir(dest), "outside")
		require.NoError(t, os.Mkdir(outside, 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(dest, "nested")))

		err := e.ensureDir("nested/deeper")
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestSymlink)

		entries, readErr := os.ReadDir(outside)
		require.NoError(t, readErr)
		require.Empty(t, entries, "created a directory through a planted symlink")
	})

	t.Run("directory component is a planted directory", func(t *testing.T) {
		t.Parallel()
		e, dest := newRoot(t)
		require.NoError(t, os.Mkdir(filepath.Join(dest, "nested"), 0o755))

		// A real directory in the way is refused, not adopted: the destination root
		// was created empty moments ago, so anything inside it arrived from somewhere
		// this extraction cannot account for.
		err := e.ensureDir("nested")
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestExists)
	})

	t.Run("leaf is a planted symlink", func(t *testing.T) {
		t.Parallel()
		e, dest := newRoot(t)
		outside := filepath.Join(filepath.Dir(dest), "canary.txt")
		require.NoError(t, os.WriteFile(outside, []byte("original"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(dest, "SKILL.md")))

		// O_EXCL refuses to follow the link rather than truncating its target.
		err := e.writeFile("SKILL.md", 0o644, strings.NewReader("overwritten"))
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestSymlink)

		body, readErr := os.ReadFile(outside)
		require.NoError(t, readErr)
		require.Equal(t, "original", string(body))
	})

	t.Run("leaf is a planted regular file", func(t *testing.T) {
		t.Parallel()
		e, dest := newRoot(t)
		require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("mine"), 0o600))

		err := e.writeFile("SKILL.md", 0o644, strings.NewReader("overwritten"))
		requireRefusal(t, err, ErrUnsafeDestination, RejectDestExists)

		body, readErr := os.ReadFile(filepath.Join(dest, "SKILL.md"))
		require.NoError(t, readErr)
		require.Equal(t, "mine", string(body), "overwrote a file this extraction did not create")
	})
}
