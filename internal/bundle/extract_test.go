package bundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type tarMember struct {
	hdr  tar.Header
	body string
}

func makeTarGz(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for i := range members {
		m := &members[i]
		hdr := m.hdr
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(m.body))
		}
		require.NoError(t, tw.WriteHeader(&hdr), "member %q", hdr.Name)
		if m.body != "" {
			_, err := tw.Write([]byte(m.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return out.Bytes()
}

type zipMember struct {
	name string
	mode fs.FileMode
	body string
}

func makeZip(t *testing.T, members ...zipMember) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for i := range members {
		m := &members[i]
		hdr := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.mode != 0 {
			hdr.SetMode(m.mode)
		}
		w, err := zw.CreateHeader(hdr)
		require.NoError(t, err, "member %q", m.name)
		if m.body != "" {
			_, err = w.Write([]byte(m.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, zw.Close())
	return out.Bytes()
}

const bombSize = 16 << 20

// makeZipBomb builds a real bomb rather than committing a binary fixture: one member of
// zeros that deflates about a thousand to one.
func makeZipBomb(t *testing.T, uncompressed int64) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "bomb.bin", Method: zip.Deflate})
	require.NoError(t, err)
	writeZeros(t, w, uncompressed)
	require.NoError(t, zw.Close())
	require.Less(t, int64(out.Len()), DefaultMaxCompressedBytes,
		"the bomb must fit under the upload cap or it proves nothing")
	return out.Bytes()
}

func makeTarGzBomb(t *testing.T, uncompressed int64) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: "bomb.bin", Mode: 0o644, Size: uncompressed,
	}))
	writeZeros(t, tw, uncompressed)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.Less(t, int64(out.Len()), DefaultMaxCompressedBytes)
	return out.Bytes()
}

func writeZeros(t *testing.T, w io.Writer, n int64) {
	t.Helper()
	chunk := make([]byte, 64<<10)
	for n > 0 {
		k := int64(len(chunk))
		if k > n {
			k = n
		}
		written, err := w.Write(chunk[:k])
		require.NoError(t, err)
		n -= int64(written)
	}
}

// makeLyingZip hand-assembles a zip whose central directory and local header both declare
// an uncompressed size of declared while the deflate stream really produces realSize
// bytes. archive/zip's writer cannot produce this, and it is the case the caps must survive:
// declared sizes are attacker-controlled.
func makeLyingZip(t *testing.T, declared uint32, realSize int64) []byte {
	t.Helper()
	var comp bytes.Buffer
	fw, err := flate.NewWriter(&comp, flate.DefaultCompression)
	require.NoError(t, err)
	sum := crc32.NewIEEE()
	writeZeros(t, io.MultiWriter(fw, sum), realSize)
	require.NoError(t, fw.Close())

	name := []byte("liar.bin")
	var out bytes.Buffer
	put16 := func(v uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		out.Write(b[:])
	}
	put32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		out.Write(b[:])
	}

	put32(0x04034b50) // local file header
	put16(20)         // version needed
	put16(0)          // flags
	put16(8)          // method: deflate
	put16(0)          // modified time
	put16(0)          // modified date
	put32(sum.Sum32())
	put32(uint32(comp.Len()))
	put32(declared) // the lie
	put16(uint16(len(name)))
	put16(0) // extra length
	out.Write(name)
	out.Write(comp.Bytes())

	cdOffset := out.Len()
	put32(0x02014b50) // central directory header
	put16(20)         // version made by
	put16(20)         // version needed
	put16(0)          // flags
	put16(8)          // method: deflate
	put16(0)          // modified time
	put16(0)          // modified date
	put32(sum.Sum32())
	put32(uint32(comp.Len()))
	put32(declared) // the same lie
	put16(uint16(len(name)))
	put16(0) // extra length
	put16(0) // comment length
	put16(0) // disk number start
	put16(0) // internal attributes
	put32(0) // external attributes
	put32(0) // local header offset
	out.Write(name)
	cdSize := out.Len() - cdOffset

	put32(0x06054b50) // end of central directory
	put16(0)          // this disk
	put16(0)          // disk with central directory
	put16(1)          // entries on this disk
	put16(1)          // entries total
	put32(uint32(cdSize))
	put32(uint32(cdOffset))
	put16(0) // comment length
	return out.Bytes()
}

// requireKind asserts the exact failure kind and reason, and that the other three kinds do
// not also match: the caller has to be able to report "malformed archive" versus "too
// large" versus "rejected member" without ambiguity.
func requireKind(t *testing.T, err error, kind ErrorKind, reason string) {
	t.Helper()
	require.Error(t, err)
	var be *Error
	require.ErrorAs(t, err, &be)
	require.Equal(t, kind.String(), be.Kind.String(), "wrong kind, error was: %v", err)
	require.Equal(t, reason, be.Reason, "wrong reason, error was: %v", err)
	require.ErrorIs(t, err, kind.sentinel())
	for _, other := range []ErrorKind{KindMalformed, KindTooLarge, KindRejectedMember, KindTimeout} {
		if other != kind {
			require.NotErrorIs(t, err, other.sentinel())
		}
	}
}

func benignTarGz(t *testing.T) []byte {
	t.Helper()
	return makeTarGz(t,
		tarMember{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "skills/", Mode: 0o755}},
		tarMember{hdr: tar.Header{Name: "plugin.json", Mode: 0o644}, body: `{"name":"demo"}`},
		tarMember{hdr: tar.Header{Name: "skills/demo.md", Mode: 0o644}, body: "# demo"},
		tarMember{hdr: tar.Header{Name: "scripts/run.sh", Mode: 0o755}, body: "#!/bin/sh\n"},
	)
}

func benignZip(t *testing.T) []byte {
	t.Helper()
	return makeZip(t,
		zipMember{name: "skills/", mode: fs.ModeDir | 0o755},
		zipMember{name: "plugin.json", mode: 0o644, body: `{"name":"demo"}`},
		zipMember{name: "skills/demo.md", mode: 0o644, body: "# demo"},
		zipMember{name: "scripts/run.sh", mode: 0o755, body: "#!/bin/sh\n"},
	)
}

func TestExtractBenignArchive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		archive func(*testing.T) []byte
	}{
		{"tar.gz extracts every file and drops the directory member", benignTarGz},
		{"zip extracts every file and drops the directory member", benignZip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Extract(context.Background(), bytes.NewReader(tc.archive(t)), Limits{})
			require.NoError(t, err)
			require.Equal(t, []string{"plugin.json", "scripts/run.sh", "skills/demo.md"}, b.Paths())

			manifest, ok := b.Lookup("plugin.json")
			require.True(t, ok)
			require.Equal(t, `{"name":"demo"}`, string(manifest.Data))
			require.Equal(t, FileMode, manifest.Mode)

			script, ok := b.Lookup("scripts/run.sh")
			require.True(t, ok)
			require.Equal(t, ExecMode, script.Mode)
			require.Equal(t, int64(len(`{"name":"demo"}`)+len("# demo")+len("#!/bin/sh\n")), b.TotalBytes())
		})
	}
}

func TestExtractNormalisesDotSlashPrefix(t *testing.T) {
	archive := makeTarGz(t,
		tarMember{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "./"}},
		tarMember{hdr: tar.Header{Name: "./plugin.json", Mode: 0o644}, body: "{}"},
	)
	b, err := Extract(context.Background(), bytes.NewReader(archive), Limits{})
	require.NoError(t, err)
	require.Equal(t, []string{"plugin.json"}, b.Paths())
}

func TestExtractRejectsTarMembers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members []tarMember
		reason  string
	}{
		{
			name:    "symlink escaping the tree",
			members: []tarMember{{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "escape", Linkname: "../../etc/passwd"}}},
			reason:  RejectSymlink,
		},
		{
			name:    "symlink pointing inside the tree is refused all the same",
			members: []tarMember{{hdr: tar.Header{Name: "a.txt", Mode: 0o644}, body: "a"}, {hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "a.txt"}}},
			reason:  RejectSymlink,
		},
		{
			name:    "hardlink",
			members: []tarMember{{hdr: tar.Header{Name: "a.txt", Mode: 0o644}, body: "a"}, {hdr: tar.Header{Typeflag: tar.TypeLink, Name: "hard", Linkname: "a.txt"}}},
			reason:  RejectHardlink,
		},
		{
			name:    "character device",
			members: []tarMember{{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Devmajor: 1, Devminor: 3}}},
			reason:  RejectDevice,
		},
		{
			name:    "block device",
			members: []tarMember{{hdr: tar.Header{Typeflag: tar.TypeBlock, Name: "dev/sda", Devmajor: 8}}},
			reason:  RejectDevice,
		},
		{
			name:    "fifo",
			members: []tarMember{{hdr: tar.Header{Typeflag: tar.TypeFifo, Name: "pipe"}}},
			reason:  RejectFIFO,
		},
		{
			name:    "absolute path",
			members: []tarMember{{hdr: tar.Header{Name: "/etc/passwd", Mode: 0o644}, body: "root"}},
			reason:  RejectAbsolutePath,
		},
		{
			name:    "windows drive letter",
			members: []tarMember{{hdr: tar.Header{Name: "C:/evil.txt", Mode: 0o644}, body: "x"}},
			reason:  RejectAbsolutePath,
		},
		{
			name:    "leading parent traversal",
			members: []tarMember{{hdr: tar.Header{Name: "../evil.txt", Mode: 0o644}, body: "x"}},
			reason:  RejectTraversal,
		},
		{
			name:    "traversal that escapes after cleaning",
			members: []tarMember{{hdr: tar.Header{Name: "a/../../evil.txt", Mode: 0o644}, body: "x"}},
			reason:  RejectTraversal,
		},
		{
			name:    "backslash separator smuggling a traversal",
			members: []tarMember{{hdr: tar.Header{Name: `a\..\..\evil.txt`, Mode: 0o644}, body: "x"}},
			reason:  RejectPathChars,
		},
		{
			name:    "two members at the same path",
			members: []tarMember{{hdr: tar.Header{Name: "a.txt", Mode: 0o644}, body: "first"}, {hdr: tar.Header{Name: "a.txt", Mode: 0o644}, body: "second"}},
			reason:  RejectDuplicate,
		},
		{
			name:    "a directory colliding with a file",
			members: []tarMember{{hdr: tar.Header{Name: "a.txt", Mode: 0o644}, body: "first"}, {hdr: tar.Header{Typeflag: tar.TypeDir, Name: "a.txt/"}}},
			reason:  RejectDuplicate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Extract(context.Background(), bytes.NewReader(makeTarGz(t, tc.members...)), Limits{})
			requireKind(t, err, KindRejectedMember, tc.reason)
		})
	}
}

func TestExtractRejectsZipMembers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		members []zipMember
		reason  string
	}{
		{
			name:    "symlink escaping the tree",
			members: []zipMember{{name: "escape", mode: fs.ModeSymlink | 0o777, body: "../../etc/passwd"}},
			reason:  RejectSymlink,
		},
		{
			name:    "fifo",
			members: []zipMember{{name: "pipe", mode: fs.ModeNamedPipe | 0o644}},
			reason:  RejectFIFO,
		},
		{
			name:    "character device",
			members: []zipMember{{name: "dev/null", mode: fs.ModeDevice | fs.ModeCharDevice | 0o644}},
			reason:  RejectDevice,
		},
		{
			name:    "absolute path",
			members: []zipMember{{name: "/etc/passwd", mode: 0o644, body: "root"}},
			reason:  RejectAbsolutePath,
		},
		{
			name:    "leading parent traversal",
			members: []zipMember{{name: "../evil.txt", mode: 0o644, body: "x"}},
			reason:  RejectTraversal,
		},
		{
			name:    "two members at the same path",
			members: []zipMember{{name: "a.txt", mode: 0o644, body: "first"}, {name: "a.txt", mode: 0o644, body: "second"}},
			reason:  RejectDuplicate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Extract(context.Background(), bytes.NewReader(makeZip(t, tc.members...)), Limits{})
			requireKind(t, err, KindRejectedMember, tc.reason)
		})
	}
}

func TestExtractEnforcesCaps(t *testing.T) {
	deep := "a/b/c/d/e.txt"
	long := strings.Repeat("x", 40) + ".txt"

	for _, tc := range []struct {
		name    string
		limits  Limits
		archive func(*testing.T) []byte
		capName string
	}{
		{
			name:    "compressed upload size, rejected before extraction begins",
			limits:  Limits{MaxCompressedBytes: 64},
			archive: benignTarGz,
			capName: CapCompressedSize,
		},
		{
			name:    "total decompressed size",
			limits:  Limits{MaxDecompressedBytes: 8, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			archive: benignTarGz,
			capName: CapDecompressedSize,
		},
		{
			name:    "single entry size",
			limits:  Limits{MaxEntryBytes: 4, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			archive: benignTarGz,
			capName: CapEntrySize,
		},
		{
			name:    "entry count",
			limits:  Limits{MaxEntries: 2},
			archive: benignTarGz,
			capName: CapEntryCount,
		},
		{
			name:   "path depth",
			limits: Limits{MaxPathDepth: 4},
			archive: func(t *testing.T) []byte {
				return makeTarGz(t, tarMember{hdr: tar.Header{Name: deep, Mode: 0o644}, body: "x"})
			},
			capName: CapPathDepth,
		},
		{
			name:   "path length",
			limits: Limits{MaxPathBytes: 32},
			archive: func(t *testing.T) []byte {
				return makeTarGz(t, tarMember{hdr: tar.Header{Name: long, Mode: 0o644}, body: "x"})
			},
			capName: CapPathLength,
		},
		{
			name:   "path depth in a zip is caught from the central directory",
			limits: Limits{MaxPathDepth: 4},
			archive: func(t *testing.T) []byte {
				return makeZip(t, zipMember{name: deep, mode: 0o644, body: "x"})
			},
			capName: CapPathDepth,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Extract(context.Background(), bytes.NewReader(tc.archive(t)), tc.limits)
			requireKind(t, err, KindTooLarge, tc.capName)
		})
	}
}

func TestExtractStopsZipBomb(t *testing.T) {
	archive := makeZipBomb(t, bombSize)
	_, err := Extract(context.Background(), bytes.NewReader(archive), Limits{})
	requireKind(t, err, KindTooLarge, CapCompressionRatio)
}

func TestExtractStopsTarGzBomb(t *testing.T) {
	archive := makeTarGzBomb(t, bombSize)
	_, err := Extract(context.Background(), bytes.NewReader(archive), Limits{})
	requireKind(t, err, KindTooLarge, CapCompressionRatio)
}

func TestExtractStopsBombBeforeTheDecompressedCap(t *testing.T) {
	// The ratio has to be what stops the bomb: with the total cap raised far above the
	// bomb's payload, only a continuous ratio check can catch it.
	archive := makeZipBomb(t, bombSize)
	_, err := Extract(context.Background(), bytes.NewReader(archive), Limits{
		MaxDecompressedBytes: 1 << 30,
		RatioGraceBytes:      1,
	})
	requireKind(t, err, KindTooLarge, CapCompressionRatio)
}

func TestExtractRejectsZipWithLyingDeclaredSize(t *testing.T) {
	// The central directory and local header both claim one byte while the deflate stream
	// really produces 40 MB. The archive must be refused, and must never hand back the
	// payload.
	archive := makeLyingZip(t, 1, bombSize)
	b, err := Extract(context.Background(), bytes.NewReader(archive), Limits{})
	require.Nil(t, b)
	require.Error(t, err)
	var be *Error
	require.ErrorAs(t, err, &be)
	require.Equal(t, KindMalformed, be.Kind, "error was: %v", err)
}

func TestReadMemberEnforcesCapsAgainstRealBytes(t *testing.T) {
	// Declared sizes are attacker-controlled, so they may only pre-size a buffer. Every
	// cap is measured against bytes the reader actually produced.
	for _, tc := range []struct {
		name    string
		real    int64
		limits  Limits
		capName string
	}{
		{
			name:    "a one-byte declaration does not buy 1 MiB past the per-entry cap",
			real:    1 << 20,
			limits:  Limits{MaxEntryBytes: 1024, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			capName: CapEntrySize,
		},
		{
			name:    "nor past the total decompressed cap",
			real:    1 << 20,
			limits:  Limits{MaxDecompressedBytes: 4096, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			capName: CapDecompressedSize,
		},
		{
			name:    "nor past the compression ratio",
			real:    1 << 20,
			limits:  Limits{MaxCompressionRatio: 10, RatioGraceBytes: 1},
			capName: CapCompressionRatio,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, cancel := newExtractor(context.Background(), tc.limits)
			defer cancel()
			e.guard.consumed(1024)
			_, err := e.readMember(io.LimitReader(zeroReader{}, tc.real), "liar.bin")
			requireKind(t, err, KindTooLarge, tc.capName)
		})
	}

	t.Run("what comes back is exactly what the reader produced", func(t *testing.T) {
		e, cancel := newExtractor(context.Background(), Limits{})
		defer cancel()
		got, err := e.readMember(io.LimitReader(zeroReader{}, 10), "liar.bin")
		require.NoError(t, err)
		require.Len(t, got, 10)
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestRatioGuardChecksEveryChunk(t *testing.T) {
	for _, tc := range []struct {
		name        string
		guard       ratioGuard
		consume     int64
		firstChunk  int64
		secondChunk int64
		capName     string
	}{
		{
			name:        "trips the instant cumulative output passes ratio times input",
			guard:       ratioGuard{limits: Limits{MaxDecompressedBytes: 1 << 30, MaxCompressionRatio: 10, RatioGraceBytes: 0}},
			consume:     100,
			firstChunk:  1000,
			secondChunk: 1,
			capName:     CapCompressionRatio,
		},
		{
			name:        "clamps the denominator to the archive's real size",
			guard:       ratioGuard{limits: Limits{MaxDecompressedBytes: 1 << 30, MaxCompressionRatio: 10, RatioGraceBytes: 0}, archiveSize: 100},
			consume:     1_000_000,
			firstChunk:  1000,
			secondChunk: 1,
			capName:     CapCompressionRatio,
		},
		{
			name:        "trips on the total decompressed cap when the ratio is generous",
			guard:       ratioGuard{limits: Limits{MaxDecompressedBytes: 1000, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20}},
			consume:     100,
			firstChunk:  1000,
			secondChunk: 1,
			capName:     CapDecompressedSize,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.guard
			g.consumed(tc.consume)
			require.NoError(t, g.produced(tc.firstChunk, "m"))
			requireKind(t, g.produced(tc.secondChunk, "m"), KindTooLarge, tc.capName)
		})
	}
}

func TestExtractHonoursWallClock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		archive func(*testing.T) []byte
	}{
		{"tar.gz", benignTarGz},
		{"zip", benignZip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Extract(context.Background(), bytes.NewReader(tc.archive(t)), Limits{MaxDuration: time.Nanosecond})
			requireKind(t, err, KindTimeout, time.Nanosecond.String())
		})
	}
}

func TestExtractMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input func(*testing.T) []byte
	}{
		{"not an archive at all", func(*testing.T) []byte {
			return []byte("this is just text, repeated enough to look like something")
		}},
		{"gzip header only", func(*testing.T) []byte {
			return []byte{0x1f, 0x8b, 0x08, 0x00}
		}},
		{"zip magic with no directory", func(*testing.T) []byte {
			return []byte("PK\x03\x04nonsense")
		}},
		{"truncated tar inside a valid gzip", func(t *testing.T) []byte {
			full := benignTarGz(t)
			return full[:len(full)-8]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Extract(context.Background(), bytes.NewReader(tc.input(t)), Limits{})
			require.Error(t, err)
			var be *Error
			require.ErrorAs(t, err, &be)
			require.Equal(t, KindMalformed, be.Kind, "error was: %v", err)
			require.ErrorIs(t, err, ErrMalformed)
			require.NotErrorIs(t, err, ErrTooLarge)
			require.NotErrorIs(t, err, ErrRejectedMember)
		})
	}
}

func TestExtractEmptyInput(t *testing.T) {
	_, err := Extract(context.Background(), bytes.NewReader(nil), Limits{})
	requireKind(t, err, KindMalformed, "empty archive")
}

func TestExtractTarGzOversizeReportsTooLargeNotMalformed(t *testing.T) {
	// Truncating an oversize stream makes it look malformed; "too large" is the honest
	// reason and the one the caller has to surface.
	_, err := ExtractTarGz(context.Background(), bytes.NewReader(benignTarGz(t)), Limits{MaxCompressedBytes: 40})
	requireKind(t, err, KindTooLarge, CapCompressedSize)
}

func TestValidatePathRules(t *testing.T) {
	e := &extractor{limits: DefaultLimits()}
	for _, tc := range []struct {
		name   string
		path   string
		reason string
	}{
		{"NUL byte truncating the path for a C consumer", "a\x00b.txt", RejectPathChars},
		{"backslash", `a\b.txt`, RejectPathChars},
		{"empty name", "", RejectEmptyPath},
		{"bare dot", ".", RejectEmptyPath},
		{"root", "/", RejectAbsolutePath},
		{"parent only", "..", RejectTraversal},
		{"parent directory of the root", "../", RejectTraversal},
		{"lowercase drive letter", "c:/x", RejectAbsolutePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := e.validatePath(tc.path)
			requireKind(t, err, KindRejectedMember, tc.reason)
		})
	}

	t.Run("a canonical relative path is accepted unchanged", func(t *testing.T) {
		clean, isDir, err := e.validatePath("skills/demo/SKILL.md")
		require.NoError(t, err)
		require.False(t, isDir)
		require.Equal(t, "skills/demo/SKILL.md", clean)
	})
}

func TestMemberKindMapping(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typeflag byte
		reason   string
	}{
		{"regular file", tar.TypeReg, ""},
		{"directory", tar.TypeDir, ""},
		{"symlink", tar.TypeSymlink, RejectSymlink},
		{"hardlink", tar.TypeLink, RejectHardlink},
		{"char device", tar.TypeChar, RejectDevice},
		{"block device", tar.TypeBlock, RejectDevice},
		{"fifo", tar.TypeFifo, RejectFIFO},
		{"anything else", tar.TypeCont, RejectMemberType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.reason, tarMemberReason(tc.typeflag))
		})
	}

	for _, tc := range []struct {
		name   string
		mode   fs.FileMode
		reason string
	}{
		{"regular file", 0o644, ""},
		{"directory", fs.ModeDir | 0o755, ""},
		{"symlink", fs.ModeSymlink | 0o777, RejectSymlink},
		{"device", fs.ModeDevice | 0o644, RejectDevice},
		{"fifo", fs.ModeNamedPipe | 0o644, RejectFIFO},
		{"socket", fs.ModeSocket | 0o644, RejectSocket},
		{"irregular", fs.ModeIrregular | 0o644, RejectMemberType},
	} {
		t.Run("zip "+tc.name, func(t *testing.T) {
			require.Equal(t, tc.reason, zipMemberReason(tc.mode))
		})
	}
}

func TestDefaultLimitsMatchResearchR3(t *testing.T) {
	l := DefaultLimits()
	require.Equal(t, int64(25<<20), l.MaxCompressedBytes)
	require.Equal(t, int64(250<<20), l.MaxDecompressedBytes)
	require.Equal(t, int64(100), l.MaxCompressionRatio)
	require.Equal(t, 10_000, l.MaxEntries)
	require.Equal(t, int64(25<<20), l.MaxEntryBytes)
	require.Equal(t, 32, l.MaxPathDepth)
	require.Equal(t, 1024, l.MaxPathBytes)
	require.Equal(t, 60*time.Second, l.MaxDuration)
}

func TestZeroLimitsFallBackToDefaults(t *testing.T) {
	require.Equal(t, DefaultLimits(), Limits{}.withDefaults())
	require.Equal(t, DefaultLimits(), Limits{MaxEntries: DefaultMaxEntries}.withDefaults())
}

func TestExtractPassesCallerContextFailureThrough(t *testing.T) {
	// A shutdown or a request timeout is not an archive defect, so neither may surface as
	// one of the four archive failure kinds — and a caller's deadline must never be
	// reported as the extraction's own wall-clock cap, which would blame the upload for a
	// budget that never expired.
	for _, tc := range []struct {
		name string
		ctx  func(*testing.T) context.Context
		want error
	}{
		{
			name: "caller cancels",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			want: context.Canceled,
		},
		{
			name: "caller's own deadline expires",
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A generous MaxDuration, so anything reported as a timeout is a misattribution.
			_, err := Extract(tc.ctx(t), bytes.NewReader(benignTarGz(t)), Limits{MaxDuration: time.Hour})
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, ErrTimeout)
			require.NotErrorIs(t, err, ErrMalformed)
			require.NotErrorIs(t, err, ErrTooLarge)
			require.NotErrorIs(t, err, ErrRejectedMember)

			var be *Error
			require.NotErrorAs(t, err, &be, "a caller-side failure must not be an archive Error")
		})
	}
}

// trickleReader feeds one byte per call after a delay: a peer that is slow rather than
// large, which no size cap can bound.
type trickleReader struct {
	data  []byte
	pos   int
	delay time.Duration
}

func (t *trickleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if t.pos >= len(t.data) {
		return 0, io.EOF
	}
	time.Sleep(t.delay)
	p[0] = t.data[t.pos]
	t.pos++
	return 1, nil
}

func TestExtractWallClockBoundsASlowPeer(t *testing.T) {
	// Buffering the upload is part of the extraction. Without the clock on the read, a
	// peer that trickles bytes holds a goroutine and the whole compressed buffer for as
	// long as it likes and the archive still extracts successfully, however small
	// MaxDuration is.
	archive := benignTarGz(t)
	const budget = 30 * time.Millisecond
	slow := &trickleReader{data: archive, delay: time.Millisecond}

	_, err := Extract(context.Background(), slow, Limits{MaxDuration: budget})
	requireKind(t, err, KindTimeout, budget.String())

	// The deadline was comfortably in the future at entry and expired while bytes were
	// still arriving, so this is the continuous check and not the one at the door.
	require.Positive(t, slow.pos, "the deadline tripped before a single byte was read")
	require.Less(t, slow.pos, len(archive), "the whole archive was read despite the deadline")
}

// rawTarHeader builds one ustar header block by hand, so PAX extended headers that
// archive/tar's writer refuses to emit are still reachable from a test.
func rawTarHeader(name string, typeflag byte, size int64) []byte {
	blk := make([]byte, 512)
	copy(blk[0:100], name)
	copy(blk[100:108], "0000644\x00")
	copy(blk[124:136], fmt.Sprintf("%011o\x00", size))
	copy(blk[136:148], fmt.Sprintf("%011o\x00", 0))
	copy(blk[148:156], "        ")
	blk[156] = typeflag
	copy(blk[257:263], "ustar\x00")
	copy(blk[263:265], "00")
	var sum int
	for _, c := range blk {
		sum += int(c)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

func paxRecords(t *testing.T, recs map[string]string) []byte {
	t.Helper()
	keys := make([]string, 0, len(recs))
	for k := range recs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, k := range keys {
		body := k + "=" + recs[k] + "\n"
		for n := len(body) + 3; ; {
			record := fmt.Sprintf("%d %s", n, body)
			if len(record) == n {
				out.WriteString(record)
				break
			}
			n = len(record)
		}
	}
	return out.Bytes()
}

func padTarBlock(b []byte) []byte {
	for len(b)%512 != 0 {
		b = append(b, 0)
	}
	return b
}

// sparseTarGz hand-builds a GNU sparse 0.1 member. The hole map lives entirely in PAX
// records, so the member's body is one byte while archive/tar hands back logical bytes of
// zeros for it — an expansion that consumes no input at all and that no declared-size
// check would see.
func sparseTarGz(t *testing.T, logical int64) []byte {
	t.Helper()
	recs := paxRecords(t, map[string]string{
		"GNU.sparse.major":     "0",
		"GNU.sparse.minor":     "1",
		"GNU.sparse.name":      "sparse.bin",
		"GNU.sparse.numblocks": "1",
		"GNU.sparse.map":       fmt.Sprintf("%d,1", logical-1),
		"GNU.sparse.size":      fmt.Sprint(logical),
		"size":                 "1",
	})

	var content bytes.Buffer
	content.Write(rawTarHeader("PaxHeaders/sparse.bin", tar.TypeXHeader, int64(len(recs))))
	content.Write(padTarBlock(recs))
	content.Write(rawTarHeader("GNUSparseFile.0/sparse.bin", tar.TypeReg, 1))
	content.Write(padTarBlock([]byte{'X'}))
	content.Write(make([]byte, 1024)) // end-of-archive marker

	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	_, err := gz.Write(content.Bytes())
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return out.Bytes()
}

func TestExtractStopsSparseTarMember(t *testing.T) {
	// A sparse member manufactures bytes out of nothing: the ratio guard is the only cap
	// that can see it, because the archive consumes no input while producing the holes.
	const logical = 200 << 20
	archive := sparseTarGz(t, logical)
	require.Less(t, len(archive), 1024, "the point of this case is a tiny archive with a huge logical member")

	_, err := Extract(context.Background(), bytes.NewReader(archive), Limits{})
	requireKind(t, err, KindTooLarge, CapCompressionRatio)
}

func TestExtractSparseTarMemberIsNotRefusedVacuously(t *testing.T) {
	// The rejection above must come from the size, not from the sparse encoding itself.
	const logical = 4096
	_, err := Extract(context.Background(), bytes.NewReader(sparseTarGz(t, logical)), Limits{})
	require.NoError(t, err)
}
