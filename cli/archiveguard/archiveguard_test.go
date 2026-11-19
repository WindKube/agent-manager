package archiveguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func requireViolation(t *testing.T, err error, kind Kind, rule Rule) *Violation {
	t.Helper()
	require.Error(t, err)
	var v *Violation
	require.ErrorAs(t, err, &v, "not a Violation: %v", err)
	require.Equal(t, kind, v.Kind, "wrong kind: %v", err)
	require.Equal(t, rule, v.Rule, "wrong rule: %v", err)
	return v
}

func TestValidatePathRefusesHostileNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		path string
		kind Kind
		rule Rule
	}{
		{"leading parent traversal", "../evil.txt", KindRejected, RejectTraversal},
		{"parent only", "..", KindRejected, RejectTraversal},
		{"parent directory of the root", "../", KindRejected, RejectTraversal},
		{"traversal that escapes after cleaning", "a/b/../../../evil.txt", KindRejected, RejectTraversal},
		{"absolute path", "/etc/passwd", KindRejected, RejectAbsolutePath},
		{"root", "/", KindRejected, RejectAbsolutePath},
		{"uppercase drive letter", "C:/Windows/system32/x", KindRejected, RejectAbsolutePath},
		{"lowercase drive letter", "c:/x", KindRejected, RejectAbsolutePath},
		// The backslash is caught before the drive letter is looked at.
		{"drive letter with backslash", `C:\Windows\x`, KindRejected, RejectPathChars},
		{"backslash smuggling a traversal", `a\..\..\x`, KindRejected, RejectPathChars},
		{"NUL truncating the path for a C consumer", "a\x00b.txt", KindRejected, RejectPathChars},
		{"empty name", "", KindRejected, RejectEmptyPath},
		{"bare dot", ".", KindRejected, RejectEmptyPath},
		{"too deep", strings.Repeat("d/", DefaultMaxPathDepth) + "x", KindTooLarge, CapPathDepth},
		{"too long", strings.Repeat("a", DefaultMaxPathBytes+1), KindTooLarge, CapPathLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ValidatePath(tc.path, Limits{})
			requireViolation(t, err, tc.kind, tc.rule)
		})
	}
}

func TestValidatePathReportsWhatItRefused(t *testing.T) {
	t.Parallel()

	_, _, err := ValidatePath(strings.Repeat("a", 100), Limits{MaxPathBytes: 80})
	v := requireViolation(t, err, KindTooLarge, CapPathLength)
	require.Equal(t, strings.Repeat("a", 64)+"...", v.Path, "a long path is reported truncated")

	_, _, err = ValidatePath("./a/b/../c/d", Limits{MaxPathDepth: 2})
	v = requireViolation(t, err, KindTooLarge, CapPathDepth)
	require.Equal(t, "a/c/d", v.Path, "depth is reported on the cleaned path")

	_, _, err = ValidatePath("x/../../y", Limits{})
	v = requireViolation(t, err, KindRejected, RejectTraversal)
	require.Equal(t, "x/../../y", v.Path, "a rejection names the member as the archive did")
}

func TestValidatePathAcceptsBenignNames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		path  string
		clean string
		isDir bool
	}{
		{"canonical file", "skills/demo/SKILL.md", "skills/demo/SKILL.md", false},
		{"directory", "skills/", "skills", true},
		{"dot-slash prefix", "./plugin.json", "plugin.json", false},
		{"archive root", "./", ".", true},
		{"internal dot-dot that stays inside", "a/../b.txt", "b.txt", false},
		{"exactly at the depth cap", strings.Repeat("d/", DefaultMaxPathDepth-1) + "x", strings.Repeat("d/", DefaultMaxPathDepth-1) + "x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clean, isDir, err := ValidatePath(tc.path, Limits{})
			require.NoError(t, err)
			require.Equal(t, tc.clean, clean)
			require.Equal(t, tc.isDir, isDir)
		})
	}
}

func TestTarMemberRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		typeflag byte
		rule     Rule
	}{
		{"regular file", tar.TypeReg, ""},
		{"directory", tar.TypeDir, ""},
		{"symlink", tar.TypeSymlink, RejectSymlink},
		{"hardlink", tar.TypeLink, RejectHardlink},
		{"char device", tar.TypeChar, RejectDevice},
		{"block device", tar.TypeBlock, RejectDevice},
		{"fifo", tar.TypeFifo, RejectFIFO},
		{"contiguous file", tar.TypeCont, RejectMemberType},
		{"gnu sparse", tar.TypeGNUSparse, RejectMemberType},
		{"unknown typeflag that reports a regular-file mode", 'z', RejectMemberType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.rule, TarMemberRule(tc.typeflag))
		})
	}
}

func TestZipMemberRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode fs.FileMode
		rule Rule
	}{
		{"regular file", 0o644, ""},
		{"directory", fs.ModeDir | 0o755, ""},
		{"symlink", fs.ModeSymlink | 0o777, RejectSymlink},
		{"device", fs.ModeDevice | 0o644, RejectDevice},
		{"char device", fs.ModeDevice | fs.ModeCharDevice | 0o644, RejectDevice},
		{"fifo", fs.ModeNamedPipe | 0o644, RejectFIFO},
		{"socket", fs.ModeSocket | 0o644, RejectSocket},
		{"irregular", fs.ModeIrregular | 0o644, RejectMemberType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.rule, ZipMemberRule(tc.mode))
		})
	}
}

func TestOnlyLinksAreDroppable(t *testing.T) {
	t.Parallel()

	require.True(t, RejectSymlink.Droppable())
	require.True(t, RejectHardlink.Droppable())
	for _, r := range []Rule{RejectDevice, RejectFIFO, RejectSocket, RejectMemberType, RejectTraversal, RejectAbsolutePath, ""} {
		require.False(t, r.Droppable(), "%q", r)
	}

	err := RejectMember(RejectDevice, "dev/null")
	v := requireViolation(t, err, KindRejected, RejectDevice)
	require.Equal(t, "dev/null", v.Path)
}

func TestGuardChecksEveryChunk(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		limits      Limits
		archiveSize int64
		consume     int64
		firstChunk  int64
		secondChunk int64
		rule        Rule
	}{
		{
			name:        "trips the instant cumulative output passes ratio times input",
			limits:      Limits{MaxDecompressedBytes: 1 << 30, MaxCompressionRatio: 10, RatioGraceBytes: 1},
			consume:     100,
			firstChunk:  1000,
			secondChunk: 1,
			rule:        CapCompressionRatio,
		},
		{
			name:        "clamps the denominator to the archive's real size",
			limits:      Limits{MaxDecompressedBytes: 1 << 30, MaxCompressionRatio: 10, RatioGraceBytes: 1},
			archiveSize: 100,
			consume:     1_000_000,
			firstChunk:  1000,
			secondChunk: 1,
			rule:        CapCompressionRatio,
		},
		{
			name:        "trips on the total decompressed cap when the ratio is generous",
			limits:      Limits{MaxDecompressedBytes: 1000, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20},
			consume:     100,
			firstChunk:  1000,
			secondChunk: 1,
			rule:        CapDecompressedSize,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewGuard(tc.limits)
			g.SetArchiveSize(tc.archiveSize)
			g.Consumed(tc.consume)
			require.NoError(t, g.Produced(tc.firstChunk, tc.firstChunk, "m"))
			requireViolation(t, g.Produced(tc.secondChunk, tc.firstChunk+tc.secondChunk, "m"), KindTooLarge, tc.rule)
		})
	}
}

func TestGuardGraceKeepsTinyArchivesOffTheRatio(t *testing.T) {
	t.Parallel()

	g := NewGuard(Limits{})
	g.Consumed(10)
	require.NoError(t, g.Produced(DefaultRatioGraceBytes, DefaultRatioGraceBytes, "padding"))
	requireViolation(t, g.Produced(1, DefaultRatioGraceBytes+1, "padding"), KindTooLarge, CapCompressionRatio)
}

func TestGuardEntryCaps(t *testing.T) {
	t.Parallel()

	t.Run("single entry size is checked before the chunk counts", func(t *testing.T) {
		t.Parallel()
		g := NewGuard(Limits{MaxEntryBytes: 10, MaxCompressionRatio: 1 << 20, RatioGraceBytes: 1 << 20})
		require.NoError(t, g.Produced(10, 10, "big"))
		v := requireViolation(t, g.Produced(1, 11, "big"), KindTooLarge, CapEntrySize)
		require.Equal(t, "big", v.Path)
		require.Equal(t, int64(10), g.Decompressed())
	})

	t.Run("too many entries", func(t *testing.T) {
		t.Parallel()
		g := NewGuard(Limits{MaxEntries: 3})
		for i := range 3 {
			require.NoError(t, g.CountEntry("f"), "entry %d", i)
		}
		requireViolation(t, g.CountEntry("one-too-many"), KindTooLarge, CapEntryCount)
	})
}

func TestGuardCountsRealInput(t *testing.T) {
	t.Parallel()

	g := NewGuard(Limits{MaxCompressedBytes: 8})
	n, err := io.Copy(io.Discard, g.Reader(strings.NewReader("12345678")))
	require.NoError(t, err)
	require.Equal(t, int64(8), n)
	require.Equal(t, int64(8), g.Compressed())
	require.NoError(t, g.CheckCompressed())

	buf := make([]byte, 4)
	_, err = g.ReaderAt(strings.NewReader("abcdef")).ReadAt(buf, 2)
	require.NoError(t, err)
	require.Equal(t, int64(12), g.Compressed())
	requireViolation(t, g.CheckCompressed(), KindTooLarge, CapCompressedSize)
}

// A real bomb against the default caps: 64 MiB of zeros gzipped to a few
// kilobytes must trip the ratio long before it is fully produced.
func TestGuardStopsAGzipBomb(t *testing.T) {
	t.Parallel()

	var packed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&packed, gzip.BestCompression)
	require.NoError(t, err)
	zeros := make([]byte, 1<<20)
	for range 64 {
		_, err = zw.Write(zeros)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.Less(t, packed.Len(), 1<<20, "the bomb must actually be small to be a bomb")

	g := NewGuard(Limits{})
	zr, err := gzip.NewReader(g.Reader(&packed))
	require.NoError(t, err)

	chunk := make([]byte, 32<<10)
	var got int64
	for {
		n, readErr := zr.Read(chunk)
		got += int64(n)
		if gErr := g.Produced(int64(n), got, "bomb.bin"); gErr != nil {
			requireViolation(t, gErr, KindTooLarge, CapCompressionRatio)
			require.Less(t, got, int64(4<<20), "the cap fired after the bomb landed")
			return
		}
		require.NoError(t, readErr, "the bomb was fully produced without tripping a cap")
	}
}

func TestClock(t *testing.T) {
	t.Parallel()

	t.Run("alive while the budget lasts", func(t *testing.T) {
		t.Parallel()
		c, cancel := StartClock(context.Background(), time.Hour)
		defer cancel()
		require.NoError(t, c.Err())
	})

	t.Run("an expired budget is a timeout violation carrying the budget", func(t *testing.T) {
		t.Parallel()
		c, cancel := StartClock(context.Background(), time.Nanosecond)
		defer cancel()
		require.Eventually(t, func() bool { return c.Err() != nil }, time.Second, time.Millisecond)
		v := requireViolation(t, c.Err(), KindTimeout, ReasonTimeBudget)
		require.Equal(t, time.Nanosecond.String(), v.Detail)
		require.ErrorIs(t, c.Err(), context.DeadlineExceeded)
	})

	for _, tc := range []struct {
		name string
		ctx  func(*testing.T) context.Context
		want error
	}{
		{"caller cancels", func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, context.Canceled},
		{"caller's own deadline expires", func(t *testing.T) context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			t.Cleanup(cancel)
			return ctx
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name+" is passed through, not blamed on the budget", func(t *testing.T) {
			t.Parallel()
			c, cancel := StartClock(tc.ctx(t), time.Hour)
			defer cancel()
			err := c.Err()
			require.ErrorIs(t, err, tc.want)
			var v *Violation
			require.NotErrorAs(t, err, &v)
		})
	}
}

func TestClockReaderStopsATricklingPeer(t *testing.T) {
	t.Parallel()

	stop := errors.New("budget spent")
	reads := 0
	alive := func() error {
		if reads >= 3 {
			return stop
		}
		return nil
	}
	r := ClockReader(readerFunc(func(p []byte) (int, error) {
		reads++
		p[0] = 'x'
		return 1, nil
	}), alive)

	_, err := io.ReadAll(r)
	require.ErrorIs(t, err, stop)
	require.Equal(t, 3, reads)
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestDrainTrailer(t *testing.T) {
	t.Parallel()

	require.NoError(t, DrainTrailer(bytes.NewReader(make([]byte, 10<<10))))
	require.NoError(t, DrainTrailer(bytes.NewReader(make([]byte, MaxTrailerBytes))))
	require.ErrorIs(t, DrainTrailer(bytes.NewReader(make([]byte, MaxTrailerBytes+1))), ErrTrailingData)

	broken := errors.New("checksum mismatch")
	err := DrainTrailer(readerFunc(func([]byte) (int, error) { return 0, broken }))
	require.ErrorIs(t, err, broken)
	require.NotErrorIs(t, err, ErrTrailingData)
}

func TestDefaultLimits(t *testing.T) {
	t.Parallel()

	l := DefaultLimits()
	require.Equal(t, int64(25<<20), l.MaxCompressedBytes)
	require.Equal(t, int64(250<<20), l.MaxDecompressedBytes)
	require.Equal(t, int64(100), l.MaxCompressionRatio)
	require.Equal(t, int64(1<<20), l.RatioGraceBytes)
	require.Equal(t, 10_000, l.MaxEntries)
	require.Equal(t, int64(25<<20), l.MaxEntryBytes)
	require.Equal(t, 32, l.MaxPathDepth)
	require.Equal(t, 1024, l.MaxPathBytes)
	require.Equal(t, 60*time.Second, l.MaxDuration)
}

func TestZeroOrNegativeLimitsTakeTheDefault(t *testing.T) {
	t.Parallel()

	require.Equal(t, DefaultLimits(), Limits{}.WithDefaults())
	require.Equal(t, DefaultLimits(), Limits{MaxEntries: DefaultMaxEntries}.WithDefaults())
	require.Equal(t, DefaultLimits(), Limits{MaxEntries: -1, MaxDuration: -time.Second}.WithDefaults())
	require.Equal(t, 7, Limits{MaxEntries: 7}.WithDefaults().MaxEntries)
}

func TestViolationError(t *testing.T) {
	t.Parallel()

	v := &Violation{Kind: KindTimeout, Rule: ReasonTimeBudget, Detail: "1s", Path: "m", Cause: context.DeadlineExceeded}
	require.Equal(t, `wall clock budget (1s) (member "m"): context deadline exceeded`, v.Error())
	require.ErrorIs(t, v, context.DeadlineExceeded)
}
