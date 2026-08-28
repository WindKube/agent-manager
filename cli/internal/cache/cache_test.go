package cache

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The NIST vector for sha256("abc"), and the SAME value in the two other
// encodings this package has to speak. Hand-derived from the published vector
// and an independent base64 implementation, never from a run of this code: a
// constant copied out of a failing test's "got" is the bug written down as the
// expectation.
const (
	abcHex       = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	abcBase64    = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
	abcBase64Raw = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
	abcBase64URL = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0="
)

func mustParseLockfile(t *testing.T, s string) Digest {
	t.Helper()
	d, err := ParseLockfileDigest(s)
	require.NoError(t, err)
	return d
}

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	return New(Dir(t.TempDir()))
}

// --- digest: one canonical form, converted only at the edges -----------------

func TestDigestTheTwoWireEncodingsDecodeToTheSameValue(t *testing.T) {
	t.Parallel()

	fromLockfile := mustParseLockfile(t, "sha256:"+abcHex)
	fromHeader, err := ParseHeaderDigest("sha-256=" + abcBase64)
	require.NoError(t, err)

	// This is the comparison FR-014 rests on. If Digest held a string, these
	// two spellings of one value would be unequal and every verification would
	// silently fail closed in a way no test of the happy path could see.
	require.Equal(t, fromLockfile, fromHeader)
	require.Equal(t, Compute([]byte("abc")), fromLockfile)
}

func TestDigestFormattersRoundTrip(t *testing.T) {
	t.Parallel()

	d := Compute([]byte("abc"))
	require.Equal(t, abcHex, d.Hex())
	require.Equal(t, "sha256:"+abcHex, d.Lockfile())
	require.Equal(t, "sha256:"+abcHex, d.String())
	require.Equal(t, "sha-256="+abcBase64, d.Header())
	require.Equal(t, "sha256-"+abcHex, d.FileName())

	back := mustParseLockfile(t, d.Lockfile())
	require.Equal(t, d, back)
	backHeader, err := ParseHeaderDigest(d.Header())
	require.NoError(t, err)
	require.Equal(t, d, backHeader)
}

func TestDigestUnpaddedHeaderBase64Accepted(t *testing.T) {
	t.Parallel()

	d, err := ParseHeaderDigest("sha-256=" + abcBase64Raw)
	require.NoError(t, err)
	require.Equal(t, Compute([]byte("abc")), d)
}

func TestDigestHeaderAlgorithmTokenIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	d, err := ParseHeaderDigest("SHA-256=" + abcBase64)
	require.NoError(t, err)
	require.Equal(t, Compute([]byte("abc")), d)
}

func TestParseLockfileDigestRefusesMalformed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty string":                  "",
		"no scheme":                     abcHex,
		"header scheme instead":         "sha-256=" + abcBase64,
		"wrong algorithm":               "sha512:" + abcHex,
		"one hex character short":       "sha256:" + abcHex[:63],
		"one hex character long":        "sha256:" + abcHex + "a",
		"uppercase hex is not folded":   "sha256:" + strings.ToUpper(abcHex),
		"non hex of the right length":   "sha256:" + strings.Repeat("g", 64),
		"scheme only":                   "sha256:",
		"leading space":                 " sha256:" + abcHex,
		"trailing newline":              "sha256:" + abcHex + "\n",
		"file scheme is not a lockfile": "sha256-" + abcHex,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseLockfileDigest(in)
			require.ErrorIs(t, err, ErrDigest)
			require.True(t, got.IsZero())
		})
	}
}

func TestParseHeaderDigestRefusesMalformed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty string":                "",
		"no scheme":                   abcBase64,
		"lockfile scheme instead":     "sha256:" + abcHex,
		"lockfile spelling of sha256": "sha256=" + abcBase64,
		"wrong algorithm":             "sha-512=" + abcBase64,
		"scheme only":                 "sha-256=",
		"base64url alphabet":          "sha-256=" + abcBase64URL,
		"not base64 at all":           "sha-256=!!!!",
		"decodes to too few bytes":    "sha-256=YWJj",
		"decodes to too many bytes":   "sha-256=" + abcBase64Raw + abcBase64,
		"hex payload":                 "sha-256=" + abcHex,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHeaderDigest(in)
			require.ErrorIs(t, err, ErrDigest)
			require.True(t, got.IsZero())
		})
	}
}

func TestParseHeaderDigestBase64urlIsRefusedRatherThanMisdecoded(t *testing.T) {
	t.Parallel()

	// The specific reason matters: a tolerant decoder would accept this and
	// return SOME digest that is not sha256("abc"), which is a wrong answer
	// rather than an error.
	_, err := ParseHeaderDigest("sha-256=" + abcBase64URL)
	require.ErrorIs(t, err, ErrDigest)
	require.Contains(t, err.Error(), "base64url")
}

func TestDigestZeroValueIsNotTheDigestOfAnything(t *testing.T) {
	t.Parallel()

	var zero Digest
	require.True(t, zero.IsZero())
	require.False(t, Compute(nil).IsZero(), "sha256 of the empty input is a real digest")
	require.NotEqual(t, zero, Compute(nil))
}

// --- cache: hit, miss, discard ----------------------------------------------

func TestCacheHitReturnsTheBytesItHashed(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)

	require.NoError(t, c.Put(d, payload))

	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, c.Verify(d))
}

func TestCacheMissOnAnEmptyStore(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	d := Compute([]byte("never fetched"))

	_, err := c.Get(d)
	require.ErrorIs(t, err, ErrMiss)
	require.NotErrorIs(t, err, ErrCorrupt, "an absent entry was never corrupt")
	require.ErrorIs(t, c.Verify(d), ErrMiss)

	// New() creates nothing: a machine that has never synced must not grow
	// directories from a read.
	_, statErr := os.Stat(c.Root())
	require.ErrorIs(t, statErr, fs.ErrNotExist)
}

func TestCacheCorruptEntryIsDiscardedNotRepaired(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)
	require.NoError(t, c.Put(d, payload))

	entry := filepath.Join(c.Root(), d.FileName())
	require.NoError(t, os.WriteFile(entry, []byte("bundle bytez"), 0o600))

	_, err := c.Get(d)
	require.ErrorIs(t, err, ErrCorrupt)
	require.ErrorIs(t, err, ErrMiss)
	require.Contains(t, err.Error(), d.Lockfile(), "the error names the digest asked for")
	require.Contains(t, err.Error(), Compute([]byte("bundle bytez")).Lockfile(),
		"and the digest actually found")

	// Discarded, not repaired, not left in place to fail again.
	_, statErr := os.Stat(entry)
	require.ErrorIs(t, statErr, fs.ErrNotExist)

	// And the second read is a plain miss, because there is nothing left.
	_, err = c.Get(d)
	require.ErrorIs(t, err, ErrMiss)
	require.NotErrorIs(t, err, ErrCorrupt)
}

func TestCacheTruncatedEntryUnderTheFinalNameIsDiscarded(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("x"), 4096)
	d := Compute(payload)
	require.NoError(t, os.MkdirAll(c.Root(), 0o700))

	// The exact failure temp-file-and-rename exists to make impossible: a short
	// file under the final name. It looks whole to anything but the re-hash.
	require.NoError(t, os.WriteFile(filepath.Join(c.Root(), d.FileName()), payload[:100], 0o600))

	_, err := c.Get(d)
	require.ErrorIs(t, err, ErrCorrupt)
	require.ErrorIs(t, err, ErrMiss)
}

func TestCacheOversizeEntryIsDiscardedRatherThanTruncated(t *testing.T) {
	t.Parallel()

	c := NewWithLimit(Dir(t.TempDir()), 64)
	payload := bytes.Repeat([]byte("y"), 200)
	d := Compute(payload)
	require.NoError(t, os.MkdirAll(c.Root(), 0o700))
	entry := filepath.Join(c.Root(), d.FileName())
	require.NoError(t, os.WriteFile(entry, payload, 0o600))

	_, err := c.Get(d)
	require.ErrorIs(t, err, ErrCorrupt)
	require.ErrorIs(t, err, ErrMiss)
	require.Contains(t, err.Error(), "larger than", "the cap, not the hash, is named as the reason")
	_, statErr := os.Stat(entry)
	require.ErrorIs(t, statErr, fs.ErrNotExist)
}

func TestCacheNonRegularEntryIsDiscardedRatherThanPoisoningTheDigestForever(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)
	require.NoError(t, os.MkdirAll(c.Root(), 0o700))
	entry := filepath.Join(c.Root(), d.FileName())
	require.NoError(t, os.MkdirAll(filepath.Join(entry, "squatter"), 0o700))

	_, err := c.Get(d)
	require.ErrorIs(t, err, ErrCorrupt)
	require.ErrorIs(t, err, ErrMiss)

	_, statErr := os.Stat(entry)
	require.ErrorIs(t, statErr, fs.ErrNotExist)

	// Self-healing: the digest is usable again after one write.
	require.NoError(t, c.Put(d, payload))
	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestCachePutRefusesBytesThatDoNotHashToTheKey(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	claimed := Compute([]byte("what the lockfile said"))

	err := c.Put(claimed, []byte("what the hub sent"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to cache")

	err = c.PutReader(claimed, bytes.NewReader([]byte("what the hub sent")))
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to cache")

	// Nothing was filed, not even under the digest of the bytes supplied.
	_, err = c.Get(claimed)
	require.ErrorIs(t, err, ErrMiss)
	_, err = c.Get(Compute([]byte("what the hub sent")))
	require.ErrorIs(t, err, ErrMiss)
	requireNoTemps(t, c)
}

func TestCachePutReaderRefusesOversize(t *testing.T) {
	t.Parallel()

	c := NewWithLimit(Dir(t.TempDir()), 64)
	payload := bytes.Repeat([]byte("z"), 65)
	d := Compute(payload)

	err := c.PutReader(d, bytes.NewReader(payload))
	require.ErrorIs(t, err, ErrTooLarge)
	_, err = c.Get(d)
	require.ErrorIs(t, err, ErrMiss)
	requireNoTemps(t, c)
}

func TestCacheZeroDigestIsRefusedOnBothPaths(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	var zero Digest

	_, err := c.Get(zero)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrMiss, "the zero digest is a programming error, not a cache miss")
	require.ErrorContains(t, err, "zero digest")

	err = c.PutReader(zero, bytes.NewReader(nil))
	require.ErrorContains(t, err, "zero digest")
}

// --- the killed write --------------------------------------------------------

// A process killed mid-download cannot run a deferred cleanup, so the partial
// bytes stay on disk. This asserts the property that matters: they are not
// visible as an entry, and they do not become one later.
func TestKilledWriteLeavesAPartialTempAndNoVisibleEntry(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("bundle"), 1000)
	d := Compute(payload)
	require.NoError(t, os.MkdirAll(c.Root(), 0o700))

	// Written by hand with exactly the name PutReader would have chosen, because
	// there is no way to kill a goroutine mid-Copy and leave the file behind: a
	// deferred remove would run. This is the on-disk state after a SIGKILL.
	partial := filepath.Join(c.Root(), tempPrefix+d.FileName()+"-2735683")
	require.NoError(t, os.WriteFile(partial, payload[:len(payload)/3], 0o600))

	// It really is there, so the assertions below are about a populated
	// directory rather than an empty one.
	info, err := os.Stat(partial)
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)/3), info.Size())

	_, err = c.Get(d)
	require.ErrorIs(t, err, ErrMiss)
	require.NotErrorIs(t, err, ErrCorrupt, "a temp file is invisible, not corrupt")
	require.ErrorIs(t, c.Verify(d), ErrMiss)

	// Nothing under the final name, and nothing promoted the temp.
	_, err = os.Stat(filepath.Join(c.Root(), d.FileName()))
	require.ErrorIs(t, err, fs.ErrNotExist)

	// The re-download converges, and the partial is collected on that write path
	// once it is old enough to be certainly dead.
	require.NoError(t, c.Put(d, payload))
	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	removed, err := c.CollectTempsOlderThan(0)
	require.NoError(t, err)
	require.Equal(t, 1, removed)
	requireNoTemps(t, c)

	// Collection took the temp and left the entry.
	got, err = c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestFailedWriteRemovesItsOwnTempAndLeavesNoEntry(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("bundle"), 1000)
	d := Compute(payload)

	wantErr := errors.New("connection reset by peer")
	r := io.MultiReader(bytes.NewReader(payload[:500]), errReader{wantErr})

	err := c.PutReader(d, r)
	require.ErrorIs(t, err, wantErr)

	_, err = c.Get(d)
	require.ErrorIs(t, err, ErrMiss)
	requireNoTemps(t, c)
}

func TestCollectTempsNeverTouchesFinishedOrForeignNames(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)
	require.NoError(t, c.Put(d, payload))

	foreign := filepath.Join(c.Root(), "someone-elses-file")
	require.NoError(t, os.WriteFile(foreign, []byte("not ours"), 0o600))
	old := filepath.Join(c.Root(), tempPrefix+"sha256-deadbeef-1")
	require.NoError(t, os.WriteFile(old, []byte("partial"), 0o600))
	require.NoError(t, os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour)))
	young := filepath.Join(c.Root(), tempPrefix+"sha256-cafebabe-2")
	require.NoError(t, os.WriteFile(young, []byte("in flight"), 0o600))

	removed, err := c.CollectTemps()
	require.NoError(t, err)
	require.Equal(t, 1, removed, "only the temp older than the max age")

	_, err = os.Stat(old)
	require.ErrorIs(t, err, fs.ErrNotExist)
	for _, keep := range []string{foreign, young, filepath.Join(c.Root(), d.FileName())} {
		_, statErr := os.Stat(keep)
		require.NoError(t, statErr, "%s must survive collection", keep)
	}
}

func TestCollectTempsOnAnAbsentDirectoryIsNotAnError(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	removed, err := c.CollectTemps()
	require.NoError(t, err)
	require.Zero(t, removed)
}

// --- concurrent writers ------------------------------------------------------

// Real goroutines, one digest, run under -race. The assertion is about the
// visible entry being WHOLE and CORRECT afterwards, not about the absence of a
// panic: every writer renaming onto the same name is only safe because each one
// wrote digest-verified bytes to its own temp first, and a test that merely
// survived would pass against a cache that wrote the final name directly.
func TestConcurrentWritersLeaveOneWholeCorrectEntry(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("concurrent bundle bytes "), 4096) // ~96 KiB
	d := Compute(payload)

	const writers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []error
	start := make(chan struct{})

	fail := func(format string, a ...any) {
		mu.Lock()
		bad = append(bad, fmt.Errorf(format, a...))
		mu.Unlock()
	}

	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Staggered starts plus a drip-feeding reader guarantee that some
			// writers are mid-write while others are already reading — the only
			// arrangement in which a non-atomic writer is observable at all.
			time.Sleep(time.Duration(i) * 2 * time.Millisecond)
			if err := c.PutReader(d, &drip{r: bytes.NewReader(payload), n: 7919}); err != nil {
				fail("writer %d: %w", i, err)
				return
			}
			// Reading after this writer's own commit, repeatedly, so the reads
			// fall inside the other writers' windows. Once ANY writer has
			// committed, every subsequent read must see whole, correct bytes: a
			// writer that wrote the final name directly would be caught here
			// truncating it under a reader.
			for range 200 {
				got, err := c.Get(d)
				if err != nil {
					fail("reader %d: %w", i, err)
					continue
				}
				if !bytes.Equal(payload, got) {
					fail("reader %d saw %d of %d bytes", i, len(got), len(payload))
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	require.Empty(t, bad)

	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	// Exactly one visible entry, and every temp cleaned up.
	entries, err := os.ReadDir(c.Root())
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Equal(t, []string{d.FileName()}, names)
}

func TestConcurrentReadersAndWritersOfTheSameDigest(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("read while written"), 2048)
	d := Compute(payload)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []error

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.PutReader(d, &drip{r: bytes.NewReader(payload), n: 4093}); err != nil {
				mu.Lock()
				bad = append(bad, err)
				mu.Unlock()
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				b, err := c.Get(d)
				switch {
				case err == nil:
					// Whatever a reader sees, it sees all of it. A partial read
					// here is the failure this whole design prevents.
					if !bytes.Equal(payload, b) {
						mu.Lock()
						bad = append(bad, fmt.Errorf("reader saw %d of %d bytes", len(b), len(payload)))
						mu.Unlock()
					}
				case errors.Is(err, ErrMiss) && !errors.Is(err, ErrCorrupt):
					// Legitimate: no writer has renamed yet.
				default:
					mu.Lock()
					bad = append(bad, err)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	require.Empty(t, bad)

	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// --- layout ------------------------------------------------------------------

func TestDirIsCentralUnderAgentManagerHome(t *testing.T) {
	t.Parallel()

	// The cache is central on purpose; staging is a sibling of the destination
	// (R3). If this ever becomes a per-destination path, the atomic swap and the
	// cache have been merged and EXDEV is back.
	home := filepath.Join(string(filepath.Separator), "home", "u", ".agent-manager")
	require.Equal(t, filepath.Join(home, "cache"), Dir(home))
	require.Equal(t, "cache", DirName)
	require.NotContains(t, DirName, "staging")
}

func TestNewWithLimitFallsBackToTheDefaultCap(t *testing.T) {
	t.Parallel()

	for _, limit := range []int64{0, -1} {
		c := NewWithLimit(t.TempDir(), limit)
		require.Equal(t, MaxBundleBytes, c.maxBytes)
	}
	require.Equal(t, int64(25<<20), MaxBundleBytes, "the hub's compressed upload cap")
}

func TestEntryFileNameCarriesNoColon(t *testing.T) {
	t.Parallel()

	// A colon is illegal in a Windows filename; the on-disk spelling of the
	// digest is deliberately the third one.
	name := Compute([]byte("abc")).FileName()
	require.NotContains(t, name, ":")
	require.Equal(t, "sha256-"+abcHex, name)
	require.False(t, strings.HasPrefix(name, tempPrefix), "collection must not match a finished entry")
}

func TestPutCreatesTheCacheDirectoryPrivately(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	require.NoError(t, c.Put(Compute(payload), payload))

	info, err := os.Stat(c.Root())
	require.NoError(t, err)

	// Windows does not have the mode bits: Go synthesises 0777 for every
	// directory, so the 0700 argument to MkdirAll is discarded and this
	// assertion could only ever be made to pass by asserting 0777, which would
	// assert nothing. The skip is therefore recording a REAL GAP, not a
	// portability detail — the cache directory is genuinely not private on
	// Windows, and making it so needs an explicit DACL via
	// golang.org/x/sys/windows, which no task in this feature owns. Do not
	// widen this into "the mode does not matter".
	if runtime.GOOS == "windows" {
		require.Equal(t, fs.FileMode(0o777), info.Mode().Perm(),
			"if Windows ever grows real mode bits, this skip needs revisiting rather than relaxing")
		t.Skip("no mode bits on windows; the cache directory is not private there — see the comment")
	}
	require.Equal(t, fs.FileMode(dirMode), info.Mode().Perm())
}

// A discard that cannot remove the entry must SAY so, because the entry then
// poisons that digest for every future read rather than for this one. The
// swallowed version of this shipped and the Windows CI leg caught it; this test
// is what keeps the reporting from being quietly reverted as noise.
func TestAnUnremovableCorruptEntryIsReportedNotSwallowed(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		// A read-only directory does not block deletion on Windows, so there is
		// no portable way to make RemoveAll fail here. The behaviour under test
		// is platform-independent; only the way to provoke it is not.
		t.Skip("cannot make a directory refuse unlink on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bit, so the removal would succeed")
	}

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)
	require.NoError(t, c.Put(d, payload))

	entry := filepath.Join(c.Root(), d.FileName())
	require.NoError(t, os.WriteFile(entry, []byte("tampered!!!!"), 0o600))

	// Unlinking needs write on the DIRECTORY, not on the entry.
	require.NoError(t, os.Chmod(c.Root(), 0o500))
	t.Cleanup(func() { _ = os.Chmod(c.Root(), 0o700) })

	_, err := c.Get(d)

	// Still a miss and still corrupt, so every existing caller behaves the same...
	require.ErrorIs(t, err, ErrMiss)
	require.ErrorIs(t, err, ErrCorrupt)
	// ...but the permanence is now visible.
	require.ErrorContains(t, err, "could not be removed")
	require.ErrorContains(t, err, "every future read of this digest will fail the same way")

	// And the claim in that message is true: the entry really did survive.
	_, statErr := os.Stat(entry)
	require.NoError(t, statErr, "the message promises the entry is still there")
}

func TestVerifyDoesNotRetainBytesButStillRehashes(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := []byte("bundle bytes")
	d := Compute(payload)
	require.NoError(t, c.Put(d, payload))
	require.NoError(t, c.Verify(d))

	entry := filepath.Join(c.Root(), d.FileName())
	require.NoError(t, os.WriteFile(entry, []byte("tampered!!!!"), 0o600))
	err := c.Verify(d)
	require.ErrorIs(t, err, ErrCorrupt)
	_, statErr := os.Stat(entry)
	require.ErrorIs(t, statErr, fs.ErrNotExist, "Verify discards too, or the next Get would")
}

func TestPutReaderStreamsWithoutRequiringTheBytesInHand(t *testing.T) {
	t.Parallel()

	c := newTestCache(t)
	payload := bytes.Repeat([]byte("streamed"), 8192)
	d := Compute(payload)

	require.NoError(t, c.PutReader(d, &drip{r: bytes.NewReader(payload), n: 1}))
	got, err := c.Get(d)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.Equal(t, sha256.Sum256(payload), sha256.Sum256(got))
}

// --- helpers -----------------------------------------------------------------

func requireNoTemps(t *testing.T, c *Cache) {
	t.Helper()
	entries, err := os.ReadDir(c.Root())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), tempPrefix), "leftover temp %s", e.Name())
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// drip hands out at most n bytes per Read, so a write takes many turns and
// concurrent writers genuinely overlap.
type drip struct {
	r *bytes.Reader
	n int
}

func (d *drip) Read(p []byte) (int, error) {
	if len(p) > d.n {
		p = p[:d.n]
	}
	return d.r.Read(p)
}
