// Package cache is the digest-addressed store for bundle bytes at
// `~/.agent-manager/cache/sha256-<digest>` (FR-017). It needs no invalidation:
// plan.md's second load-bearing fact is that bundle bytes are immutable, so a
// key uniquely determines its content forever, and the only question a reader
// can ask is whether the bytes on disk still ARE that content.
//
// What this package deliberately does NOT do:
//
//   - It never repairs. A cache entry whose bytes no longer hash to its key is
//     deleted, not patched, not re-verified against something else, not used
//     "because it is probably fine". Every entry is reconstructible from the
//     hub by definition, so discarding is always the recoverable direction and
//     is the only one that keeps FR-017 true.
//   - It never hands out a path for reading. Verifying a file and then
//     returning its name is a TOCTOU: the thing verified and the thing used
//     must be the same thing, so Get returns the bytes it hashed. Root() exists
//     for error messages only.
//   - It does not bound its own size. See "Eviction" below.
//   - It is NOT the staging directory, and the two must never be merged.
//     Staging is a sibling of the destination (`<dest-parent>/.amctl-staging/`)
//     because gate R3 measured `os.Rename` across filesystems: agent
//     directories are frequently symlinks into a dotfiles repo on another
//     mount, and same-filesystem staging is the only thing that makes the
//     atomic swap a rename at all. This cache is central precisely because it
//     is NOT renamed into place — it holds compressed bundle bytes that are
//     read, verified and copied out, so the same bytes fetched for two hubs,
//     two profiles or two targets are stored once. Moving staging in here to
//     "unify the two digest-addressed directories" reintroduces the EXDEV
//     failure exactly where R3's rollback needs a rename to work.
//
// # Eviction
//
// There is none, and no task in this feature owns adding one. The consequence
// is honest and monotone: every version ever fetched stays until someone
// deletes the directory, bounded per entry by MaxBundleBytes (25 MiB, the hub's
// upload cap) and in practice by how often a catalogue churns. A machine
// syncing a large catalogue for a year accumulates real disk. Whoever adds it
// needs a last-used signal, and atime is not one — `relatime` and `noatime`
// make it unreliable — so it needs either an mtime touch on every hit (a write
// on the read path, deliberately not done here) or a sidecar of last-use
// timestamps. Until then the supported answer is `rm -rf ~/.agent-manager/cache`,
// which is always safe, and the natural home for a real `--prune-cache` is US5
// (T055/T056), the only story that already reasons about cache contents.
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
	"strings"
	"time"
)

const (
	// DirName is the cache's directory name under `~/.agent-manager`. It is
	// deliberately NOT per hub: the same version fetched from two hubs is the
	// same bytes, and keying by hub would double the disk for no gain
	// (plan.md, storage table).
	DirName = "cache"

	// MaxBundleBytes caps what a single entry may be, on both the write and
	// the read path. The number is the hub's own compressed upload limit
	// (`internal/bundle.DefaultMaxCompressedBytes`, 25 MiB) — the same NUMBER
	// on purpose and independent CODE on purpose, for the reason plan.md's
	// Complexity Tracking gives about the extractor: the CLI is the last hop
	// and must not trust the hub, and a shared module means a shared bug.
	MaxBundleBytes int64 = 25 << 20

	// DefaultTempMaxAge is how old a leftover temp file must be before
	// collection removes it. See CollectTempsOlderThan.
	DefaultTempMaxAge = 24 * time.Hour

	// tempPrefix marks a file as a partial write of ours. Collection matches on
	// it, so it must never be a prefix of a finished entry's name
	// (`sha256-<hex>`).
	tempPrefix = ".amctl-tmp-"

	dirMode = 0o700
)

// ErrMiss means "this digest is not usable from cache". It covers an absent
// entry and a discarded one alike, because a caller deciding whether to
// download cannot act on the difference; `--offline` (FR-018) reports the
// digest either way. Errors from Get and Verify always wrap it, so
// errors.Is(err, ErrMiss) is the test — never an os.IsNotExist on Root().
var ErrMiss = errors.New("not in cache")

// ErrCorrupt marks the subset of misses that had bytes on disk which failed the
// re-hash and were discarded. Returned joined with ErrMiss, so a caller that
// only wants to know whether to download matches ErrMiss and a caller that
// wants to TELL the user their cache was corrupt matches ErrCorrupt.
var ErrCorrupt = errors.New("cache entry did not match its digest and was discarded")

// ErrTooLarge is returned by Put/PutReader for a bundle over the cap. On the
// read path an oversize entry is a corrupt entry: it cannot be what the hub
// served, so it is discarded rather than reported as too large.
var ErrTooLarge = errors.New("bundle exceeds the cache's size cap")

// Cache is a directory of digest-addressed bundle bytes. It holds no state
// beyond its configuration, so concurrent use from multiple goroutines — and
// multiple processes — is safe; see PutReader on how writers race.
type Cache struct {
	dir      string
	maxBytes int64
}

// Dir is the cache directory under an already-resolved `~/.agent-manager`.
//
// This package does NOT resolve the home directory itself. FR-039 requires the
// refusal for an unset or unwritable home to name the variable, and that check
// belongs to `internal/cmd`'s home resolution, before any network call. A cache
// that quietly fell back to `os.UserHomeDir` would route around it.
func Dir(agentManagerHome string) string {
	return filepath.Join(agentManagerHome, DirName)
}

// New returns a cache rooted at dir with the default size cap.
//
// It creates nothing. A read against a machine that has never synced must not
// fabricate directories — `status --offline` reports a miss instead. The
// directory is created by the first write.
func New(dir string) *Cache {
	return NewWithLimit(dir, MaxBundleBytes)
}

// NewWithLimit is New with an explicit per-entry cap. Non-positive means the
// default; the tests use a small cap to exercise the oversize paths without
// writing 25 MiB.
func NewWithLimit(dir string, maxBytes int64) *Cache {
	if maxBytes <= 0 {
		maxBytes = MaxBundleBytes
	}
	return &Cache{dir: dir, maxBytes: maxBytes}
}

// Root is the cache directory, for error messages and diagnostics. It is not a
// read handle: see the package comment on why no path is handed out for
// reading.
func (c *Cache) Root() string { return c.dir }

func (c *Cache) path(d Digest) string { return filepath.Join(c.dir, d.FileName()) }

// Get returns the bytes stored under d, having re-hashed them first (FR-017).
//
// The returned slice IS the slice that was hashed — not a re-read of the file —
// so nothing can change between the check and the use. A mismatch discards the
// entry and reports a miss; the caller downloads again.
func (c *Cache) Get(d Digest) ([]byte, error) {
	return c.load(d, true)
}

// Verify reports whether a trustworthy entry for d exists, without retaining
// its bytes. Same discard-on-mismatch rule as Get. This is the honest form of
// "is it cached": an existence check that does not re-hash would answer a
// question FR-017 does not allow anyone to ask.
func (c *Cache) Verify(d Digest) error {
	_, err := c.load(d, false)
	return err
}

func (c *Cache) load(d Digest, keep bool) ([]byte, error) {
	if d.IsZero() {
		return nil, errors.New("refusing to read the zero digest: it was never parsed or computed")
	}
	p := c.path(d)

	// A missing cache directory is a miss, not an error: New creates nothing, so
	// a machine that has never synced reaches here with no directory at all,
	// and open reports the same fs.ErrNotExist for both.
	f, err := os.Open(p) //nolint:gosec // p is c.dir joined with a parsed digest's canonical file name
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", d, ErrMiss)
		}
		return nil, fmt.Errorf("opening cache entry %s: %w", p, err)
	}
	defer func() { _ = f.Close() }()

	// fstat on the handle we will actually read, not an lstat of the name: the
	// thing checked and the thing used must be the same object.
	//
	// A cache entry that is not a regular file cannot be what the hub served, so
	// it is discarded on the same grounds as an oversize one. It is not merely
	// tidiness: a directory named `sha256-<hex>` makes every read of that digest
	// fail with EISDIR forever — a permanent poison for one bundle that no
	// re-download can clear — and a symlink at that name would have the read
	// follow it out of the cache directory. The re-hash still makes either safe;
	// this makes both self-healing.
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat of cache entry %s: %w", p, err)
	}
	if !st.Mode().IsRegular() {
		return nil, c.discard(d, fmt.Errorf("%s is not a regular file (%s)", d, st.Mode().Type()))
	}

	h := sha256.New()
	var buf []byte
	var sink io.Writer = h
	if keep {
		// Cap the buffer's growth by pre-sizing from the stat; the LimitReader
		// below is what actually bounds it, because the file may still grow.
		if st.Size() > 0 && st.Size() <= c.maxBytes {
			buf = make([]byte, 0, st.Size())
		}
		sink = io.MultiWriter(h, &sliceWriter{buf: &buf})
	}

	// maxBytes+1 so an oversize file is detected rather than silently truncated
	// into a hash that then cannot match — a truncating read would report a
	// digest mismatch and blame the bytes for the reader's own cap.
	n, err := io.Copy(sink, io.LimitReader(f, c.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading cache entry %s: %w", p, err)
	}
	if n > c.maxBytes {
		return nil, c.discard(d, fmt.Errorf("%s is larger than the %d-byte cap", d, c.maxBytes))
	}

	got, err := digestFromSlice(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	if got != d {
		return nil, c.discard(d, fmt.Errorf("%s hashes to %s", d, got))
	}
	if keep {
		return buf, nil
	}
	return nil, nil
}

// discard removes an entry that has just been proven unusable and returns the
// error the caller should report: reason, marked ErrCorrupt and ErrMiss so the
// caller re-downloads.
//
// A failed removal is REPORTED, joined onto that miss. An earlier version
// swallowed it, reasoning that "the caller's outcome is the same either way —
// the entry is unusable and the bundle is re-downloaded". That is true of this
// call and false of the next one: if the entry survives, every future read of
// the digest finds the same corruption and re-downloads again, forever.
//
// errors.Join, so errors.Is still sees ErrCorrupt and ErrMiss and no caller has
// to learn about the removal to keep working.
//
// RemoveAll rather than Remove only so that a directory-shaped squatter at an
// entry name can be cleared; the name is always the `sha256-<hex>` spelling of
// a parsed Digest, never a caller's string, so the recursion has nowhere to go.
func (c *Cache) discard(d Digest, reason error) error {
	miss := fmt.Errorf("%w: %w: %w", reason, ErrCorrupt, ErrMiss)
	if err := os.RemoveAll(c.path(d)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(miss, fmt.Errorf(
			"cache entry %s could not be removed, so every future read of this digest will fail the same way: %w",
			c.path(d), err))
	}
	return miss
}

// Put stores b under d. It refuses bytes that do not hash to d, so no code path
// in this CLI can file bytes under a key they do not match.
func (c *Cache) Put(d Digest, b []byte) error {
	if got := Compute(b); got != d {
		return fmt.Errorf("refusing to cache %d bytes hashing to %s under %s", len(b), got, d)
	}
	return c.PutReader(d, bytes.NewReader(b))
}

// PutReader streams r into the cache under d.
//
// Temp file, hash while streaming, verify, fsync, rename. Each step is load
// bearing:
//
//   - Writing to the final name directly is how a killed process leaves a
//     truncated file that looks whole — and a whole-looking short file passes
//     every check except the digest, which is why the digest check exists;
//     but the file would still be re-read and re-hashed on every future run
//     forever. The temp name means an interrupted write is invisible to Get.
//   - The hash is computed on the bytes as they are WRITTEN, not by re-reading
//     the temp afterwards. Re-reading verifies the page cache, not the file.
//   - The fsync of the temp is not decoration. R3's finding for T040 applies
//     verbatim here: fsyncing a directory makes the entry DURABLE, not the
//     CONTENT, so on a delayed-allocation filesystem a crash just after the
//     rename can leave the final name present and zero length — precisely the
//     whole-looking truncated entry this whole dance exists to prevent.
//
// Two processes fetching the same bundle each write their own temp and rename
// onto the same final name; the rename is atomic and both wrote byte-identical,
// digest-verified content, so the loser is harmless. A POSIX reader holding the
// replaced inode open keeps reading identical bytes.
func (c *Cache) PutReader(d Digest, r io.Reader) error {
	if d.IsZero() {
		return errors.New("refusing to write the zero digest: it was never parsed or computed")
	}
	if err := os.MkdirAll(c.dir, dirMode); err != nil {
		return fmt.Errorf("creating cache directory %s: %w", c.dir, err)
	}

	// The temp name carries the prefix so collection can recognise it and the
	// digest so a human can see what it was; the random suffix is os.CreateTemp's.
	tmp, err := os.CreateTemp(c.dir, tempPrefix+d.FileName()+"-*")
	if err != nil {
		return fmt.Errorf("creating cache temp file in %s: %w", c.dir, err)
	}
	name := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, c.maxBytes+1))
	if err != nil {
		return fmt.Errorf("writing cache temp file %s: %w", name, err)
	}
	if n > c.maxBytes {
		return fmt.Errorf("%s is over the %d-byte cap: %w", d, c.maxBytes, ErrTooLarge)
	}
	got, err := digestFromSlice(h.Sum(nil))
	if err != nil {
		return err
	}
	if got != d {
		return fmt.Errorf("refusing to cache %d bytes hashing to %s under %s", n, got, d)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing cache temp file %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing cache temp file %s: %w", name, err)
	}
	if err := os.Rename(name, c.path(d)); err != nil {
		return fmt.Errorf("installing cache entry %s: %w", c.path(d), err)
	}
	committed = true

	c.syncDir()
	// Collection runs on the write path only: it is one readdir of a small
	// directory, and the write path has already paid for a network fetch, so a
	// leaked temp is always collected by the next download without any caller
	// having to remember to wire this up.
	_, _ = c.CollectTemps()
	return nil
}

// syncDir makes the new directory entry durable. Non-fatal, matching R3's
// treatment of the same step in the swap: the entry is already installed and
// correct, and a filesystem that refuses the fsync (some network mounts) must
// not fail an otherwise complete write.
func (c *Cache) syncDir() {
	f, err := os.Open(c.dir) //nolint:gosec // the cache directory this Cache was constructed with
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_ = f.Sync()
}

// CollectTemps removes leftover temp files older than DefaultTempMaxAge.
func (c *Cache) CollectTemps() (int, error) {
	return c.CollectTempsOlderThan(DefaultTempMaxAge)
}

// CollectTempsOlderThan removes temp files last modified more than age ago, and
// returns how many it removed.
//
// The criterion is AGE, not PID liveness. A temp name could carry the writing
// process's PID, but liveness of a PID is meaningless across a container
// boundary and wrong after PID reuse — the same trap T024's lock documents — so
// this reads no PID and makes no liveness claim. Age is sound in one direction
// only, which is the direction that matters: a temp file untouched for a day is
// certainly dead, because a download that has not written a byte in 24 hours is
// not in progress.
//
// What it does NOT catch, deliberately: a temp file younger than age, including
// one from a process killed a second ago (it is collected by a later run); and
// what it would wrongly catch — a genuinely live download stalled for over a
// day — costs only that download, which fails its rename and is retried, never
// a finished entry.
//
// A prefix match over a directory listing is acceptable HERE and forbidden in
// prune (FR-028) for a reason worth stating: amctl creates and owns this whole
// directory, so every name in it is one amctl wrote. An agent's skills
// directory is shared with the user's own hand-written files, which is why
// removal there walks the installation record instead. Names that do not carry
// tempPrefix — a finished `sha256-<hex>` entry, or anything a stranger left —
// are never touched.
func (c *Cache) CollectTempsOlderThan(age time.Duration) (int, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading cache directory %s: %w", c.dir, err)
	}
	cutoff := time.Now().Add(-age)
	removed := 0
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		info, infoErr := e.Info()
		if infoErr != nil {
			if !errors.Is(infoErr, fs.ErrNotExist) {
				errs = append(errs, infoErr)
			}
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if rmErr := os.Remove(filepath.Join(c.dir, e.Name())); rmErr != nil {
			if !errors.Is(rmErr, fs.ErrNotExist) {
				errs = append(errs, rmErr)
			}
			continue
		}
		removed++
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("collecting cache temp files in %s: %w", c.dir, errors.Join(errs...))
	}
	return removed, nil
}

// sliceWriter appends to a slice through a pointer, so the pre-sized buffer in
// load survives the append that grows it.
type sliceWriter struct{ buf *[]byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}
