// Package cache is the digest-addressed store for bundle bytes at
// `~/.agent-manager/cache/sha256-<digest>`. Bundle bytes are immutable, so a
// key needs no invalidation, only a check that the bytes on disk still match it.
//
// It never repairs a corrupt entry, only deletes it: every entry is
// reconstructible from the hub, so discarding is always safe. It never hands
// out a path for reading, only verified bytes, to avoid a TOCTOU between the
// check and the use. It is not the staging directory used for atomic install:
// staging must be same-filesystem as its destination for os.Rename to work,
// while this cache holds bytes fetched once and reused across hubs/profiles/targets.
//
// There is no eviction. Every version ever fetched stays until the directory
// is deleted by hand (`rm -rf ~/.agent-manager/cache`), which is always safe.
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
	// DirName is not per hub: the same version fetched from two hubs is the
	// same bytes, so keying by hub would double the disk for no gain.
	DirName = "cache"

	// MaxBundleBytes mirrors the hub's own compressed upload limit, kept as an
	// independent constant (not a shared module) since the CLI must not trust
	// the hub to enforce it.
	MaxBundleBytes int64 = 25 << 20

	// DefaultTempMaxAge is how old a leftover temp file must be before
	// collection removes it. See CollectTempsOlderThan.
	DefaultTempMaxAge = 24 * time.Hour

	// tempPrefix must never be a prefix of a finished entry's name (`sha256-<hex>`).
	tempPrefix = ".amctl-tmp-"

	dirMode = 0o700
)

// ErrMiss means "this digest is not usable from cache", covering both an
// absent entry and a discarded one, since a caller deciding whether to
// download cannot act on the difference. Errors from Get and Verify always
// wrap it, so errors.Is(err, ErrMiss) is the test.
var ErrMiss = errors.New("not in cache")

// ErrCorrupt marks the subset of misses that had bytes on disk which failed
// the re-hash and were discarded. Joined onto ErrMiss.
var ErrCorrupt = errors.New("cache entry did not match its digest and was discarded")

// ErrTooLarge is returned by Put/PutReader for a bundle over the cap.
var ErrTooLarge = errors.New("bundle exceeds the cache's size cap")

// Cache is a directory of digest-addressed bundle bytes. It holds no state
// beyond its configuration, so concurrent use from multiple goroutines and
// processes is safe; see PutReader on how writers race.
type Cache struct {
	dir      string
	maxBytes int64
}

// Dir is the cache directory under an already-resolved `~/.agent-manager`.
// This package does not resolve the home directory itself; that check
// belongs to internal/cmd's home resolution, before any network call.
func Dir(agentManagerHome string) string {
	return filepath.Join(agentManagerHome, DirName)
}

// New returns a cache rooted at dir with the default size cap. It creates
// nothing; the directory is created by the first write.
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

// Root is the cache directory, for error messages and diagnostics only; it is
// not a read handle (see the package comment).
func (c *Cache) Root() string { return c.dir }

func (c *Cache) path(d Digest) string { return filepath.Join(c.dir, d.FileName()) }

// Get returns the bytes stored under d, having re-hashed them first. The
// returned slice is the slice that was hashed, not a re-read of the file, so
// nothing can change between check and use. A mismatch discards the entry
// and reports a miss.
func (c *Cache) Get(d Digest) ([]byte, error) {
	return c.load(d, true)
}

// Verify reports whether a trustworthy entry for d exists, without retaining
// its bytes. Same discard-on-mismatch rule as Get.
func (c *Cache) Verify(d Digest) error {
	_, err := c.load(d, false)
	return err
}

func (c *Cache) load(d Digest, keep bool) ([]byte, error) {
	if d.IsZero() {
		return nil, errors.New("refusing to read the zero digest: it was never parsed or computed")
	}
	p := c.path(d)

	// A missing cache directory is a miss, not an error: open reports the same
	// fs.ErrNotExist whether the entry or the whole directory is absent.
	f, err := os.Open(p) //nolint:gosec // p is c.dir joined with a parsed digest's canonical file name
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", d, ErrMiss)
		}
		return nil, fmt.Errorf("opening cache entry %s: %w", p, err)
	}
	defer func() { _ = f.Close() }()

	// fstat on the handle actually read, not an lstat of the name, so the thing
	// checked and the thing used are the same object. A non-regular entry
	// (e.g. a directory squatting at the name, which would otherwise poison
	// that digest with EISDIR forever) is discarded like an oversize one.
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
		// Pre-size from stat; the LimitReader below is what actually bounds it,
		// since the file may still grow.
		if st.Size() > 0 && st.Size() <= c.maxBytes {
			buf = make([]byte, 0, st.Size())
		}
		sink = io.MultiWriter(h, &sliceWriter{buf: &buf})
	}

	// maxBytes+1 so an oversize file is detected rather than silently
	// truncated into a hash that then just fails to match.
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
// error the caller should report, marked ErrCorrupt and ErrMiss. A failed
// removal is reported too (joined on), since a surviving corrupt entry would
// otherwise fail every future read of the digest the same way forever.
// RemoveAll rather than Remove so a directory-shaped squatter can be cleared;
// the name is always a parsed Digest's own spelling, never a caller's string.
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

// PutReader streams r into the cache under d: write to a temp file, hash
// while streaming, verify, fsync, then rename into place. Writing the final
// name directly would let a killed process leave a truncated file that
// re-hashes wrong forever; fsync before rename matters because syncing the
// directory makes the entry durable but not its content, and a crash right
// after rename can otherwise leave a zero-length final file. Two processes
// racing to fetch the same bundle each rename byte-identical, verified
// content onto the same name, so the loser is harmless.
func (c *Cache) PutReader(d Digest, r io.Reader) error {
	if d.IsZero() {
		return errors.New("refusing to write the zero digest: it was never parsed or computed")
	}
	if err := os.MkdirAll(c.dir, dirMode); err != nil {
		return fmt.Errorf("creating cache directory %s: %w", c.dir, err)
	}

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
	// Runs on the write path only, piggybacking on a fetch that already paid
	// for a network round trip, so a leaked temp is always eventually collected.
	_, _ = c.CollectTemps()
	return nil
}

// syncDir makes the new directory entry durable. Non-fatal: the entry is
// already installed and correct, and a filesystem that refuses the fsync
// (some network mounts) must not fail an otherwise complete write.
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

// CollectTempsOlderThan removes temp files last modified more than age ago,
// and returns how many it removed. The criterion is age, not PID liveness,
// since a PID is meaningless across a container boundary and wrong after PID
// reuse; a temp file untouched for a day is certainly dead, since no download
// stays silent that long while still in progress. A prefix match over a
// directory listing is safe here (unlike in prune) because amctl owns this
// whole directory, so every name in it is one amctl wrote.
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
