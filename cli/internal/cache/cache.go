// Package cache is the digest-addressed store for bundle bytes. Entries are
// immutable and never repaired, only discarded and re-fetched.
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
	// DirName is not per hub: the same version from two hubs is the same bytes.
	DirName = "cache"

	// MaxBundleBytes mirrors the hub's own upload limit; kept independent since
	// the CLI must not trust the hub to enforce it.
	MaxBundleBytes int64 = 25 << 20

	// DefaultTempMaxAge is how old a leftover temp file must be before
	// collection removes it.
	DefaultTempMaxAge = 24 * time.Hour

	// tempPrefix must never be a prefix of a finished entry's name.
	tempPrefix = ".amctl-tmp-"

	dirMode = 0o700
)

// ErrMiss means "this digest is not usable from cache": absent or discarded.
// Errors from Get and Verify always wrap it.
var ErrMiss = errors.New("not in cache")

// ErrCorrupt marks a miss whose bytes existed but failed the re-hash. Joined
// onto ErrMiss.
var ErrCorrupt = errors.New("cache entry did not match its digest and was discarded")

// ErrTooLarge is returned by Put/PutReader for a bundle over the cap.
var ErrTooLarge = errors.New("bundle exceeds the cache's size cap")

// Cache is a directory of digest-addressed bundle bytes. Safe for concurrent
// use from multiple goroutines and processes; see PutReader.
type Cache struct {
	dir      string
	maxBytes int64
}

// Dir is the cache directory under an already-resolved home directory.
func Dir(agentManagerHome string) string {
	return filepath.Join(agentManagerHome, DirName)
}

// New returns a cache rooted at dir with the default size cap.
func New(dir string) *Cache {
	return NewWithLimit(dir, MaxBundleBytes)
}

// NewWithLimit is New with an explicit per-entry cap; non-positive means the
// default.
func NewWithLimit(dir string, maxBytes int64) *Cache {
	if maxBytes <= 0 {
		maxBytes = MaxBundleBytes
	}
	return &Cache{dir: dir, maxBytes: maxBytes}
}

// Root is the cache directory, for messages only; not a read handle.
func (c *Cache) Root() string { return c.dir }

func (c *Cache) path(d Digest) string { return filepath.Join(c.dir, d.FileName()) }

// Get returns the bytes stored under d, re-hashed first. A mismatch discards
// the entry and reports a miss.
func (c *Cache) Get(d Digest) ([]byte, error) {
	return c.load(d, true)
}

// Verify reports whether a trustworthy entry for d exists, without keeping
// its bytes.
func (c *Cache) Verify(d Digest) error {
	_, err := c.load(d, false)
	return err
}

func (c *Cache) load(d Digest, keep bool) ([]byte, error) {
	if d.IsZero() {
		return nil, errors.New("refusing to read the zero digest: it was never parsed or computed")
	}
	p := c.path(d)

	f, err := os.Open(p) //nolint:gosec // p is c.dir joined with a parsed digest's canonical file name
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", d, ErrMiss)
		}
		return nil, fmt.Errorf("opening cache entry %s: %w", p, err)
	}
	defer func() { _ = f.Close() }()

	// Stat the open handle, not the name, so the thing checked and the thing
	// used are the same object.
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
		if st.Size() > 0 && st.Size() <= c.maxBytes {
			buf = make([]byte, 0, st.Size())
		}
		sink = io.MultiWriter(h, &sliceWriter{buf: &buf})
	}

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

// discard removes an entry proven unusable. RemoveAll rather than Remove so a
// directory-shaped squatter is cleared too.
func (c *Cache) discard(d Digest, reason error) error {
	miss := fmt.Errorf("%w: %w: %w", reason, ErrCorrupt, ErrMiss)
	if err := os.RemoveAll(c.path(d)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(miss, fmt.Errorf(
			"cache entry %s could not be removed, so every future read of this digest will fail the same way: %w",
			c.path(d), err))
	}
	return miss
}

// Put stores b under d, refusing bytes that do not hash to d.
func (c *Cache) Put(d Digest, b []byte) error {
	if got := Compute(b); got != d {
		return fmt.Errorf("refusing to cache %d bytes hashing to %s under %s", len(b), got, d)
	}
	return c.PutReader(d, bytes.NewReader(b))
}

// PutReader streams r into the cache under d: write to a temp file while
// hashing, verify, fsync, then rename into place. That order means a killed
// process leaves a stray temp file rather than a truncated final entry, and
// two processes racing on the same digest each rename identical, verified
// bytes onto the same name, so the loser is harmless.
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
	_, _ = c.CollectTemps()
	return nil
}

// syncDir makes the new directory entry durable. Non-fatal: the entry is
// already installed and correct.
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
// and returns how many it removed. Age, not PID liveness: a PID means
// nothing across a container boundary or after reuse.
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

// sliceWriter appends to a slice through a pointer.
type sliceWriter struct{ buf *[]byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}
