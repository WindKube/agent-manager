package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Concurrent syncs on one home are refused via an O_CREATE|O_EXCL file at
// ~/.agent-manager/sync.lock. Staleness is decided by heartbeat (a holder
// refreshes the lock's mtime every lockHeartbeat; older than lockStaleAfter
// is stale) — the pid-liveness check in liveness.go only ever SHORTENS that
// wait, never replaces it, since pid reuse, container namespaces and a
// merely frozen (not dead) holder all make it lie toward "alive" only.
const (
	lockHeartbeat  = 15 * time.Second
	lockStaleAfter = 90 * time.Second // six heartbeats; wrong here costs two concurrent syncs
)

// ErrLocked marks the refusal: another amctl holds this home's sync lock.
// Callers match on it with errors.Is; the message names the other holder.
var ErrLocked = errors.New("another amctl is syncing this home")

// Holder is what a lock file records, so a refusal can name a pid, host and
// start time instead of saying "busy". Nothing here is secret or trusted for
// anything beyond a message and the pid accelerator above.
type Holder struct {
	PID     int    `json:"pid"`
	Host    string `json:"host"` // os.Hostname at acquisition; skips the pid check in another container
	Version string `json:"version"`
	// AcquiredAt is NOT what staleness is measured from — that's the file's
	// heartbeat-refreshed mtime.
	AcquiredAt time.Time `json:"acquiredAt"`
	Token      string    `json:"token"` // lets a holder notice its lock was reclaimed
}

// String renders a holder for the refusal message.
func (h Holder) String() string {
	s := fmt.Sprintf("process %d on host %q", h.PID, h.Host)
	if !h.AcquiredAt.IsZero() {
		s += ", started " + h.AcquiredAt.UTC().Format(time.RFC3339)
	}
	if h.Version != "" {
		s += ", amctl " + h.Version
	}
	return s
}

// Lock is a held sync lock. Release it exactly once, with defer.
type Lock struct {
	path   string
	holder Holder
	opts   lockOptions

	stop     chan struct{}
	stopped  chan struct{}
	once     sync.Once
	lost     atomic.Bool
	released atomic.Bool
}

type lockOptions struct {
	staleAfter time.Duration
	heartbeat  time.Duration
	now        func() time.Time
	host       string
	pid        int
}

func defaultLockOptions() lockOptions {
	host, err := os.Hostname()
	if err != nil || host == "" {
		// unknownHost, not "": "" would match every holder that also failed here.
		host = unknownHost
	}
	return lockOptions{
		staleAfter: lockStaleAfter,
		heartbeat:  lockHeartbeat,
		now:        time.Now,
		host:       host,
		pid:        os.Getpid(),
	}
}

// unknownHost contains a character no real hostname may contain, so it never
// accidentally matches.
const unknownHost = "?unknown"

// Acquire takes the per-home sync lock, or refuses (CodeRefused) naming
// whoever holds it. It never blocks or waits: a queued sync would be
// indistinguishable from a hung CLI, and the caller decides whether to retry.
func Acquire(h Home) (*Lock, error) { return acquire(h, defaultLockOptions()) }

func acquire(h Home, o lockOptions) (*Lock, error) {
	path := h.LockPath()
	if err := os.MkdirAll(h.Root, 0o700); err != nil {
		return nil, Refusef("cannot create %s for the sync lock: %w", h.Root, err)
	}

	// Two attempts, never more: the second is only for a stale lock just
	// reclaimed; a third failure is a live acquirer, and looping would block.
	for attempt := range 2 {
		l, err := tryCreate(path, o)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, Refusef("cannot create the sync lock %s: %w", path, err)
		}
		if attempt == 1 {
			return nil, refuseLocked(path, Holder{}, "it was taken by another amctl while this one was reclaiming a stale lock")
		}

		holder, info, readErr := readLock(path)
		if readErr != nil {
			if errors.Is(readErr, fs.ErrNotExist) {
				continue // it went away between the create and the read
			}
			// Still a lock: treating it as absent would let garbage bytes defeat it.
			return nil, refuseLocked(path, Holder{},
				fmt.Sprintf("its lock file could not be read (%v); delete it if no amctl is running", readErr))
		}
		stale, why := o.isStale(holder, info)
		if !stale {
			return nil, refuseLocked(path, holder, "")
		}
		if err := removeIfUnchanged(path, info); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, refuseLocked(path, holder,
				fmt.Sprintf("%s, but its lock file could not be reclaimed (%v)", why, err))
		}
	}
	return nil, refuseLocked(path, Holder{}, "")
}

func refuseLocked(path string, h Holder, detail string) error {
	switch {
	case detail != "":
		return Refusef("%w: %s (%s)", ErrLocked, detail, path)
	case h.PID != 0:
		return Refusef("%w: %s has held %s; wait for it to finish, or delete that file if the process is gone",
			ErrLocked, h, path)
	default:
		return Refusef("%w: %s is held; wait for it to finish, or delete that file if no amctl is running",
			ErrLocked, path)
	}
}

func tryCreate(path string, o lockOptions) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // path is Home.LockPath, derived from a validated home
	if err != nil {
		return nil, err
	}
	holder := Holder{
		PID:        o.pid,
		Host:       o.host,
		Version:    Version,
		AcquiredAt: o.now().UTC(),
		Token:      newLockToken(),
	}
	body, err := json.Marshal(holder)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	// Sync so a reader in another process never sees an empty file.
	_ = f.Sync()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}

	l := &Lock{path: path, holder: holder, opts: o, stop: make(chan struct{}), stopped: make(chan struct{})}
	go l.beat()
	return l, nil
}

func newLockToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable" // never fails in practice; only weakens frozen-holder detection
	}
	return hex.EncodeToString(b[:])
}

// beat refreshes the lock's mtime and checks the lock is still ours.
func (l *Lock) beat() {
	defer close(l.stopped)
	t := time.NewTicker(l.opts.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			holder, _, err := readLock(l.path)
			if err != nil || holder.Token != l.holder.Token {
				l.lost.Store(true)
				return
			}
			now := l.opts.now()
			_ = os.Chtimes(l.path, now, now)
		}
	}
}

// Lost reports whether this lock was reclaimed while held (the frozen-holder case).
func (l *Lock) Lost() bool { return l.lost.Load() }

func (l *Lock) Path() string { return l.path }

func (l *Lock) Holder() Holder { return l.holder }

// Release stops the heartbeat and removes the lock file. Idempotent and safe
// from a defer, including mid-panic. Does NOT remove a lock file that is no
// longer ours (Lost): that would hand a third run a free pass.
func (l *Lock) Release() error {
	if !l.released.CompareAndSwap(false, true) {
		return nil
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.stopped
	})
	if l.lost.Load() {
		return fmt.Errorf("the sync lock %s was reclaimed by another amctl while this run held it", l.path)
	}
	// Verify ownership before unlinking.
	if holder, _, err := readLock(l.path); err == nil && holder.Token != l.holder.Token {
		l.lost.Store(true)
		return fmt.Errorf("the sync lock %s is now held by %s; leaving it in place", l.path, holder)
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the sync lock %s: %w", l.path, err)
	}
	return nil
}

// WithLock runs fn under the per-home sync lock, releasing it afterwards
// including on a panic. A release failure is returned only when fn itself
// succeeded, so a real error is never replaced by a cleanup complaint.
func WithLock(h Home, fn func(*Lock) error) error {
	l, err := Acquire(h)
	if err != nil {
		return err
	}
	defer func() { _ = l.Release() }()
	if err := fn(l); err != nil {
		return err
	}
	return l.Release()
}

// readLock stats the open handle, not the path, so mtime describes the bytes read.
func readLock(path string) (Holder, os.FileInfo, error) {
	f, err := os.Open(path) //nolint:gosec // path is Home.LockPath, derived from a validated home
	if err != nil {
		return Holder{}, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Holder{}, nil, err
	}
	var h Holder
	if err := json.NewDecoder(f).Decode(&h); err != nil {
		return Holder{}, info, fmt.Errorf("unreadable lock file: %w", err)
	}
	return h, info, nil
}

// removeIfUnchanged unlinks path only if it's unchanged since judged stale, narrowing (not closing) the reclaim race.
func removeIfUnchanged(path string, judged os.FileInfo) error {
	fresh, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(judged, fresh) {
		return errors.New("the lock file was replaced while it was being examined")
	}
	if !fresh.ModTime().Equal(judged.ModTime()) {
		return errors.New("the lock file's holder is still heartbeating")
	}
	return os.Remove(path)
}

// isStale implements the two rules at the top of this file.
func (o lockOptions) isStale(h Holder, info os.FileInfo) (stale bool, why string) {
	if info != nil {
		if age := o.now().Sub(info.ModTime()); age > o.staleAfter {
			return true, fmt.Sprintf("its heartbeat stopped %s ago", age.Round(time.Second))
		}
	}
	if h.Host != "" && h.Host == o.host && h.Host != unknownHost && !processAlive(h.PID) {
		return true, fmt.Sprintf("process %d on this host is gone", h.PID)
	}
	return false, ""
}
