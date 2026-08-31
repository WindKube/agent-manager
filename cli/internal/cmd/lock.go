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

// FR-038 refuses concurrent syncs against the same home rather than
// interleaving them. The mechanism is an O_CREATE|O_EXCL file at
// `~/.agent-manager/sync.lock`, which is atomic on every platform amctl
// targets, in the standard library, and needs no build tags.
//
// # What was NOT used, and why
//
//   - `flock`/`fcntl` locks (gofrs/flock and friends). A kernel-held lock is
//     released automatically when the process dies, which is strictly better
//     than anything below — and it is famously unreliable over NFS, and on
//     Linux an `flock` on an inherited fd is shared with children. No
//     dependency was added for this; the standard library is enough.
//   - A lock DIRECTORY (`os.Mkdir`). Also atomic, but there is nowhere to
//     record who holds it, and "another amctl is running" without a pid, a
//     host and a start time is a message nobody can act on.
//
// # How a stale lock is decided — the deliverable comment
//
// Staleness is a HEARTBEAT, not a timeout on the sync and not a liveness check
// on a pid:
//
//  1. While a lock is held, the holder rewrites the lock file's mtime every
//     lockHeartbeat (15s). A lock whose mtime is older than lockStaleAfter
//     (90s, six heartbeats) is stale.
//  2. As an ACCELERATOR only, a lock recording our own hostname whose pid is
//     no longer alive is stale immediately, without waiting out the 90s.
//
// The heartbeat is the correctness argument; the pid check only ever SHORTENS
// the wait. That asymmetry is deliberate, because every way the pid check can
// be wrong makes it say "alive":
//
//   - PID reuse. The recorded pid now belongs to an unrelated process, so
//     Signal(0) succeeds and we call it alive. We then fall back to the
//     heartbeat, which is correct. The reverse — concluding a live holder is
//     dead — cannot happen this way.
//   - A container boundary. A holder in another container has its own pid
//     namespace, so pid 7 there may be pid 7 here and belong to something
//     else; the hostname guard normally skips the check entirely (container
//     hostnames differ), and where it does not (`--uts host`), the worst
//     answer is again "alive".
//   - Permission denied — another user's process, which therefore exists. Read
//     as alive.
//
// The probe itself is in liveness.go.
//
// # What this does NOT catch. All four are real; none is fixed by the code
//
//   - A holder FROZEN for longer than lockStaleAfter — SIGSTOP, a laptop
//     suspend, an uninterruptible read from a dead NFS mount, a very long stop
//     the world — is declared stale while still alive, and two syncs can then
//     run. The mitigation is one-sided: each heartbeat re-reads the lock file
//     and compares its token, so a holder that lost its lock discovers it
//     within one heartbeat and Lost() reports true. It is not airtight — a
//     holder unfrozen mid-write still lands that write.
//   - CLOCK SKEW. Staleness compares the file's mtime, set by the server
//     holding the filesystem, against this machine's clock. On a home on NFS or
//     SMB with a skewed server clock, a fresh lock can look 90 seconds old (two
//     syncs) or a dead one can look fresh forever (a wedged CLI until the file
//     is deleted by hand, which the refusal message says how to do).
//   - A filesystem without atomic O_EXCL. Old NFSv2/v3 mounts without proper
//     locking support can grant O_EXCL to two clients. A home on such a mount
//     is not covered by this lock at all.
//   - RECLAIM is not atomic. Deciding a lock is stale and unlinking it are two
//     syscalls; removeIfUnchanged re-stats and unlinks only if it is still the
//     same inode with the same mtime it judged, which narrows the window to a
//     single syscall and means the holder must heartbeat inside it. After that
//     the unlink-then-O_EXCL-create sequence has exactly one winner, because a
//     second reclaimer either finds the fresh lock (and refuses, since a fresh
//     lock is not stale) or loses the create.
//
// The failure modes of getting this wrong are asymmetric and both are in this
// list: too eager and two syncs interleave on one skills directory; too
// reluctant and one crashed process makes the CLI permanently unusable. The
// heartbeat is the only mechanism found that is wrong in neither direction for
// a sync that legitimately runs for twenty minutes.
const (
	// lockHeartbeat is how often a holder proves it is still alive.
	lockHeartbeat = 15 * time.Second
	// lockStaleAfter is six heartbeats. A generous multiple, because the cost
	// of being wrong here is two concurrent syncs and the cost of waiting is a
	// message telling the user exactly which pid to look at.
	lockStaleAfter = 90 * time.Second
)

// ErrLocked marks the refusal: another amctl holds this home's sync lock.
// Callers match on it with errors.Is; the message names the other holder.
var ErrLocked = errors.New("another amctl is syncing this home")

// Holder is what a lock file records about whoever holds it. It exists so the
// refusal can name a pid, a host and a start time instead of saying "busy".
//
// Nothing here is secret — no token, no hub URL, no credential (FR-007) — and
// nothing here is trusted for anything but a message and the pid accelerator
// above.
type Holder struct {
	// PID is the holder's process id, meaningful only together with Host.
	PID int `json:"pid"`
	// Host is os.Hostname at acquisition, which is what makes the pid check
	// skip a holder in another container.
	Host string `json:"host"`
	// Version is the amctl build that took the lock, so a lock left by an old
	// binary is identifiable.
	Version string `json:"version"`
	// AcquiredAt is when the lock was taken. It is NOT what staleness is
	// measured from — that is the file's mtime, refreshed by the heartbeat —
	// because a sync that has legitimately run for an hour must not be
	// declared dead for having started an hour ago.
	AcquiredAt time.Time `json:"acquiredAt"`
	// Token is a random per-acquisition id. Its only job is to let a holder
	// notice that its lock was reclaimed from under it; see the frozen-holder
	// note above.
	Token string `json:"token"`
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
		// An unknown hostname must not be confused with a match: "" would make
		// the pid accelerator fire against every holder that also failed here.
		// unknownHost never equals a real hostname, so the check just skips.
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

// unknownHost stands in for a hostname this process could not read. It contains
// a character no hostname may contain, so it can never accidentally match.
const unknownHost = "?unknown"

// Acquire takes the per-home sync lock, or refuses naming whoever holds it.
//
// The refusal is Refuse-marked, so it reaches FR-036's CodeRefused: retrying is
// pointless until the other run finishes, which is exactly what that code
// means. It does NOT block and it does NOT wait — a sync that queued behind
// another would be indistinguishable from a hung CLI, and the caller (a cron
// job, a CI step) is far better placed to decide whether to retry than this
// function is.
func Acquire(h Home) (*Lock, error) { return acquire(h, defaultLockOptions()) }

func acquire(h Home, o lockOptions) (*Lock, error) {
	path := h.LockPath()
	if err := os.MkdirAll(h.Root, 0o700); err != nil {
		return nil, Refusef("cannot create %s for the sync lock: %w", h.Root, err)
	}

	// Two attempts, never more. The second exists only for the case where the
	// first found a stale lock and reclaimed it; anything beyond that is
	// another live acquirer, and looping would be the blocking behaviour this
	// function refuses to have.
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
			// An unreadable lock file is still a lock. Refusing on a corrupt
			// one is the safe direction: treating it as absent would be a way
			// to defeat the lock by writing garbage into it, and the message
			// tells the user which file to delete.
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
	// Sync so a reader in another process sees the holder rather than an empty
	// file. An empty lock file would be refused as unreadable, which is safe
	// but reports the wrong reason.
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
		// crypto/rand.Read does not fail on any supported platform, and a
		// predictable token here costs only the frozen-holder detection, not
		// the lock itself.
		return "unavailable"
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

// Lost reports that this lock was reclaimed or deleted by someone else while
// held — the frozen-holder case in the package comment. A caller that sees true
// should stop before it writes anything more; nothing here enforces that,
// because there is no way to un-write what has already landed.
func (l *Lock) Lost() bool { return l.lost.Load() }

// Path is the lock file's path, for messages.
func (l *Lock) Path() string { return l.path }

// Holder is what this lock recorded about itself.
func (l *Lock) Holder() Holder { return l.holder }

// Release stops the heartbeat and removes the lock file. It is idempotent and
// safe to call from a defer, including while a panic unwinds — which is the
// reason WithLock exists and the reason a panicking sync does not leave the
// machine locked for 90 seconds.
//
// It does NOT remove a lock file that is no longer ours (Lost): deleting the
// current holder's lock on the way out would hand a third run a free pass.
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
	// Verify ownership before unlinking, for the same reason.
	if holder, _, err := readLock(l.path); err == nil && holder.Token != l.holder.Token {
		l.lost.Store(true)
		return fmt.Errorf("the sync lock %s is now held by %s; leaving it in place", l.path, holder)
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the sync lock %s: %w", l.path, err)
	}
	return nil
}

// WithLock runs fn under the per-home sync lock and releases it afterwards,
// including on a panic. Use this rather than Acquire wherever the work fits in
// a function: it is the only shape in which the release cannot be forgotten.
//
// A release failure is returned only when fn itself succeeded, so a real error
// is never replaced by a cleanup complaint.
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

// The FileInfo comes from File.Stat() on the open handle rather than from a
// second os.Stat of the path, so the mode and mtime reported here describe the
// file this call actually read.
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

// removeIfUnchanged unlinks path only if it is still the same file, with the
// same mtime, that the caller judged stale. See the reclaim note in the package
// comment: this narrows the reclaim race to one syscall, it does not close it,
// and there is no portable conditional unlink that would.
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

// isStale implements the two rules documented at the top of this file.
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
