package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// lockHome builds a Home over a temp directory without going through
// ResolveHome, so a lock test cannot fail for a home-resolution reason.
func lockHome(t *testing.T) Home {
	t.Helper()
	dir := t.TempDir()
	return Home{UserHome: dir, Var: homeEnvVar(), Root: filepath.Join(dir, DirName)}
}

// fastOpts shrinks the heartbeat and the staleness window so a test does not
// wait 90 seconds. The intervals are OPTIONS rather than package variables on
// purpose: a mutable package knob plus -shuffle plus -race is a race in the
// test harness rather than in the code under test.
func fastOpts(o lockOptions) lockOptions {
	o.heartbeat = 5 * time.Millisecond
	o.staleAfter = 200 * time.Millisecond
	return o
}

func TestAcquireWritesAHolderAndReleaseRemovesTheFile(t *testing.T) {
	h := lockHome(t)

	l, err := Acquire(h)
	require.NoError(t, err)
	require.Equal(t, h.LockPath(), l.Path())
	require.FileExists(t, l.Path())

	body, err := os.ReadFile(l.Path())
	require.NoError(t, err)
	var got Holder
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, os.Getpid(), got.PID)
	require.NotEmpty(t, got.Host)
	require.NotEmpty(t, got.Token)
	require.False(t, got.AcquiredAt.IsZero())
	require.Equal(t, l.Holder().Token, got.Token)

	require.NoError(t, l.Release())
	require.NoFileExists(t, l.Path())
	require.False(t, l.Lost())
}

func TestAcquireCreatesTheStateRootIfItIsMissing(t *testing.T) {
	h := lockHome(t)
	require.NoDirExists(t, h.Root)

	l, err := Acquire(h)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Release() })
	require.DirExists(t, h.Root)
}

func TestReleaseIsIdempotent(t *testing.T) {
	h := lockHome(t)
	l, err := Acquire(h)
	require.NoError(t, err)

	require.NoError(t, l.Release())
	require.NoError(t, l.Release())
	require.NoError(t, l.Release())
}

// Refuse, do not interleave and do not wait. This is the two-goroutine
// (really two in-process acquisitions) form: it proves the O_EXCL
// exclusion, the exit code and the message. It does not prove exclusion
// across processes — TestASecondPROCESSRefusesAndNamesTheHolder does that.
func TestASecondAcquireRefusesNamingTheHolder(t *testing.T) {
	h := lockHome(t)

	first, err := Acquire(h)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Release() })

	start := time.Now()
	second, err := Acquire(h)
	require.Error(t, err)
	require.Nil(t, second)
	require.Less(t, time.Since(start), 2*time.Second, "FR-038 refuses; it must not block or wait")

	require.ErrorIs(t, err, ErrLocked)
	require.True(t, IsRefusal(err), "a concurrent sync is user-fixable: wait, or kill the other run")
	require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err),
		"exit.go's CodeRefused is the user-fixable class, and FR-038 is in its doc comment")

	// Naming the holder is the point of recording one. Asserting only that an
	// error occurred would pass against "busy".
	msg := err.Error()
	require.Contains(t, msg, strconv.Itoa(first.Holder().PID))
	require.Contains(t, msg, first.Holder().Host)
	require.Contains(t, msg, h.LockPath())
	require.Contains(t, msg, first.Holder().AcquiredAt.UTC().Format(time.RFC3339))

	// The refusal is printed, so it must carry nothing but process facts.
	require.NotContains(t, msg, "token")
	require.NotContains(t, msg, first.Holder().Token)

	// The first holder still holds it, and its file is untouched.
	require.FileExists(t, h.LockPath())
	require.False(t, first.Lost())
}

// The two-PROCESS case. The in-process test above shares one runtime, one
// os.OpenFile implementation and one page cache, so it cannot distinguish
// "O_EXCL excludes" from "the Go runtime serialised us"; and it cannot produce
// a holder that dies without unwinding. This re-executes the test binary,
// SIGKILLs the child, and then proves both halves.
func TestASecondPROCESSRefusesAndNamesTheHolder(t *testing.T) {
	if os.Getenv("AMCTL_LOCK_HELPER") != "" {
		return // see lockHelperProcess
	}
	dir := t.TempDir()
	h := Home{UserHome: dir, Var: homeEnvVar(), Root: filepath.Join(dir, DirName)}

	child := exec.Command(os.Args[0], "-test.run=TestLockHelperProcess", "-test.v")
	child.Env = append(os.Environ(), "AMCTL_LOCK_HELPER="+h.Root)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	// Wait for the child to report the pid it locked with.
	childPID := readHelperPID(t, stdout)
	require.NotEqual(t, os.Getpid(), childPID)

	_, err = Acquire(h)
	require.ErrorIs(t, err, ErrLocked)
	require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
	require.Contains(t, err.Error(), strconv.Itoa(childPID),
		"the refusal must name the other process, not merely report that something failed")

	// Kill the holder without letting it unwind: the lock file survives, which
	// is exactly the state the staleness rule exists for.
	require.NoError(t, child.Process.Kill())
	_, _ = child.Process.Wait()
	require.FileExists(t, h.LockPath())

	// The pid accelerator: same host, process gone, so this is reclaimed
	// immediately rather than after lockStaleAfter. If it waited for the
	// heartbeat window this test would time out, which is the assertion.
	l, err := Acquire(h)
	require.NoError(t, err, "a lock left by a SIGKILLed process must not wedge the machine")
	require.Equal(t, os.Getpid(), l.Holder().PID)
	require.NoError(t, l.Release())
}

// TestLockHelperProcess is not a test. It is the child half of the test above:
// it takes the lock, prints its pid and blocks until it is killed.
func TestLockHelperProcess(t *testing.T) {
	root := os.Getenv("AMCTL_LOCK_HELPER")
	if root == "" {
		t.Skip("child half of TestASecondPROCESSRefusesAndNamesTheHolder")
	}
	h := Home{UserHome: filepath.Dir(root), Var: homeEnvVar(), Root: root}
	l, err := Acquire(h)
	if err != nil {
		fmt.Printf("AMCTL_HELPER_ERROR %v\n", err)
		return
	}
	fmt.Printf("AMCTL_HELPER_PID %d\n", l.Holder().PID)
	os.Stdout.Sync()
	time.Sleep(2 * time.Minute)
}

func readHelperPID(t *testing.T, stdout interface{ Read([]byte) (int, error) }) int {
	t.Helper()
	buf := make([]byte, 0, 512)
	chunk := make([]byte, 128)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n, err := stdout.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for _, line := range strings.Split(string(buf), "\n") {
			if rest, ok := strings.CutPrefix(line, "AMCTL_HELPER_PID "); ok {
				pid, convErr := strconv.Atoi(strings.TrimSpace(rest))
				require.NoError(t, convErr)
				return pid
			}
			if strings.HasPrefix(line, "AMCTL_HELPER_ERROR") {
				t.Fatalf("helper could not lock: %s", line)
			}
		}
		if err != nil {
			break
		}
	}
	t.Fatalf("helper never reported a pid; got %q", buf)
	return 0
}

// A lock whose recorded process is gone ON THIS HOST is reclaimed at once,
// without waiting out the heartbeat window.
func TestAStaleLockFromADeadProcessOnThisHostIsReclaimedImmediately(t *testing.T) {
	h := lockHome(t)
	o := defaultLockOptions()
	writeLockFile(t, h, Holder{
		PID:        deadPID(t),
		Host:       o.host,
		Version:    "1.0.0",
		AcquiredAt: time.Now().UTC(),
		Token:      "aaaa",
	}, time.Now()) // a FRESH mtime, so only the pid rule can explain a reclaim

	l, err := Acquire(h)
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), l.Holder().PID)
	require.NotEqual(t, "aaaa", l.Holder().Token)
	require.NoError(t, l.Release())
}

// A lock recorded by ANOTHER host is never pid-checked — a pid means nothing
// across a host or container boundary — so only the heartbeat can reclaim it.
func TestAStaleLockFromAnotherHostIsReclaimedOnlyByTheHeartbeatWindow(t *testing.T) {
	h := lockHome(t)
	o := fastOpts(defaultLockOptions())

	t.Run("a fresh mtime from another host is refused even with a dead pid", func(t *testing.T) {
		writeLockFile(t, h, Holder{PID: deadPID(t), Host: "some-other-box", Token: "bbbb"}, time.Now())
		_, err := acquire(h, o)
		require.ErrorIs(t, err, ErrLocked)
		require.Contains(t, err.Error(), "some-other-box")
	})

	t.Run("a stopped heartbeat from another host is reclaimed", func(t *testing.T) {
		writeLockFile(t, h, Holder{PID: deadPID(t), Host: "some-other-box", Token: "bbbb"},
			time.Now().Add(-10*o.staleAfter))
		l, err := acquire(h, o)
		require.NoError(t, err)
		require.NoError(t, l.Release())
	})
}

// The failure mode of an mtime timeout is a sync that legitimately runs longer
// than the timeout being declared dead. The heartbeat is what prevents that, so
// it is asserted directly: a holder that started long ago but is still beating
// keeps its lock.
func TestALongRunningSyncKeepsItsLockBecauseTheHeartbeatKeepsBeating(t *testing.T) {
	h := lockHome(t)
	o := fastOpts(defaultLockOptions())

	l, err := acquire(h, o)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Release() })

	// Backdate the recorded start time far past staleAfter. Staleness must not
	// be measured from AcquiredAt.
	holder := l.Holder()
	holder.AcquiredAt = time.Now().Add(-1 * time.Hour).UTC()
	body, err := json.Marshal(holder)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(l.Path(), body, 0o600))

	// Wait well past staleAfter. The heartbeat must keep the mtime current.
	time.Sleep(4 * o.staleAfter)

	_, err = acquire(h, o)
	require.ErrorIs(t, err, ErrLocked, "a sync that has run for an hour is not a stale lock")
	require.False(t, l.Lost())
}

func TestTheHeartbeatRefreshesTheLockFilesMtime(t *testing.T) {
	h := lockHome(t)
	o := fastOpts(defaultLockOptions())

	l, err := acquire(h, o)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Release() })

	first, err := os.Stat(l.Path())
	require.NoError(t, err)
	require.NoError(t, os.Chtimes(l.Path(), time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)))

	require.Eventually(t, func() bool {
		info, statErr := os.Stat(l.Path())
		return statErr == nil && !info.ModTime().Before(first.ModTime())
	}, 5*time.Second, 5*time.Millisecond, "the heartbeat must put the mtime back")
}

// The frozen-holder case from lock.go's comment: a holder whose lock was
// reclaimed from under it must notice, because nothing else can tell it.
func TestAHolderWhoseLockWasReclaimedReportsLost(t *testing.T) {
	h := lockHome(t)
	o := fastOpts(defaultLockOptions())

	l, err := acquire(h, o)
	require.NoError(t, err)

	// Simulate a reclaim by another run: replace the file with a different
	// token, which is exactly what tryCreate would leave behind.
	writeLockFile(t, h, Holder{PID: 999999, Host: "thief", Token: "zzzz"}, time.Now())

	require.Eventually(t, l.Lost, 5*time.Second, 5*time.Millisecond,
		"the token check on each heartbeat is the only way a holder can find out")

	// Release must NOT delete the new holder's lock.
	err = l.Release()
	require.Error(t, err)
	require.Contains(t, err.Error(), "reclaimed")
	require.FileExists(t, h.LockPath())
	holder, _, err := readLock(h.LockPath())
	require.NoError(t, err)
	require.Equal(t, "zzzz", holder.Token, "the thief's lock must survive our Release")
}

// TestASyncWhoseLockWasReclaimedStopsBeforeWriting is the other half of the test
// above, and it is what makes the detection a mitigation rather than a fact
// nobody reads. Lock.Lost's own doc says "a caller that sees true should stop
// before it writes anything more"; until this was wired, `sync` discarded the
// *Lock at WithLock and Lost had no production call site at all, so a holder
// frozen past the staleness window resumed and kept swapping entries in a tree
// another amctl was already applying to.
func TestASyncWhoseLockWasReclaimedStopsBeforeWriting(t *testing.T) {
	h := lockHome(t)
	l, err := acquire(h, fastOpts(defaultLockOptions()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Release() })

	opts, _, _ := testOptions("https://hub.example.com", output.FormatHuman)
	r := &syncRun{opts: opts, s: opts.Streams(), home: h, lock: l}
	require.NoError(t, r.stillOurs(), "a lock we still hold is not a reason to stop")

	// Another run reclaims it while this one is frozen.
	writeLockFile(t, h, Holder{PID: 999999, Host: "thief", Token: "zzzz"}, time.Now())
	require.Eventually(t, l.Lost, 5*time.Second, 5*time.Millisecond)

	err = r.stillOurs()
	require.Error(t, err)
	require.Contains(t, err.Error(), h.LockPath(), "the message must name the lock")
	require.False(t, IsRefusal(err), "nothing the user did caused this and re-running is the fix")

	// And the apply phase refuses before it opens the tree.
	applied, aerr := r.apply(t.Context(), plan.Plan{}, record.New("https://hub.example.com"),
		filepath.Join(h.Root, "hub", record.FileName), nil, nil, nil)
	require.Error(t, aerr)
	require.Contains(t, aerr.Error(), h.LockPath())
	require.Nil(t, applied, "nothing may be attempted once the lock is somebody else's")
}

// A corrupt lock file is still a lock: treating it as absent would be a way to
// defeat the lock by writing garbage into it.
func TestACorruptLockFileIsRefusedRatherThanIgnored(t *testing.T) {
	h := lockHome(t)
	require.NoError(t, os.MkdirAll(h.Root, 0o700))
	require.NoError(t, os.WriteFile(h.LockPath(), []byte("{not json"), 0o600))

	_, err := Acquire(h)
	require.ErrorIs(t, err, ErrLocked)
	require.Equal(t, CodeRefused, ExitCode(CodeNoChanges, err))
	require.Contains(t, err.Error(), "could not be read")
	require.Contains(t, err.Error(), h.LockPath(), "the message must say which file to delete")
}

func TestWithLockReleasesOnANormalReturn(t *testing.T) {
	h := lockHome(t)

	ran := false
	require.NoError(t, WithLock(h, func(l *Lock) error {
		ran = true
		require.FileExists(t, l.Path())
		return nil
	}))
	require.True(t, ran)
	require.NoFileExists(t, h.LockPath())

	// And the lock is immediately re-acquirable, which is the observable half.
	l, err := Acquire(h)
	require.NoError(t, err)
	require.NoError(t, l.Release())
}

func TestWithLockReturnsTheWorkErrorAndStillReleases(t *testing.T) {
	h := lockHome(t)
	sentinel := errors.New("sync failed")

	err := WithLock(h, func(*Lock) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
	require.NoFileExists(t, h.LockPath())
}

// Released on a panic. Claimed in Release's doc comment, so it is proved: a
// panicking sync must not leave the machine locked until the heartbeat expires.
func TestWithLockReleasesWhileAPanicUnwinds(t *testing.T) {
	h := lockHome(t)

	require.PanicsWithValue(t, "boom", func() {
		_ = WithLock(h, func(*Lock) error { panic("boom") })
	})
	require.NoFileExists(t, h.LockPath())

	l, err := Acquire(h)
	require.NoError(t, err, "the lock must be free again the instant the panic unwinds")
	require.NoError(t, l.Release())
}

// Exactly one of N concurrent acquirers wins, and every loser gets ErrLocked
// rather than a corrupt lock or a second success. Run under -race, this is also
// the race detector's look at the heartbeat goroutine.
func TestExactlyOneOfManyConcurrentAcquirersWins(t *testing.T) {
	h := lockHome(t)
	require.NoError(t, os.MkdirAll(h.Root, 0o700))

	const n = 16
	var wins atomic.Int64
	var locked atomic.Int64
	var other []error
	var mu sync.Mutex
	var wg sync.WaitGroup
	release := make(chan struct{})

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := Acquire(h)
			switch {
			case err == nil:
				wins.Add(1)
				<-release
				_ = l.Release()
			case errors.Is(err, ErrLocked):
				locked.Add(1)
			default:
				mu.Lock()
				other = append(other, err)
				mu.Unlock()
			}
		}()
	}
	// Hold the winner until every loser has had its turn, so a loser cannot
	// win by arriving after the winner released.
	require.Eventually(t, func() bool { return wins.Load()+locked.Load()+int64(len(other)) == n },
		10*time.Second, time.Millisecond)
	close(release)
	wg.Wait()

	require.Empty(t, other, "no acquirer may fail for a reason other than ErrLocked")
	require.Equal(t, int64(1), wins.Load(), "FR-038: two syncs must not both proceed")
	require.Equal(t, int64(n-1), locked.Load())
	require.NoFileExists(t, h.LockPath())
}

func TestIsStaleRules(t *testing.T) {
	o := defaultLockOptions()
	o.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	fresh := stubInfo{mod: o.now().Add(-time.Second)}
	old := stubInfo{mod: o.now().Add(-2 * lockStaleAfter)}

	cases := []struct {
		name      string
		holder    Holder
		info      os.FileInfo
		wantStale bool
		wantWhy   string
	}{
		{"a beating heartbeat from this host with a live pid holds", Holder{PID: os.Getpid(), Host: o.host}, fresh, false, ""},
		{"a beating heartbeat from another host holds", Holder{PID: 1, Host: "elsewhere"}, fresh, false, ""},
		{"a stopped heartbeat is stale whoever held it", Holder{PID: os.Getpid(), Host: o.host}, old, true, "heartbeat stopped"},
		{"a dead pid on this host is stale at once", Holder{PID: deadPID(t), Host: o.host}, fresh, true, "on this host is gone"},
		{"a dead pid on another host is not pid-checked", Holder{PID: deadPID(t), Host: "elsewhere"}, fresh, false, ""},
		{"an unknown hostname never matches", Holder{PID: deadPID(t), Host: unknownHost}, fresh, false, ""},
		{"a holder with no host is not pid-checked", Holder{PID: deadPID(t)}, fresh, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stale, why := o.isStale(tc.holder, tc.info)
			require.Equal(t, tc.wantStale, stale)
			if tc.wantWhy != "" {
				require.Contains(t, why, tc.wantWhy)
			}
		})
	}
}

// processAlive answers "alive" to every question it cannot answer, because the
// only unsafe direction is calling a live holder dead.
func TestProcessAliveFailsTowardsAlive(t *testing.T) {
	require.True(t, processAlive(os.Getpid()), "our own process is alive")
	require.False(t, processAlive(0), "pid 0 is not a holder")
	require.False(t, processAlive(-1))
	require.False(t, processAlive(deadPID(t)))
}

// removeIfUnchanged is the reclaim guard: it must not unlink a lock whose
// holder heartbeated after the staleness judgment.
func TestRemoveIfUnchangedRefusesAFileThatChangedSinceItWasJudged(t *testing.T) {
	// The FileInfo comes from an open HANDLE, because that is how readLock
	// obtains the one this guard is given in production (f.Stat(), not
	// os.Stat).
	newLock := func(t *testing.T) (string, os.FileInfo) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "sync.lock")
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0o600))
		f, err := os.Open(p)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		require.NoError(t, err)
		return p, info
	}

	t.Run("a heartbeat since the judgment blocks the unlink", func(t *testing.T) {
		p, judged := newLock(t)
		now := judged.ModTime().Add(time.Second)
		require.NoError(t, os.Chtimes(p, now, now))

		err := removeIfUnchanged(p, judged)
		require.Error(t, err)
		require.Contains(t, err.Error(), "still heartbeating")
		require.FileExists(t, p)
	})

	// A DIFFERENT file at the same path with the SAME mtime: the mtime check
	// alone cannot see this, so it isolates the SameFile half of the guard.
	// Constructed by rename rather than by delete-and-recreate, because a
	// recreated file can land on the recycled inode and defeat the point.
	t.Run("a different file at the same path blocks the unlink", func(t *testing.T) {
		p, judged := newLock(t)
		other := p + ".other"
		require.NoError(t, os.WriteFile(other, []byte("{}"), 0o600))
		require.NoError(t, os.Chtimes(other, judged.ModTime(), judged.ModTime()))
		require.NoError(t, os.Rename(other, p))

		fresh, err := os.Stat(p)
		require.NoError(t, err)
		require.True(t, fresh.ModTime().Equal(judged.ModTime()), "the mtimes must match, or this proves nothing")
		require.False(t, os.SameFile(judged, fresh),
			"it must be a different file, or this proves nothing — see the handle note on newLock")

		err = removeIfUnchanged(p, judged)
		require.Error(t, err)
		require.Contains(t, err.Error(), "replaced")
		require.FileExists(t, p)
	})

	t.Run("an absent file reports not-exist so the caller retries the create", func(t *testing.T) {
		p, judged := newLock(t)
		require.NoError(t, os.Remove(p))
		require.ErrorIs(t, removeIfUnchanged(p, judged), os.ErrNotExist)
	})

	// The negative control: without this, the three cases above would also pass
	// against a removeIfUnchanged that never removed anything.
	t.Run("an unchanged file is unlinked", func(t *testing.T) {
		p, judged := newLock(t)
		require.NoError(t, removeIfUnchanged(p, judged))
		require.NoFileExists(t, p)
	})
}

func TestHolderStringNamesTheProcessAndOmitsNothingUseful(t *testing.T) {
	at := time.Date(2026, 8, 28, 9, 30, 0, 0, time.UTC)
	s := Holder{PID: 4242, Host: "box", Version: "1.2.3", AcquiredAt: at}.String()
	require.Contains(t, s, "4242")
	require.Contains(t, s, `"box"`)
	require.Contains(t, s, "2026-08-28T09:30:00Z")
	require.Contains(t, s, "1.2.3")
}

func writeLockFile(t *testing.T, h Home, holder Holder, mod time.Time) {
	t.Helper()
	require.NoError(t, os.MkdirAll(h.Root, 0o700))
	body, err := json.Marshal(holder)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(h.LockPath(), body, 0o600))
	require.NoError(t, os.Chtimes(h.LockPath(), mod, mod))
}

// deadPID returns a pid that is not running: a child that has been reaped, so
// the kernel has genuinely released it rather than a number guessed to be free.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHelperProcessThatExitsImmediately")
	cmd.Env = append(os.Environ(), "AMCTL_LOCK_NOOP=1")
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	return pid
}

// TestLockHelperProcessThatExitsImmediately is the reaped child deadPID needs.
func TestLockHelperProcessThatExitsImmediately(t *testing.T) {
	if os.Getenv("AMCTL_LOCK_NOOP") == "" {
		t.Skip("child half of deadPID")
	}
}

type stubInfo struct {
	os.FileInfo
	mod time.Time
}

func (s stubInfo) ModTime() time.Time { return s.mod }
