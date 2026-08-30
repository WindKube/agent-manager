// This file is T046: SC-008, the install tree after a sync KILLED mid-flight and
// re-run. It changes no production code; every finding below is a statement about
// the code as it stands.
//
// # WHAT "KILLED" MEANS HERE, AND WHY IT IS NOT A FAKE RETURNING AN ERROR
//
// An injected error proves much less than it looks like it does: production's
// `defer`s still run, Swap's step-3 rollback still runs, `Staged.Discard` still
// runs, and `WithLock`'s release still runs, so the state left behind is the
// state a crash CANNOT produce. So the killed run is a REAL child process,
// re-executing this test binary in the helper mode below, doing a real sync
// against the real fake hub over the parent's own HOME — and it dies of SIGKILL
// (`os.Process.Kill` on itself), which no defer, no recover and no rollback
// survives.
//
// That the defers really did not run is asserted, not assumed, and the lock is
// the proof: `WithLock` releases with a defer, and every one of these tests finds
// the dead child's lock file still on disk with the dead child's pid in it
// (requireLockWasLeftByTheKilledChild). The staged tree left behind in case 1 is
// the second proof — `Staged.Discard` is also a deferred cleanup that did not
// happen.
//
// `os.Exit` was the cheaper option the brief allowed and is not what is used —
// forbidigo also forbids it outside main.go — but it would have been the weaker
// mechanism anyway: it is a Go-level exit, so it can only land at a point the
// test's own code reaches, never between two syscalls production makes back to
// back.
//
// The kill is triggered by a WATCHER goroutine in the child that spins on one
// `lstat` and signals the moment the tree reaches the state under test. It needs
// no hook in production code, so it cannot be disarmed by a change to production
// code and it cannot silently drift away from what production does the way an
// injected hook can. What it costs is determinism, and the cost is paid twice:
// by the attempt loop in `killUntil` (every attempt asserts convergence from
// whatever state it actually produced, and the test requires the state it is
// named after to have been produced at least once), and — for the one window a
// watcher provably cannot see — by reaching that state with one syscall of the
// test's own. See TestTheWindowWhereTheDestinationIsAbsentConvergesByReclaimingTheAside.
//
// # THE THREE POINTS, WHICH ARE R3's STEPS, AND WHICH OF THEM A WATCHER CAN CATCH
//
//	killWhenStaged     the staged tree is complete (its marker, which Stage
//	                   writes last, is there) and step 2 has not run: dest
//	                   untouched, nothing recorded. CAUGHT on the first attempt,
//	                   every time: the window is Stage's two remaining fsyncs
//	                   wide.
//	killWhenAside      between steps 2 and 3 — the ONE window in which dest is
//	                   absent. NOT CATCHABLE, measured rather than assumed: the
//	                   userspace distance between the two renames in swap.go is a
//	                   single error check, 21ns mean and 42ns worst over 500
//	                   rounds, while one iteration of the cheapest watcher this
//	                   file can write (a dirfd-relative Root.Lstat of a
//	                   single-component name) costs 355ns. The window is 17x
//	                   narrower than one poll, and 24 real kills aimed at it — 12
//	                   with the collector on and 12 with it off, in case a mark
//	                   assist was the jitter — landed one syscall late, every
//	                   single time, as has every run of
//	                   TestARealKillAimedAtTheAsideWindowLandsOneSyscallLateAndStillConverges
//	                   since.
//	                   FR-024 permits this state explicitly, so what matters is
//	                   that a re-run converges from it, and that is asserted from
//	                   the state itself rather than from an attempt to race for
//	                   it.
//	killWhenInstalled  after step 3, before the record write. The tree is new; the
//	                   record still says old, or says nothing. CAUGHT on the first
//	                   attempt: the window is record.Save's fsync wide.
//
// # WHAT THIS FILE DOES NOT COVER
//
//   - Power loss. SIGKILL kills a process; it does not lose a write the kernel
//     has already accepted. Crash consistency needs dm-log-writes or a VM
//     force-reset loop, exactly as gate R3 says.
//   - Windows. `os.Process.Kill` is TerminateProcess there, and the "died of a
//     signal" assertion (`ExitCode() == -1`) is POSIX, so it is asserted
//     per-GOOS. Nothing here is skipped on Windows, but the kill assertion is
//     weaker there and says so at the assertion.
//   - A kill DURING a rename. Rename is atomic, so there is no such state to
//     observeInterrupted; that is why the interruption points are the boundaries between
//     R3's steps and not points inside them.
//   - Anything about swap.go's own step 2 (that it produces the aside state at
//     all). That is internal/apply/swap_test.go's R3 gate, which drove the
//     sequence directly and measured every rename in it.
//   - The one-entry-at-a-time shape of these scenarios. Every case kills during
//     the FIRST entry the plan writes, so no case here has a half-installed
//     PROFILE with several entries done and several not. Nothing in apply is
//     per-profile transactional, so that is a difference of degree; a case that
//     killed the third of three entries would exercise the same three windows.
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// ---------------------------------------------------------------- the contract with the child

// The child's parameters travel in the environment, EXCEPT the bearer token,
// which travels in a 0600 file whose path is in the environment. FR-007 is about
// logs, reports and errors and an environment variable is none of those, but a
// child process's environment is dumped by every debugger, every `ps -E` and
// every crash reporter, and the leakscan gate reads this suite's whole output —
// so the token is never a word in a command line or an environment value here.
const (
	interruptModeEnv    = "AMCTL_T046_MODE"
	interruptHubEnv     = "AMCTL_T046_HUB"
	interruptCredEnv    = "AMCTL_T046_CREDFILE"
	interruptProfileEnv = "AMCTL_T046_PROFILE"
	interruptRevEnv     = "AMCTL_T046_REVISION"
	interruptForceEnv   = "AMCTL_T046_FORCE"
	interruptDestEnv    = "AMCTL_T046_DEST"
	interruptVerEnv     = "AMCTL_T046_VERSION"
)

// childSurvivedMarker is printed by the child when runSync RETURNED — i.e. the
// watcher never fired. The parent treats that as a missed attempt rather than a
// failure, and it must never be mistaken for a kill.
const childSurvivedMarker = "AMCTL_T046_CHILD_SURVIVED"

type interruptMode string

const (
	killWhenStaged    interruptMode = "staged"
	killWhenAside     interruptMode = "aside"
	killWhenInstalled interruptMode = "installed"
)

// interruptClock is the fixed clock both the parent and the child stamp the
// record with, so a record written by one process and read by the other cannot
// differ by a timestamp.
var interruptClock = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------- the fixtures, hand-derived

// The two revisions of the baseline profile, read out of internal/hub/fake's
// catalog.go (profiles(), slugBaseline) rather than out of a run: revision 6 is
// one entry at 2.4.0, revision 7 (head) is three, with code-review moved to
// 2.4.1. requireFixturesStillSay re-derives them from the served lockfile so a
// fixture change cannot quietly make these tests assert nothing.
var (
	priorRevisionTree = map[string]string{"acme--code-review": "2.4.0"}
	headRevisionTree  = map[string]string{
		"acme--code-review":   "2.4.1",
		"acme--lint-guard":    "1.0.3",
		"example--doc-writer": "0.9.0",
	}
)

// interruptedDir is the entry every case interrupts: the one entry that exists in
// BOTH revisions, so it is the only one whose install can be an upgrade and
// therefore the only one whose swap has an aside at all.
const (
	interruptedDir = "acme--code-review"
	interruptedID  = "acme/code-review"
)

// ---------------------------------------------------------------- the child

// TestSyncInterruptHelperProcess is not a test. It is the killed run: a real
// `amctl sync` in a process that kills itself the moment the tree reaches the
// state its mode names.
//
// It takes no t.TempDir and registers no cleanup, because this process is
// expected to die between two syscalls and anything it registered would not run
// — which is the entire point of doing this in a child at all.
func TestSyncInterruptHelperProcess(t *testing.T) {
	mode := os.Getenv(interruptModeEnv)
	if mode == "" {
		t.Skip("child half of the T046 interruption tests")
	}
	token, err := os.ReadFile(os.Getenv(interruptCredEnv))
	if err != nil {
		t.Fatalf("child could not read its credential file: %v", err)
	}

	opts := &Options{
		Hub:    os.Getenv(interruptHubEnv),
		Output: string(output.FormatHuman),
		// The fake is plaintext for the child's sake: its self-signed
		// certificate cannot cross a process boundary, and an
		// InsecureSkipVerify client in here would be a second, weaker TLS path
		// that no test of TLS uses. FR-041's refusal is sync_test.go's.
		AllowPlaintextHub: true,
		Verbose:           true,
		result:            io.Discard,
		diag:              os.Stderr,
	}
	opts.streams = output.NewStreams(output.FormatHuman, opts.result, opts.diag)
	opts.streams.SetVerbose(true)

	flags := syncFlags{
		profiles: []string{os.Getenv(interruptProfileEnv)},
		force:    os.Getenv(interruptForceEnv) == "1",
	}
	if rev := os.Getenv(interruptRevEnv); rev != "" {
		flags.revisions = []string{rev}
	}
	deps := syncDeps{
		hostname:  func() (string, error) { return syncHost, nil },
		backends:  fileBackendOnly(),
		lookupEnv: childLookupEnv(strings.TrimSpace(string(token))),
		now:       func() time.Time { return interruptClock },
	}

	// The collector is off, and the honest reason is that it was a HYPOTHESIS
	// that did not pan out: the watcher's spin loop allocates, so it can be
	// recruited as a mark assist and parked at a STW for tens of microseconds,
	// which was the first suspect for the missed aside window. Turning it off
	// changed nothing — 3 more kills, same landing point — and the real
	// explanation is the 21ns window in the file header. It stays off because it
	// removes a source of jitter from every other window at no cost: this process
	// syncs three tiny skills and then dies.
	debug.SetGCPercent(-1)
	armKiller(interruptMode(mode), os.Getenv(interruptDestEnv), os.Getenv(interruptVerEnv))
	err = runSync(context.Background(), opts, flags, deps)
	fmt.Fprintf(os.Stderr, "%s err=%v\n", childSurvivedMarker, err)
}

// childLookupEnv hands the sync its credential without putting it in the
// process environment; see the comment on interruptCredEnv.
func childLookupEnv(token string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == credentials.TokenEnvVar {
			return token, true
		}
		return "", false
	}
}

// armKiller starts the watcher goroutines. Each spins on its own predicate — no
// sleep, no shared state — and SIGKILLs this process the instant it fires.
//
// Two watchers for killWhenAside and one otherwise. Two does not make that
// window catchable — the file header has the measurement that says nothing can —
// but it halves the mean detection latency for the state that IS caught there
// (after step 3, before step 5), and the second watcher costs one spinning
// thread on a 4-CPU box for the 30ms the child lives. Each goroutine builds its
// own predicate, so nothing is shared and no lock sits on the hot path, and each
// is pinned with LockOSThread so the scheduler cannot park a watcher and a
// syscall-heavy main goroutine on one CPU.
func armKiller(mode interruptMode, dest, version string) {
	watchers := 1
	if mode == killWhenAside {
		watchers = 2
	}
	ready := make(chan struct{}, watchers)
	for range watchers {
		go func() {
			runtime.LockOSThread()
			fired := newInterruptPredicate(mode, dest, version)
			self, err := os.FindProcess(os.Getpid())
			ready <- struct{}{}
			if err != nil {
				return
			}
			for {
				if fired() {
					_ = self.Kill()
					return
				}
			}
		}()
	}
	for range watchers {
		<-ready
	}
}

// newInterruptPredicate returns "the tree is now in the state this mode names".
// Each call returns a fresh closure with its own file handles, so several
// watchers never share one.
func newInterruptPredicate(mode interruptMode, dest, version string) func() bool {
	switch mode {
	case killWhenStaged:
		// The marker is what Stage writes LAST, so its presence means the staged
		// tree is complete — "after staging is populated", not "during
		// extraction".
		stagingRoot := layout.StagingRoot(dest)
		return func() bool {
			entries, err := os.ReadDir(stagingRoot)
			if err != nil {
				return false
			}
			for _, e := range entries {
				if _, serr := os.Lstat(filepath.Join(stagingRoot, e.Name(), layout.MarkerFileName)); serr == nil {
					return true
				}
			}
			return false
		}

	case killWhenAside:
		// One dirfd-relative lstat and nothing else. The aside exists ONLY
		// between step 2 and step 5, and dest is absent for the first rename of
		// that span, so firing on the aside alone fires at the earliest possible
		// instant; whether the window was actually caught is decided afterwards,
		// by the parent, from the state on disk.
		parent, name := filepath.Dir(dest), filepath.Base(dest)
		aside := name + record.AsideSuffix
		var root *os.Root
		return func() bool {
			if root == nil {
				opened, err := os.OpenRoot(parent)
				if err != nil {
					return false
				}
				root = opened
			}
			_, err := root.Lstat(aside)
			return err == nil
		}

	case killWhenInstalled:
		// The marker arrives at dest with the same single rename as the rest of
		// the entry (step 3), so a marker naming the NEW version means the swap
		// is done and only the record write is outstanding. Parsed rather than
		// substring-matched: an unparseable marker must not read as a version.
		marker := filepath.Join(dest, layout.MarkerFileName)
		return func() bool {
			b, err := os.ReadFile(marker)
			if err != nil {
				return false
			}
			m, err := layout.ParseMarker(b)
			return err == nil && m.Version == version
		}
	}
	return func() bool { return false }
}

// ---------------------------------------------------------------- the parent's wiring

// startInterruptFake starts the fake over http. See the child's
// AllowPlaintextHub comment for why this file cannot use TLS.
func startInterruptFake(t *testing.T) fake.Target {
	t.Helper()
	h := fake.New(fake.Options{})
	t.Cleanup(h.Close)
	return h.Target()
}

// runInterrupted is a sync run in THIS process — the prep run before a kill and
// the re-run after one. Verbose, because the two things that prove the re-run
// converged the way R3 says (the reclaimed aside, the marker adoption) are
// Debugf lines.
func runInterrupted(t *testing.T, e *syncEnv, flags syncFlags) (code Code, result, diag *syncBuffer, err error) {
	t.Helper()
	opts, result, diag := testOptions(e.target.BaseURL, output.FormatHuman)
	opts.AllowPlaintextHub = true
	opts.Verbose = true
	opts.Streams().SetVerbose(true)
	err = runSync(context.Background(), opts, flags, e.deps)
	return ExitCode(opts.Outcome, err), result, diag, err
}

func writeChildCredFile(t *testing.T, token string) string {
	t.Helper()
	// Outside the HOME under test: nothing this file asserts about the tree may
	// be looking at a file this file put there.
	path := filepath.Join(t.TempDir(), "cred")
	require.NoError(t, os.WriteFile(path, []byte(token), 0o600))
	return path
}

// killedChild is what one child attempt produced.
type killedChild struct {
	pid      int
	output   string
	survived bool
	exitCode int
}

// spawnKilledSync runs one real sync in a child that kills itself at mode, and
// returns once the child is REAPED. Reaping matters: the lock's staleness
// accelerator asks whether the recorded pid is alive, and on Unix a zombie
// answers yes — so a parent that had not waited would see the re-run refuse with
// ErrLocked and would blame the lock.
func spawnKilledSync(t *testing.T, e *syncEnv, mode interruptMode, flags syncFlags, version string) killedChild {
	t.Helper()
	dest := filepath.Join(e.skillsRoot(), interruptedDir)

	child := exec.Command(os.Args[0], "-test.run=TestSyncInterruptHelperProcess", "-test.v")
	env := append(os.Environ(),
		homeEnvVar()+"="+e.home,
		interruptModeEnv+"="+string(mode),
		interruptHubEnv+"="+e.target.BaseURL,
		interruptCredEnv+"="+writeChildCredFile(t, e.target.Token),
		interruptProfileEnv+"="+flags.profiles[0],
		interruptDestEnv+"="+dest,
		interruptVerEnv+"="+version,
	)
	if len(flags.revisions) > 0 {
		env = append(env, interruptRevEnv+"="+flags.revisions[0])
	}
	if flags.force {
		env = append(env, interruptForceEnv+"=1")
	}
	child.Env = env

	var buf bytes.Buffer
	child.Stdout, child.Stderr = &buf, &buf
	require.NoError(t, child.Start())
	pid := child.Process.Pid
	_ = child.Wait()

	out := buf.String()
	run := killedChild{pid: pid, output: out,
		survived: strings.Contains(out, childSurvivedMarker),
		exitCode: child.ProcessState.ExitCode(),
	}
	if run.survived {
		return run
	}
	require.NotEqual(t, 0, run.exitCode, "a child that neither reported surviving nor died is a bug in this test: %s", out)
	require.NotContains(t, out, "panic:", "the child must have been KILLED, not panicked: %s", out)
	if runtime.GOOS != "windows" {
		require.Equal(t, -1, run.exitCode,
			"exit code -1 is os/exec's report of death by signal; anything else means the process unwound, and an unwound process runs defers")
	}
	return run
}

// ---------------------------------------------------------------- observing the wreckage

// interruptState is the state of the tree and the record for the watched entry, after
// a kill. It is what decides WHICH interruption point an attempt actually hit.
type interruptState struct {
	destVersion     string // the marker at dest, "" when dest is absent
	destPresent     bool
	asideVersion    string
	asidePresent    bool
	staged          []string // digest-named staged trees left behind
	recordExists    bool
	recordVersion   string // the version the record claims for the watched entry
	recordTempFiles []string
}

func (o interruptState) String() string {
	return fmt.Sprintf("dest=%q(present=%t) aside=%q(present=%t) staged=%v record=%q(exists=%t) temps=%v",
		o.destVersion, o.destPresent, o.asideVersion, o.asidePresent, o.staged, o.recordVersion, o.recordExists, o.recordTempFiles)
}

// inTheAsideWindow is the state killWhenAside is named after: the old version is
// wholly in the aside and dest does not exist. FR-024 permits exactly this.
func (o interruptState) inTheAsideWindow() bool { return o.asidePresent && !o.destPresent }

func observeInterrupted(t *testing.T, e *syncEnv) interruptState {
	t.Helper()
	dest := filepath.Join(e.skillsRoot(), interruptedDir)
	o := interruptState{}
	o.destVersion, o.destPresent = installedVersionAt(t, dest)
	o.asideVersion, o.asidePresent = installedVersionAt(t, dest+record.AsideSuffix)

	stagingRoot := layout.StagingRoot(dest)
	if entries, err := os.ReadDir(stagingRoot); err == nil {
		for _, ent := range entries {
			o.staged = append(o.staged, ent.Name())
		}
	}

	recPath := e.recordPath(t)
	if _, err := os.Lstat(recPath); err == nil {
		o.recordExists = true
		rec, lerr := record.Load(recPath, canonicalHubURL(t, e.target.BaseURL))
		require.NoError(t, lerr, "the record left by a killed sync must still be readable: a torn state.json is a defect")
		refs := rec.Refs()
		for i := range refs {
			if refs[i].Entry.ID == interruptedID {
				o.recordVersion = refs[i].Entry.Version
			}
		}
	}
	if entries, err := os.ReadDir(filepath.Dir(recPath)); err == nil {
		for _, ent := range entries {
			if strings.HasPrefix(ent.Name(), "."+record.FileName) {
				o.recordTempFiles = append(o.recordTempFiles, ent.Name())
			}
		}
	}
	return o
}

func canonicalHubURL(t *testing.T, raw string) string {
	t.Helper()
	h, err := ParseHub(raw)
	require.NoError(t, err)
	return h.URL
}

// installedVersionAt reads the FR-022 marker at dir. It is how this file identifies
// WHICH version is at a path without trusting the record, which is the whole
// question in the third case.
func installedVersionAt(t *testing.T, dir string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, layout.MarkerFileName))
	if err != nil {
		if _, serr := os.Lstat(dir); serr == nil {
			return "", true // present, but not a marked entry root
		}
		return "", false
	}
	m, perr := layout.ParseMarker(b)
	require.NoError(t, perr, "a marker written by a killed sync must still parse: it arrives with a single rename")
	return m.Version, true
}

// ---------------------------------------------------------------- "matches the lockfile exactly"

// requireTreeMatchesLockfile is the four-part definition SC-008 is asserted against: the
// right version at the right path, no aside anywhere, no staging anywhere, and a
// record that agrees with the tree.
func requireTreeMatchesLockfile(t *testing.T, e *syncEnv, tg fake.Target, revision int64, want map[string]string) {
	t.Helper()

	// 1. The right version at the right path. The version is read from the
	// installed bytes (SKILL.md, whose body the fake derives from id and
	// version) as well as from the marker, so an install that wrote the marker
	// and not the tree cannot pass.
	require.ElementsMatch(t, interruptWantedDirs(want), skillDirs(t, e.skillsRoot()),
		"the skills root must hold exactly the lockfile's entries")
	for dir, version := range want {
		entry := filepath.Join(e.skillsRoot(), dir)
		body, err := os.ReadFile(filepath.Join(entry, layout.SkillEntryFile))
		require.NoError(t, err)
		require.Contains(t, string(body), "version: "+version,
			"%s holds the wrong version's bytes", dir)
		got, present := installedVersionAt(t, entry)
		require.True(t, present)
		require.Equal(t, version, got, "%s's marker names the wrong version", dir)
	}

	// 2 and 3. No .amctl-old and no .amctl-staging anywhere under the home.
	// Walked, not stat-ed at the two paths this test knows about: a leftover
	// beside an entry this test did not think of is exactly the kind of thing an
	// interrupted run leaves.
	var leftovers []string
	require.NoError(t, filepath.WalkDir(e.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(d.Name(), record.AsideSuffix) || d.Name() == layout.StagingDirName {
			leftovers = append(leftovers, p)
		}
		return nil
	}))
	require.Empty(t, leftovers, "a converged run leaves no aside and no staging directory behind")

	// 4. A record that agrees with the tree, in both directions.
	rec := e.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok, "the profile must be recorded")
	require.Equal(t, int(revision), prof.Revision, "FR-013: the record names the resolved revision")
	require.Len(t, prof.Entries, len(want))
	for i := range prof.Entries {
		entry := &prof.Entries[i]
		version, expected := want[filepath.Base(entry.Dest)]
		require.True(t, expected, "the record claims %s, which the lockfile does not", entry.Dest)
		require.Equal(t, version, entry.Version, "the record disagrees with the tree about %s", entry.ID)
		require.Equal(t, record.TargetClaudeCode, entry.Target)
		onDisk, present := installedVersionAt(t, entry.Dest)
		require.True(t, present, "the record claims %s, which is not on disk", entry.Dest)
		require.Equal(t, version, onDisk)
	}
	require.Empty(t, recordTempFiles(t, e), "record.Save's temp file is unlinked by the run that wrote it, and collected by the next one")
}

func recordTempFiles(t *testing.T, e *syncEnv) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(filepath.Dir(e.recordPath(t)))
	require.NoError(t, err)
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), "."+record.FileName) {
			out = append(out, ent.Name())
		}
	}
	return out
}

func interruptWantedDirs(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// requireLockWasLeftByTheKilledChild is the negative control for "the kill did
// not wedge the machine": if the lock file were absent, a re-run that acquired
// the lock would prove nothing at all.
func requireLockWasLeftByTheKilledChild(t *testing.T, e *syncEnv, run killedChild) {
	t.Helper()
	home := Home{UserHome: e.home, Var: homeEnvVar(), Root: filepath.Join(e.home, DirName)}
	require.FileExists(t, home.LockPath(),
		"the killed child held the per-home lock and could not release it, so its lock file must still be there")
	holder, _, err := readLock(home.LockPath())
	require.NoError(t, err)
	require.Equal(t, run.pid, holder.PID, "the lock left behind must be the dead child's")
}

// ---------------------------------------------------------------- the attempt loop

// interruptAttempt is one kill and the state it produced.
type interruptAttempt struct {
	env   *syncEnv
	run   killedChild
	state interruptState
	hit   bool
}

const interruptAttemptLimit = 12

// killUntil runs prep-then-kill until `want` reports the state the caller is
// after, and asserts the re-run on EVERY attempt via requireTheReRunConverges.
// Every attempt is a full, independent world, so a "wasted" attempt is not
// wasted: it is another interruption point, and its re-run is asserted just as
// hard as the one the test is named after.
//
// between, when given, runs after the kill and before the re-run. It is how the
// one window a watcher cannot land in is REACHED rather than raced for; see
// TestTheWindowWhereTheDestinationIsAbsentConvergesByReclaimingTheAside.
//
// mustHit false means "try, report where it landed, and assert the re-run from
// wherever that was" — for a state this machine cannot produce on demand.
func killUntil(
	t *testing.T,
	tg fake.Target,
	mode interruptMode,
	prep func(*testing.T, *syncEnv),
	flags syncFlags,
	version string,
	want func(interruptState) bool,
	mustHit bool,
	between func(*testing.T, interruptAttempt),
) interruptAttempt {
	t.Helper()
	attempts := interruptAttemptLimit
	if !mustHit {
		attempts = 3
	}
	var last interruptAttempt
	for i := 1; i <= attempts; i++ {
		env := newSyncEnv(t, tg)
		if prep != nil {
			prep(t, env)
		}
		run := spawnKilledSync(t, env, mode, flags, version)
		if run.survived {
			// The child's own diagnostics, because the interesting case is a
			// survival caused by the sync failing for an unrelated reason rather
			// than by a slow watcher, and the two look identical from here.
			t.Logf("attempt %d: the watcher never fired and the sync completed; retrying. The child said:\n%s", i, run.output)
			continue
		}
		state := observeInterrupted(t, env)
		last = interruptAttempt{env: env, run: run, state: state, hit: want(state)}
		t.Logf("attempt %d: killed with %s (state under test: %t)", i, state, last.hit)

		requireLockWasLeftByTheKilledChild(t, env, run)
		if between != nil {
			between(t, last)
		}
		requireTheReRunConverges(t, tg, env)
		if last.hit {
			return last
		}
	}
	if mustHit {
		t.Fatalf("%d attempts never produced the state under test; the last was %s", attempts, last.state)
	}
	return last
}

// requireTheReRunConverges is the answer to "what does a re-run do from here",
// for every state a kill in this file can leave. It is one function and not a
// per-test callback deliberately: the interruption point an attempt hits is
// decided by a race, so the assertions have to be indexed by the state on disk
// rather than by the test's intent, and writing them once means an attempt that
// missed its window still proves something rather than being retried away.
//
// The states, and they are exhaustive over what these three modes can produce:
//
//	dest absent, no aside            killed at or before staging     -> converges unforced
//	dest absent, aside holds old     R3's step 2 -> step 3 window    -> converges unforced, by RECLAIM
//	dest new, record has no row      swap done, first record write   -> converges unforced, by MARKER
//	dest new, record still says old  swap done, record write of an
//	                                 UPGRADE                         -> REFUSES; see the comment there
//	dest new, record says new        killed after the record write   -> converges unforced
func requireTheReRunConverges(t *testing.T, tg fake.Target, env *syncEnv) {
	t.Helper()
	unforced := syncFlags{profiles: []string{tg.Fixtures.Profile}}
	newVersion, oldVersion := headRevisionTree[interruptedDir], priorRevisionTree[interruptedDir]
	// Re-observed here rather than carried from the attempt, because `between` may
	// have moved the tree on to the state under test since.
	state := observeInterrupted(t, env)

	switch {
	case state.inTheAsideWindow():
		started := time.Now()
		code, _, diag, err := runInterrupted(t, env, unforced)
		require.NoError(t, err, diag.String())
		require.Equal(t, CodeChanged, code)
		requireTheLockWasNotWaitedOut(t, started)

		// The two diagnostics that separate "converged" from "converged for the
		// wrong reason": the guard saw a destination the record claims and
		// nothing on disk, and Swap step 1 moved the old version BACK before
		// replacing it, rather than installing over an absent destination.
		require.Contains(t, diag.String(), "but nothing is there; re-installing")
		require.Contains(t, diag.String(), "reclaimed",
			"R3 step 1 must reclaim the aside: it holds the only copy of the version the record claims")
		require.NotContains(t, diag.String(), "--force",
			"an ABSENT destination needs no override; the modification guard has nothing to verify")
		requireTreeMatchesLockfile(t, env, tg, tg.Fixtures.HeadRevision, headRevisionTree)

	case state.destVersion == newVersion && state.recordVersion == oldVersion:
		requireAnInterruptedUpgradeConvergesWithoutForce(t, tg, env)

	case state.destVersion == newVersion && state.recordVersion == "":
		code, _, diag, err := runInterrupted(t, env, unforced)
		require.NoError(t, err, diag.String())
		require.Equal(t, CodeChanged, code)
		require.Contains(t, diag.String(), "interrupted between the install and the record write",
			"the FR-022 marker is the only thing on disk that can say this directory is amctl's own leftover")
		require.NotContains(t, diag.String(), "should be removed",
			"a tree the record does not claim is re-installed, never pruned (FR-028)")
		requireTreeMatchesLockfile(t, env, tg, tg.Fixtures.HeadRevision, headRevisionTree)

	default:
		started := time.Now()
		code, _, diag, err := runInterrupted(t, env, unforced)
		require.NoError(t, err, diag.String())
		require.Equal(t, CodeChanged, code)
		requireTheLockWasNotWaitedOut(t, started)
		requireTreeMatchesLockfile(t, env, tg, tg.Fixtures.HeadRevision, headRevisionTree)
		require.NoFileExists(t, filepath.Join(env.home, DirName, LockFileName),
			"the re-run must release the lock it reclaimed")
	}
}

// requireAnInterruptedUpgradeConvergesWithoutForce was THE FINDING, and is now
// the fix's regression test.
//
// The killed run finished the swap of an UPGRADE and died before the record
// write, so the tree holds the new version and the record row still names the
// old one. As first written, the re-run REFUSED that entry forever: the record
// row makes it an upgrade, apply.verifyUnmodified demands a positive unmodified
// verdict for the version the record names, the entry carries no install
// fingerprint, and absence of evidence is deliberately not evidence of absence.
// So `sync` exited non-zero on a machine whose tree was already correct, until a
// human passed --force.
//
// It was never merely the missing T049 fingerprinter. With one wired, the
// recorded fingerprint would be the OLD version's and the tree the NEW version's,
// so every file would read as modified and the refusal would become ErrModified
// — a refusal saying "you modified these files" about amctl's own finished
// install.
//
// The real gap was that apply.guard's `From != nil` path never consulted the
// FR-022 marker, while the `From == nil` path three lines above did exactly
// that. A marker whose ID, Target AND Version all equal the change being
// installed is proof of amctl's own completed install of that very version, and
// consulting it there costs nothing anywhere else: the marker still influences
// only an OVERWRITE, never a removal, so FR-028 is untouched.
func requireAnInterruptedUpgradeConvergesWithoutForce(t *testing.T, tg fake.Target, env *syncEnv) {
	t.Helper()
	unforced := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	code, _, diag, err := runInterrupted(t, env, unforced)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	require.Contains(t, diag.String(), "interrupted between the install and the record write",
		"the FR-022 marker is the only thing on disk that can say the tree is amctl's own leftover")
	require.NotContains(t, diag.String(), "--force",
		"a tree that is already correct must not send the operator to --force")
	require.NotContains(t, diag.String(), "should be removed",
		"whatever else it does, a record/tree disagreement must never be read as a removal")

	// Both halves converge: the tree is the lockfile's, and so is the record.
	requireTreeMatchesLockfile(t, env, tg, tg.Fixtures.HeadRevision, headRevisionTree)
	require.Equal(t, headRevisionTree[interruptedDir], recordedVersion(t, env, tg, interruptedID),
		"the record must catch up to the tree, which is the whole point of the fix")

	// And it is idempotent: a second re-run has nothing left to do.
	code, _, diag, err = runInterrupted(t, env, unforced)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code, "the first re-run converged, so the second changes nothing")
}

// requireTheLockWasNotWaitedOut is the second half of "the kill did not wedge
// the machine". The first half is requireLockWasLeftByTheKilledChild: the dead
// child's lock file is still there, so the re-run genuinely had to deal with it.
//
// The ANSWER to "how long did the re-run have to wait" is "it did not wait at
// all, and it must not": Acquire never blocks — FR-038 refuses a live holder
// rather than queueing — so the only two outcomes are an immediate reclaim under
// the dead-pid rule and an immediate ErrLocked. require.NoError on the re-run is
// therefore already the whole assertion; this bound exists so that a future
// Acquire that DID wait out the staleness window would fail here instead of
// making every one of these tests 90 seconds slower and still green.
func requireTheLockWasNotWaitedOut(t *testing.T, started time.Time) {
	t.Helper()
	elapsed := time.Since(started)
	t.Logf("  re-run took %s, lock included; lockStaleAfter is %s and the pid rule is what makes the difference",
		elapsed, lockStaleAfter)
	require.Less(t, elapsed, lockStaleAfter/3,
		"a re-run that took a third of the staleness window has probably waited the dead holder out rather than reclaiming it")
}

func recordedVersion(t *testing.T, e *syncEnv, tg fake.Target, id string) string {
	t.Helper()
	rec := e.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	for i := range prof.Entries {
		if prof.Entries[i].ID == id {
			return prof.Entries[i].Version
		}
	}
	return ""
}

// ---------------------------------------------------------------- case 1: killed at staging

// A kill after the staged tree is complete and before R3's step 2 leaves the
// destination untouched, nothing recorded, and a staged tree behind. The re-run
// converges and leaves no staging directory.
func TestAKillWhileTheStagedTreeIsCompleteConvergesOnAReRun(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	flags := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	// The watched entry is the FIRST entry the plan writes (Writes() sorts by
	// target then id), so the state this case is named after is: a staged tree
	// present, nothing installed, and no record file at all.
	a := killUntil(t, tg, killWhenStaged, nil, flags, headRevisionTree[interruptedDir], func(o interruptState) bool {
		return len(o.staged) > 0 && !o.destPresent && !o.recordExists
	}, true, nil)
	require.False(t, a.state.asidePresent, "there was no old version, so step 2 had nothing to move aside")
	require.Len(t, a.state.staged, 1, "one entry was being staged, so exactly one digest-named tree is left")
}

// ---------------------------------------------------------------- case 2: the one window where dest is absent

// R3's step 2 -> step 3: the old version is wholly in the aside and the
// destination does not exist. FR-024 permits this state explicitly, so what is
// asserted is that a re-run CONVERGES — and that it converges by RECLAIMING the
// aside, which is the only path that does not destroy the version the record
// still claims.
//
// THIS STATE IS REACHED, NOT RACED FOR, AND THE MEASUREMENT IS WHY.
// The userspace distance between swap.go's step 2 and step 3 is one error check:
// 21ns mean, 42ns worst, measured on this machine (go1.26.6, linux/arm64,
// go run over 500 rounds). One iteration of the cheapest watcher this file can
// write — a dirfd-relative Root.Lstat of a single-component name — costs 355ns.
// The window is seventeen times narrower than one poll, so a watcher cannot see
// it, and every real kill aimed at it landed one syscall later, between steps 3
// and 5 — 24 of them, see the file header. That is not a state this file skips:
// the late one is asserted too, by
// TestARealKillAimedAtTheAsideWindowLandsOneSyscallLateAndStillConverges.
//
// So the state is assembled from a real killed sync plus ONE syscall: a real
// child is SIGKILLed with its staged tree complete (the previous case's
// mechanism), and then this test performs R3's own step 2 —
// os.Rename(dest, dest+AsideSuffix) — on the tree that dead process left behind.
// Everything else is the killed process's: the staged new version, the record
// still naming the old one, the lock file it could not release. Rename is atomic,
// so this is not an approximation of the state between the two steps; it IS that
// state, and there is no other state step 2 can leave.
//
// What it does not cover: that swap.go's own step 2 produces this state. That is
// internal/apply/swap_test.go's R3 gate, which measured the sequence directly.
func TestTheWindowWhereTheDestinationIsAbsentConvergesByReclaimingTheAside(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	requireFixturesStillSay(t, tg, fmt.Sprint(tg.Fixtures.PriorRevision), priorRevisionTree)

	a := killUntil(t, tg, killWhenStaged, installPriorRevisionFirst(tg), killedUpgradeFlags(tg), headRevisionTree[interruptedDir],
		func(o interruptState) bool {
			// Killed with the new version staged and the OLD version still at
			// dest: precisely the instant before step 2.
			return len(o.staged) == 1 && o.destVersion == priorRevisionTree[interruptedDir] && !o.asidePresent
		}, true,
		func(t *testing.T, a interruptAttempt) {
			dest := filepath.Join(a.env.skillsRoot(), interruptedDir)
			require.NoError(t, os.Rename(dest, dest+record.AsideSuffix),
				"R3 step 2, performed by the test: this is the one syscall of this state that the killed process did not make")
		})

	require.Equal(t, priorRevisionTree[interruptedDir], a.state.destVersion)
	require.Equal(t, priorRevisionTree[interruptedDir], a.state.recordVersion,
		"the record claims the old version, which is exactly why step 1 must reclaim the aside rather than discard it")
}

// TestARealKillAimedAtTheAsideWindowLandsOneSyscallLateAndStillConverges is the
// measurement behind the test above, kept as a test rather than as a comment: a
// watcher spinning on the aside's appearance does fire, the process does die of
// SIGKILL, and where it dies is one syscall past the window every time — after
// step 3, before step 5's RemoveAll, which is a real interruption point of its
// own and one nothing else in this file aims at.
//
// It is not required to hit the window (mustHit false). If a future machine,
// kernel or Go release does land it there, requireTheReRunConverges asserts the
// reclaim path for it automatically and nothing here has to change.
func TestARealKillAimedAtTheAsideWindowLandsOneSyscallLateAndStillConverges(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, fmt.Sprint(tg.Fixtures.PriorRevision), priorRevisionTree)

	a := killUntil(t, tg, killWhenAside, installPriorRevisionFirst(tg), killedUpgradeFlags(tg), headRevisionTree[interruptedDir],
		interruptState.inTheAsideWindow, false, nil)

	switch {
	case a.state.inTheAsideWindow():
		t.Log("this machine CAN land the step 2 -> step 3 window; requireTheReRunConverges asserted the reclaim path for it")
	case a.state.asidePresent:
		require.Equal(t, headRevisionTree[interruptedDir], a.state.destVersion,
			"one syscall late: step 3 completed, so the new version is at dest and step 5 had not removed the aside yet")
	default:
		require.Equal(t, headRevisionTree[interruptedDir], a.state.destVersion,
			"later still: steps 3 to 5 completed and the record write had not, which is case 3b's state")
	}
}

// ---------------------------------------------------------------- case 3a: killed between swap and record

// The tree is new and the record does not mention the entry at all. This is what
// the FR-022 marker exists for: apply.guard adopts a destination carrying amctl's
// own marker for the same id and target, warns, and re-installs. It does not read
// "the record does not claim this, therefore somebody else's, therefore refuse",
// and it does not read "drift, therefore remove".
func TestAKillBetweenTheSwapAndTheRecordWriteIsAdoptedByItsMarker(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	flags := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	a := killUntil(t, tg, killWhenInstalled, nil, flags, headRevisionTree[interruptedDir], func(o interruptState) bool {
		return o.destVersion == headRevisionTree[interruptedDir] && o.recordVersion == ""
	}, true, nil)
	require.False(t, a.state.asidePresent, "a fresh install has no old version to leave aside")
}

// ---------------------------------------------------------------- case 3b: the same kill, on an UPGRADE

// The subtle one: the tree is NEW and the record still says OLD. The assertions
// and the finding are in requireARecordThatLagsBehindTheTreeNeedsForce; this test
// is what produces the state.
func TestAKillBetweenTheSwapAndTheRecordWriteOfAnUpgradeConverges(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	requireFixturesStillSay(t, tg, fmt.Sprint(tg.Fixtures.PriorRevision), priorRevisionTree)

	killUntil(t, tg, killWhenInstalled, installPriorRevisionFirst(tg), killedUpgradeFlags(tg), headRevisionTree[interruptedDir],
		func(o interruptState) bool {
			return o.destVersion == headRevisionTree[interruptedDir] && o.recordVersion == priorRevisionTree[interruptedDir]
		}, true, nil)
}

// ---------------------------------------------------------------- shared scenario pieces

// killedUpgradeFlags is the KILLED run's flags for every upgrade case, and --force is
// not decoration: this build wires no Fingerprinter (internal/cmd/sync.go says so
// in as many words; T049 is unwritten), so apply.verifyUnmodified refuses EVERY
// upgrade of an entry that was installed without one. An upgrade is the only
// change whose swap has an aside at all, so without --force there is no way to
// reach R3's step 2 in this build. Every RE-RUN in this file is unforced, which is
// the half that is being tested.
func killedUpgradeFlags(tg fake.Target) syncFlags {
	return syncFlags{profiles: []string{tg.Fixtures.Profile}, force: true}
}

// installPriorRevisionFirst syncs the older revision, so that the head sync that gets
// killed is an UPGRADE of the watched entry rather than a fresh install.
func installPriorRevisionFirst(tg fake.Target) func(*testing.T, *syncEnv) {
	return func(t *testing.T, e *syncEnv) {
		t.Helper()
		code, _, diag, err := runInterrupted(t, e, syncFlags{
			profiles:  []string{tg.Fixtures.Profile},
			revisions: []string{fmt.Sprint(tg.Fixtures.PriorRevision)},
		})
		require.NoError(t, err, diag.String())
		require.Equal(t, CodeChanged, code)
		require.Equal(t, []string{interruptedDir}, skillDirs(t, e.skillsRoot()))
		require.Equal(t, priorRevisionTree[interruptedDir], recordedVersion(t, e, tg, interruptedID))
	}
}

// ---------------------------------------------------------------- the fixtures are still what this file thinks

// requireFixturesStillSay re-derives priorRevisionTree and headRevisionTree from the lockfile the
// hub actually serves, through the hub client rather than through the install
// path. Without it a fixture change would leave these tests asserting a tree that
// matches a stale expectation, which is the failure mode of every hand-written
// table.
func requireFixturesStillSay(t *testing.T, tg fake.Target, revision string, want map[string]string) {
	t.Helper()
	client, err := hub.New(hub.Config{
		URL:            tg.BaseURL,
		Token:          tg.Token,
		AllowPlaintext: true,
		HTTPClient:     tg.HTTPClient,
		UserAgent:      "amctl-t046",
	})
	require.NoError(t, err)
	lf, err := client.GetRevision(context.Background(), tg.Fixtures.Profile, revision)
	require.NoError(t, err)

	got := map[string]string{}
	for i := range lf.Entries {
		pkg, perr := layout.ParsePackageID(lf.Entries[i].Id)
		require.NoError(t, perr)
		got[pkg.DirName()] = lf.Entries[i].Version
	}
	require.Equal(t, want, got, "revision %s of %s is not what this file's table says", revision, tg.Fixtures.Profile)
}
