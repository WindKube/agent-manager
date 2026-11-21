// This file checks the install tree after a sync is killed mid-flight and re-run.
//
// The killed run is a real child process (this test binary in helper mode)
// that SIGKILLs itself, so no defer, rollback or lock release runs; an injected
// error would leave a state a crash cannot produce. A watcher goroutine in the
// child spins on lstat and kills the process when the tree reaches the target
// state, needing no production hook.
//
// The three points are the swap's steps: killWhenStaged (staged tree complete,
// dest untouched), killWhenAside (between steps 2 and 3, dest absent; ~21ns wide,
// narrower than one watcher poll, so it is reached by one rename of the test's
// own instead), and killWhenInstalled (after step 3, before the record write).
//
// Not covered: power loss, which needs dm-log-writes or a VM reset loop.
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

// The bearer token travels in a 0600 file, never in the environment: a child's
// environment is dumped by debuggers, `ps -E` and crash reporters.
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

// childSurvivedMarker is printed when runSync returned, i.e. the watcher never
// fired; the parent treats it as a missed attempt, never a kill.
const childSurvivedMarker = "AMCTL_T046_CHILD_SURVIVED"

type interruptMode string

const (
	killWhenStaged    interruptMode = "staged"
	killWhenAside     interruptMode = "aside"
	killWhenInstalled interruptMode = "installed"
)

// interruptClock is shared by parent and child so records cannot differ by a timestamp.
var interruptClock = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

// Hand-derived from internal/hub/fake's catalog; requireFixturesStillSay
// re-derives them from the served lockfile so a fixture change can't make these
// tests vacuous.
var (
	priorRevisionTree = map[string]string{"acme--code-review": "2.4.0"}
	headRevisionTree  = map[string]string{
		"acme--code-review":   "2.4.1",
		"acme--lint-guard":    "1.0.3",
		"example--doc-writer": "0.9.0",
	}
)

// interruptedDir is the one entry in both revisions, so the only one whose swap has an aside.
const (
	interruptedDir = "acme--code-review"
	interruptedID  = "acme/code-review"
)

// TestSyncInterruptHelperProcess is not a test: it is the killed run. It
// registers no cleanup, since this process is expected to die between two syscalls.
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
		// Plaintext: the fake's self-signed certificate cannot cross a process
		// boundary, and an InsecureSkipVerify client would be a weaker TLS path.
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

	// GC off removes a source of jitter from every window at no cost; it did not
	// make the aside window catchable.
	debug.SetGCPercent(-1)
	armKiller(interruptMode(mode), os.Getenv(interruptDestEnv), os.Getenv(interruptVerEnv))
	err = runSync(context.Background(), opts, flags, deps)
	fmt.Fprintf(os.Stderr, "%s err=%v\n", childSurvivedMarker, err)
}

// childLookupEnv hands the sync its credential without putting it in the process environment.
func childLookupEnv(token string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == credentials.TokenEnvVar {
			return token, true
		}
		return "", false
	}
}

// armKiller starts the watcher goroutines, each spinning on its own predicate
// and pinned with LockOSThread, and SIGKILLs this process when one fires.
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

// newInterruptPredicate returns a fresh closure with its own file handles, so watchers share nothing.
func newInterruptPredicate(mode interruptMode, dest, version string) func() bool {
	switch mode {
	case killWhenStaged:
		// The marker is what Stage writes last, so its presence means the staged tree is complete.
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
		// The aside exists only between steps 2 and 5, so firing on it is the
		// earliest possible instant; the parent decides from disk whether the window was hit.
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
		// A marker naming the new version means only the record write is outstanding.
		// Parsed, so an unparseable marker never reads as a version.
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

// startInterruptFake starts the fake over http, since the child cannot use TLS.
func startInterruptFake(t *testing.T) fake.Target {
	t.Helper()
	h := fake.New(fake.Options{})
	t.Cleanup(h.Close)
	return h.Target()
}

// runInterrupted is verbose because the reclaim and marker-adoption proofs are Debugf lines.
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
	// Outside the HOME under test.
	path := filepath.Join(t.TempDir(), "cred")
	require.NoError(t, os.WriteFile(path, []byte(token), 0o600))
	return path
}

type killedChild struct {
	pid      int
	output   string
	survived bool
	exitCode int
}

// spawnKilledSync returns once the child is reaped: a zombie pid answers
// "alive", so the re-run would refuse with ErrLocked.
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
	require.Equal(t, -1, run.exitCode,
		"exit code -1 is os/exec's report of death by signal; anything else means the process unwound, and an unwound process runs defers")
	return run
}

// interruptState decides which interruption point an attempt actually hit.
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

// installedVersionAt reads the marker at dir, identifying the version without trusting the record.
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

// requireTreeMatchesLockfile asserts a converged tree: right version at the
// right path, no aside, no staging, and a record that agrees.
func requireTreeMatchesLockfile(t *testing.T, e *syncEnv, tg fake.Target, revision int64, want map[string]string) {
	t.Helper()

	// Read from SKILL.md as well as the marker, so a marker without the tree cannot pass.
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

	// Walked, not stat-ed at known paths, so a leftover anywhere is caught.
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

	// A record that agrees with the tree, in both directions.
	rec := e.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok, "the profile must be recorded")
	require.Equal(t, int(revision), prof.Revision, "the record names the resolved revision")
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

// Negative control: without the dead child's lock still present, a re-run acquiring it proves nothing.
func requireLockWasLeftByTheKilledChild(t *testing.T, e *syncEnv, run killedChild) {
	t.Helper()
	home := Home{UserHome: e.home, Var: homeEnvVar(), Root: filepath.Join(e.home, DirName)}
	require.FileExists(t, home.LockPath(),
		"the killed child held the per-home lock and could not release it, so its lock file must still be there")
	holder, _, err := readLock(home.LockPath())
	require.NoError(t, err)
	require.Equal(t, run.pid, holder.PID, "the lock left behind must be the dead child's")
}

type interruptAttempt struct {
	env   *syncEnv
	run   killedChild
	state interruptState
	hit   bool
}

const interruptAttemptLimit = 12

// killUntil runs prep-then-kill until want matches, asserting the re-run on
// every attempt, so a missed window still proves something. between runs after
// the kill to reach the window a watcher cannot land in; mustHit false accepts
// wherever the kill landed.
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
			// A survival may be the sync failing for an unrelated reason, so show the child's output.
			t.Logf("attempt %d: the watcher never fired and the sync completed; retrying. The child said:\n%s", i, run.output)
			continue
		}
		state := observeInterrupted(t, env)
		last = interruptAttempt{env: env, run: run, state: state, hit: want(state)}
		t.Logf("attempt %d: killed with %s (state under test: %t)", i, state, last.hit)

		requireLockWasLeftByTheKilledChild(t, env, run)
		// Only on a hit: `between` on an overshot tree builds a state nobody
		// describes (the re-run is a no-op), which was a CI flake.
		if between != nil && last.hit {
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

// requireTheReRunConverges asserts by the state on disk rather than by the
// test's intent, since which point a kill hit is a race:
//
//	dest absent, no aside            killed at or before staging     -> converges
//	dest absent, aside holds old     step 2 -> step 3 window         -> converges, by reclaim
//	dest new, record has no row      swap done, first record write   -> converges, by marker
//	dest new, record still says old  swap done, upgrade record write -> converges, by marker
//	dest new, record says new        killed after the record write   -> converges
func requireTheReRunConverges(t *testing.T, tg fake.Target, env *syncEnv) {
	t.Helper()
	unforced := syncFlags{profiles: []string{tg.Fixtures.Profile}}
	newVersion, oldVersion := headRevisionTree[interruptedDir], priorRevisionTree[interruptedDir]
	// Re-observed: `between` may have moved the tree since the attempt.
	state := observeInterrupted(t, env)

	switch {
	case state.inTheAsideWindow():
		started := time.Now()
		code, _, diag, err := runInterrupted(t, env, unforced)
		require.NoError(t, err, diag.String())
		require.Equal(t, CodeChanged, code)
		requireTheLockWasNotWaitedOut(t, started)

		// These separate "converged" from "converged for the wrong reason": the guard
		// saw the claimed destination missing, and the swap restored the aside first.
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
			"the marker is the only thing on disk that can say this directory is amctl's own leftover")
		require.NotContains(t, diag.String(), "should be removed",
			"a tree the record does not claim is re-installed, never pruned")
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

// requireAnInterruptedUpgradeConvergesWithoutForce: the tree holds the new
// version and the record the old. A marker matching the change's ID, Target and
// Version proves amctl's own completed install, so the re-run must not demand
// --force for it.
func requireAnInterruptedUpgradeConvergesWithoutForce(t *testing.T, tg fake.Target, env *syncEnv) {
	t.Helper()
	unforced := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	code, _, diag, err := runInterrupted(t, env, unforced)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	require.Contains(t, diag.String(), "interrupted between the install and the record write",
		"the marker is the only thing on disk that can say the tree is amctl's own leftover")
	require.NotContains(t, diag.String(), "--force",
		"a tree that is already correct must not send the operator to --force")
	require.NotContains(t, diag.String(), "should be removed",
		"whatever else it does, a record/tree disagreement must never be read as a removal")

	requireTreeMatchesLockfile(t, env, tg, tg.Fixtures.HeadRevision, headRevisionTree)
	require.Equal(t, headRevisionTree[interruptedDir], recordedVersion(t, env, tg, interruptedID),
		"the record must catch up to the tree, which is the whole point of the fix")

	// Idempotent: a second re-run has nothing left to do.
	code, _, diag, err = runInterrupted(t, env, unforced)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code, "the first re-run converged, so the second changes nothing")
}

// requireTheLockWasNotWaitedOut fails if a future Acquire waits out the
// staleness window instead of reclaiming a dead holder's lock at once.
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

// A kill after staging and before step 2 leaves dest untouched and a staged
// tree behind; the re-run converges and cleans it up.
func TestAKillWhileTheStagedTreeIsCompleteConvergesOnAReRun(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	flags := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	// The watched entry is the first the plan writes, so the target state is a
	// staged tree with nothing installed and no record.
	a := killUntil(t, tg, killWhenStaged, nil, flags, headRevisionTree[interruptedDir], func(o interruptState) bool {
		return len(o.staged) > 0 && !o.destPresent && !o.recordExists
	}, true, nil)
	require.False(t, a.state.asidePresent, "there was no old version, so step 2 had nothing to move aside")
	require.Len(t, a.state.staged, 1, "one entry was being staged, so exactly one digest-named tree is left")
}

// The step 2 -> 3 window is too narrow for a watcher, so it is assembled from
// a real kill with the staged tree complete plus the swap's own step 2
// (os.Rename(dest, dest+AsideSuffix)). Rename is atomic, so this is that state,
// not an approximation. The re-run must converge by reclaiming the aside.
func TestTheWindowWhereTheDestinationIsAbsentConvergesByReclaimingTheAside(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	requireFixturesStillSay(t, tg, fmt.Sprint(tg.Fixtures.PriorRevision), priorRevisionTree)

	a := killUntil(t, tg, killWhenStaged, installPriorRevisionFirst(tg), killedUpgradeFlags(tg), headRevisionTree[interruptedDir],
		func(o interruptState) bool {
			// Killed with the new version staged and the old still at dest: just before step 2.
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

// A watcher aimed at the aside window fires one syscall late (after step 3,
// before step 5), itself a real interruption point. mustHit is false: if a
// future machine does land in the window, the reclaim path is asserted automatically.
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

// The tree is new and the record does not mention the entry: apply.guard must
// adopt a destination carrying amctl's own marker, not refuse or remove it.
func TestAKillBetweenTheSwapAndTheRecordWriteIsAdoptedByItsMarker(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	flags := syncFlags{profiles: []string{tg.Fixtures.Profile}}

	a := killUntil(t, tg, killWhenInstalled, nil, flags, headRevisionTree[interruptedDir], func(o interruptState) bool {
		return o.destVersion == headRevisionTree[interruptedDir] && o.recordVersion == ""
	}, true, nil)
	require.False(t, a.state.asidePresent, "a fresh install has no old version to leave aside")
}

// The tree is new and the record still says old; see
// requireAnInterruptedUpgradeConvergesWithoutForce.
func TestAKillBetweenTheSwapAndTheRecordWriteOfAnUpgradeConverges(t *testing.T) {
	tg := startInterruptFake(t)
	requireFixturesStillSay(t, tg, revisionHead, headRevisionTree)
	requireFixturesStillSay(t, tg, fmt.Sprint(tg.Fixtures.PriorRevision), priorRevisionTree)

	killUntil(t, tg, killWhenInstalled, installPriorRevisionFirst(tg), killedUpgradeFlags(tg), headRevisionTree[interruptedDir],
		func(o interruptState) bool {
			return o.destVersion == headRevisionTree[interruptedDir] && o.recordVersion == priorRevisionTree[interruptedDir]
		}, true, nil)
}

// killedUpgradeFlags forces the killed run; every re-run is unforced, which is the half under test.
func killedUpgradeFlags(tg fake.Target) syncFlags {
	return syncFlags{profiles: []string{tg.Fixtures.Profile}, force: true}
}

// installPriorRevisionFirst makes the killed head sync an upgrade, the only change whose swap has an aside.
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

// requireFixturesStillSay re-derives the fixture trees from the lockfile the hub
// serves, so a fixture change can't leave these tests asserting a stale table.
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
