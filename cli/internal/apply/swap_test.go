// R3 GATE — task T011. DO NOT DELETE THIS FILE AS A DUPLICATE OF T041's TESTS.
//
// This file is a *gate*, not a unit test of production code. `swap.go` (task
// T041) does not exist yet, and T011 exists precisely so that T041 is written
// against a measured sequence rather than a guess. Everything below therefore
// exercises the rename sequence directly against the filesystem through
// `gateSwap`, a helper local to this file. That is deliberate:
//
//   - it proves the sequence is sound on the platform the test runs on, and
//   - it pins the exact ordering, the exact aside-name derivation, and the
//     exact per-step interruption outcomes that T041 must reproduce.
//
// When T041 lands it MUST keep this file. `gateSwap` is the specification;
// `swap.go` is the implementation. Two independent statements of the same
// sequence are worth their duplication — a test that only calls the code under
// test cannot notice that the code changed the ordering, because it changed
// with it. T041 should additionally assert that swap.go's own aside suffix
// equals gateAsideSuffix, so the two cannot drift apart silently.
//
// The property being established is FR-024: a crash at ANY step of an entry's
// replacement leaves the destination wholly the old version or wholly the new
// (or absent, which FR-024 explicitly permits) — never a mixture.
//
// The findings, the numbered sequence, and the per-platform unverified list are
// written up in specs/002-agent-manager-cli/ R3 notes; the short version lives
// in the comments on gateSwap below.

package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// gateAsideSuffix is appended to the destination path to name the place the old
// version is moved to. Two properties of this name are load-bearing and are
// asserted by TestR3AsideNameIsASiblingDerivedFromTheDestination:
//
//   - It is DERIVED DETERMINISTICALLY from the destination, not randomised.
//     The installation record stores destination paths (FR-026), so a
//     deterministic suffix means the set of paths amctl may ever remove is
//     exactly {dest, dest+suffix} for each recorded entry. FR-028 ("MUST NOT
//     remove any path absent from its own record") then holds by construction
//     rather than by care: cleanup is a walk of the record, never a glob over a
//     directory amctl does not own. A random token would force a glob.
//   - It is a SIBLING of the destination, in the same parent directory. Step 2
//     is then guaranteed to be an intra-filesystem rename, which a central
//     `~/.agent-manager/trash/` would not be — see the EXDEV test.
//
// The caller must guarantee no package ever legitimately installs to a path
// ending in this suffix. internal/layout owns that guarantee.
const gateAsideSuffix = ".amctl-old"

// gateStep numbers the sequence. The numbering is the deliverable: T041 must
// implement these steps in this order, and a crash immediately after step N
// must leave the observable state this file asserts for N.
type gateStep int

const (
	gateStepNone      gateStep = 0 // nothing done yet
	gateStepReclaimed gateStep = 1 // a leftover aside has been reclaimed or discarded
	gateStepAsided    gateStep = 2 // the old version has been renamed aside
	gateStepMovedIn   gateStep = 3 // the staged tree has been renamed into place
	gateStepSynced    gateStep = 4 // the destination's parent directory has been fsynced
	gateStepComplete  gateStep = 5 // the aside has been removed
)

func (s gateStep) String() string {
	switch s {
	case gateStepNone:
		return "before step 1 (nothing done)"
	case gateStepReclaimed:
		return "after step 1 (leftover aside reclaimed)"
	case gateStepAsided:
		return "after step 2 (old renamed aside)"
	case gateStepMovedIn:
		return "after step 3 (new renamed in)"
	case gateStepSynced:
		return "after step 4 (parent fsynced)"
	case gateStepComplete:
		return "after step 5 (aside removed)"
	}
	return fmt.Sprintf("gateStep(%d)", int(s))
}

// errGateInterrupted stands in for the process being killed. It is returned
// *after* the requested step has completed and, unlike a real error, it does
// NOT run step 3's rollback — which is the whole point: a crash cannot roll
// back, so the state it leaves behind is what FR-024 has to hold for.
var errGateInterrupted = errors.New("interrupted")

// gateOutcome carries the two errors the sequence treats as NON-fatal. Both
// happen after the new version is already in place, so failing the entry on
// either would report a failure for an installation that succeeded — the exact
// inversion of "prefer failing closed" that would be wrong here.
type gateOutcome struct {
	SyncDirErr     error // step 4
	RemoveAsideErr error // step 5
}

// gateSwap is THE SEQUENCE. T041 implements this against real entries.
//
// Why not simply os.Rename(staging, dest):
//
// MEASURED, and stronger than plan.md's R3 paragraph claims. plan.md says
// os.Rename "is not atomic for directories on any platform". Through Go's os
// package it is worse than that: it FAILS, empty destination or not.
// $GOROOT/src/os/file_unix.go's rename() Lstats newname first and returns
// EEXIST outright if it is a directory, without ever reaching syscall.Rename.
// Measured on linux/arm64, go1.26.6: os.Rename(dir, EMPTY dir) = EEXIST,
// os.Rename(dir, NON-EMPTY dir) = EEXIST, os.Rename(dir, SYMLINK->dir) =
// ENOTDIR, os.Rename(dir, ABSENT) = nil. Only the last one is usable.
//
// So the aside step is the only way os.Rename installs over anything at all,
// and dest MUST be absent before step 3 runs. The trap this creates is the
// reverse of the one plan.md anticipated: the raw POSIX call is more permissive
// than Go's wrapper (syscall.Rename(dir, EMPTY dir) = nil, measured), so anyone
// "fixing" the EEXIST by dropping to syscall.Rename or golang.org/x/sys gets a
// swap that works for empty destinations and fails with ENOTEMPTY for real
// upgrades. TestR3NaiveRenameOverAnExistingDestination pins all of it.
//
// Why step 2 tolerates ENOENT instead of stat-ing first: a Stat-then-branch
// implementation has two code paths (a three-step swap when no old version
// exists, a five-step swap when one does) and a TOCTOU window between the stat
// and the rename. Tolerating ENOENT collapses both into one path. amctl also
// holds a per-home lock (FR-038), so the only writer that can race here is one
// that is not amctl, which is out of scope and stated as such.
//
// Why step 3 rolls back but a crash does not: FR-015 wants a failed entry to
// "leave the machine unchanged", and after step 2 the machine is changed — dest
// is absent. Rolling back on a step-3 error restores the old version and makes
// the failed entry a true no-op. A crash cannot do that, which is what makes
// step 1 necessary.
//
// Why step 1 RECLAIMS rather than discards: a crash between steps 2 and 3
// leaves dest absent and the aside holding a complete old version (rename is
// atomic, so the aside is never partial). Discarding it destroys the only copy
// of the version the record claims, and if this run then fails at step 3 there
// is nothing to roll back to. Reclaiming restores the invariant "dest holds the
// version the record claims" before the swap begins.
func gateSwap(staging, dest string, stopAfter gateStep) (gateOutcome, error) {
	var out gateOutcome
	aside := dest + gateAsideSuffix

	if stopAfter == gateStepNone {
		return out, errGateInterrupted
	}

	// STEP 1 — reclaim or discard a leftover aside from an earlier interrupted
	// swap. An aside that outlives its swap is a slow leak: nothing else in
	// amctl will ever look at that path.
	if _, err := os.Lstat(aside); err == nil {
		_, destErr := os.Lstat(dest)
		switch {
		case errors.Is(destErr, fs.ErrNotExist):
			if rerr := os.Rename(aside, dest); rerr != nil {
				return out, fmt.Errorf("reclaim leftover %s: %w", aside, rerr)
			}
		default:
			// dest exists, so the aside is a superseded duplicate: a crash
			// after step 3 but before step 5. dest is authoritative.
			if rerr := os.RemoveAll(aside); rerr != nil {
				return out, fmt.Errorf("discard stale %s: %w", aside, rerr)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return out, fmt.Errorf("inspect %s: %w", aside, err)
	}
	if stopAfter == gateStepReclaimed {
		return out, errGateInterrupted
	}

	// STEP 2 — move the old version aside. ENOENT means there was no old
	// version, which is not an error. os.Rename does NOT follow a symlink at
	// dest: the link itself moves, and whatever it pointed at is untouched.
	// That is the behaviour amctl wants — see the symlink tests.
	if err := os.Rename(dest, aside); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return out, fmt.Errorf("move %s aside: %w", dest, err)
	}
	if stopAfter == gateStepAsided {
		return out, errGateInterrupted
	}

	// STEP 3 — move the staged tree into place. dest is absent at this point,
	// so this is the one rename that must succeed, and it succeeds on all three
	// platforms only because dest is absent.
	if err := os.Rename(staging, dest); err != nil {
		if _, serr := os.Lstat(dest); errors.Is(serr, fs.ErrNotExist) {
			if rerr := os.Rename(aside, dest); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				return out, fmt.Errorf(
					"move staged tree into %s: %w (rollback of %s failed too: %w)", dest, err, aside, rerr)
			}
		}
		return out, fmt.Errorf("move staged tree into %s: %w", dest, err)
	}
	if stopAfter == gateStepMovedIn {
		return out, errGateInterrupted
	}

	// STEP 4 — fsync the destination's PARENT directory, so the directory entry
	// created by step 3 survives a power loss. NON-FATAL: see gateOutcome.
	//
	// This does NOT make the entry durable on its own. rename is a metadata
	// operation; the file *contents* staged in step 0 may still be in page
	// cache, and on a delayed-allocation filesystem a power loss here yields a
	// destination directory full of zero-length files — which is exactly the
	// "mixture" FR-024 forbids. Durability of the staged CONTENT is T040's
	// (stage) job: every extracted file must be fsynced before the staging tree
	// is handed to the swap. Durability of the directory ENTRY is this step's.
	out.SyncDirErr = gateSyncDir(filepath.Dir(dest))
	if stopAfter == gateStepSynced {
		return out, errGateInterrupted
	}

	// STEP 5 — remove the aside. NON-FATAL: the new version is already in
	// place, so a permission quirk or a busy file in the old tree must not fail
	// the entry — that would report a broken install for a working one. It is
	// reported as a leftover to clean next run instead.
	out.RemoveAsideErr = os.RemoveAll(aside)
	return out, nil
}

// gateSyncDir fsyncs a directory. On darwin Go's os.File.Sync is
// fcntl(F_FULLFSYNC), not fsync(2) — verified in
// $GOROOT/src/internal/poll/fd_fsync_darwin.go, which cites golang/go#26650
// ("on OS X, SYS_FSYNC doesn't fully flush contents to disk"). So the same Go
// call gives a real barrier on both linux and darwin.
func gateSyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// --- fixtures ---------------------------------------------------------------

type gateVersion string

const (
	gateOld gateVersion = "old"
	gateNew gateVersion = "new"
)

// gateManifest is the source of truth for what each tree contains. Expected
// values in the tests below are derived from THIS, never from observing a run.
//
// The two trees deliberately do not have the same file set: only-in-old.md
// exists in the old version and not the new. A swap that merges instead of
// replacing (a CopyDir implementation, say) leaves it behind, and that is the
// most likely wrong implementation of this task.
func gateManifest(v gateVersion) map[string]string {
	switch v {
	case gateOld:
		return map[string]string{
			"VERSION":        "old",
			"SKILL.md":       "the old version's body",
			"only-in-old.md": "a file the new version removed",
			"sub/nested.txt": "old nested",
		}
	case gateNew:
		return map[string]string{
			"VERSION":        "new",
			"SKILL.md":       "the new version's body",
			"only-in-new.md": "a file the old version did not have",
			"sub/nested.txt": "new nested",
		}
	}
	panic("unknown gate version " + string(v))
}

func gateWriteTree(t *testing.T, root string, v gateVersion) string {
	t.Helper()
	for rel, body := range gateManifest(v) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	return root
}

// The observable states. FR-024 permits exactly three of these at a
// destination: absent, wholly old, wholly new. Every other value is a failure.
const (
	gateStateAbsent   = "absent"
	gateStateOld      = "wholly the old version"
	gateStateNew      = "wholly the new version"
	gateStateMixed    = "a mixture of versions"
	gateStateEmptyDir = "an empty directory"
	gateStateFile     = "a regular file"
	gateStateSymlink  = "a symlink"
)

// gateState classifies a path by full content comparison against both
// manifests. A VERSION marker alone is not enough: a merged tree can carry the
// new marker and the old files, and that is the case this must catch.
func gateState(t *testing.T, path string) string {
	t.Helper()

	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return gateStateAbsent
	}
	require.NoError(t, err)
	if info.Mode()&os.ModeSymlink != 0 {
		return gateStateSymlink
	}
	if !info.IsDir() {
		return gateStateFile
	}

	got := map[string]string{}
	require.NoError(t, filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(path, p)
		if relErr != nil {
			return relErr
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		got[filepath.ToSlash(rel)] = string(body)
		return nil
	}))

	if len(got) == 0 {
		return gateStateEmptyDir
	}
	if gateEqual(got, gateManifest(gateOld)) {
		return gateStateOld
	}
	if gateEqual(got, gateManifest(gateNew)) {
		return gateStateNew
	}
	return gateStateMixed
}

func gateEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// gateFixture is one destination-plus-staging pair inside a fake home.
type gateFixture struct {
	home    string
	dest    string
	aside   string
	staging string
}

func newGateFixture(t *testing.T) gateFixture {
	t.Helper()
	home := t.TempDir()
	agentDir := filepath.Join(home, ".claude", "skills")
	require.NoError(t, os.MkdirAll(agentDir, 0o755))
	dest := filepath.Join(agentDir, "acme__lint-go")
	return gateFixture{
		home:    home,
		dest:    dest,
		aside:   dest + gateAsideSuffix,
		staging: filepath.Join(agentDir, ".amctl-staging", "sha256-deadbeef"),
	}
}

// stageNew (re)creates the staged new version. A re-run after a crash re-stages
// from the digest-addressed cache, so recreating it is the faithful simulation
// of a second `amctl sync`, not a shortcut.
func (f gateFixture) stageNew(t *testing.T) {
	t.Helper()
	require.NoError(t, os.RemoveAll(f.staging))
	require.NoError(t, os.MkdirAll(f.staging, 0o755))
	gateWriteTree(t, f.staging, gateNew)
}

func (f gateFixture) installOld(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(f.dest, 0o755))
	gateWriteTree(t, f.dest, gateOld)
}

// --- the gate ---------------------------------------------------------------

// TestR3InterruptionAtEveryStepLeavesOldOrNew is the gate proper: FR-024.
//
// Expected states are hand-derived from the sequence, not from a run. If T041
// reorders the steps, this table is what disagrees with it.
func TestR3InterruptionAtEveryStepLeavesOldOrNew(t *testing.T) {
	tests := []struct {
		stopAfter    gateStep
		wantDest     string
		wantAside    string
		wantLeftover bool
	}{
		{gateStepNone, gateStateOld, gateStateAbsent, false},
		{gateStepReclaimed, gateStateOld, gateStateAbsent, false},
		// The only window in which the destination is absent. FR-024 permits
		// absent; what it does not permit is half-written, and rename cannot
		// produce that.
		{gateStepAsided, gateStateAbsent, gateStateOld, true},
		{gateStepMovedIn, gateStateNew, gateStateOld, true},
		{gateStepSynced, gateStateNew, gateStateOld, true},
		{gateStepComplete, gateStateNew, gateStateAbsent, false},
	}

	for _, tc := range tests {
		t.Run("a crash "+tc.stopAfter.String()+" leaves the destination "+tc.wantDest, func(t *testing.T) {
			f := newGateFixture(t)
			f.installOld(t)
			f.stageNew(t)

			_, err := gateSwap(f.staging, f.dest, tc.stopAfter)
			if tc.stopAfter == gateStepComplete {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errGateInterrupted)
			}

			got := gateState(t, f.dest)
			require.Contains(t,
				[]string{gateStateAbsent, gateStateOld, gateStateNew}, got,
				"FR-024: the destination must be absent, wholly old or wholly new, got %s", got)
			require.Equal(t, tc.wantDest, got)
			require.Equal(t, tc.wantAside, gateState(t, f.aside))

			// An aside nothing will ever clean up is a slow leak, not
			// atomicity. Prove the NEXT run cleans it and converges.
			f.stageNew(t)
			out, rerr := gateSwap(f.staging, f.dest, gateStepComplete)
			require.NoError(t, rerr)
			require.NoError(t, out.RemoveAsideErr)
			require.Equal(t, gateStateNew, gateState(t, f.dest), "a re-run must converge on the new version")
			require.Equal(t, gateStateAbsent, gateState(t, f.aside), "a re-run must not leave an aside behind")
			require.Equal(t, gateStateAbsent, gateState(t, f.staging), "the staged tree is consumed by the swap")
		})
	}
}

// TestR3ReclaimingALeftoverAsideRestoresARollbackTarget is the negative control
// for step 1. An implementation that DISCARDS the leftover instead of reclaiming
// it passes every test above and fails this one: after a crash in the
// dest-absent window, a second failure would leave the entry gone for good.
func TestR3ReclaimingALeftoverAsideRestoresARollbackTarget(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepAsided)
	require.ErrorIs(t, err, errGateInterrupted)
	require.Equal(t, gateStateAbsent, gateState(t, f.dest))
	require.Equal(t, gateStateOld, gateState(t, f.aside))

	// The second run fails at step 3 — the staged tree is missing, standing in
	// for any step-3 failure (EXDEV, ENOSPC, a permission change).
	missing := filepath.Join(filepath.Dir(f.staging), "sha256-never-staged")
	_, err = gateSwap(missing, f.dest, gateStepComplete)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist, "the specific failure must be the missing staged tree")

	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"step 1 must reclaim the leftover aside so step 3 has something to roll back to")
}

// TestR3StepThreeFailureRollsBackToTheOldVersion — FR-015's "leave the machine
// unchanged for it" applied to a swap that has already moved the old aside.
func TestR3StepThreeFailureRollsBackToTheOldVersion(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)

	_, err := gateSwap(filepath.Join(f.home, "no-such-staging"), f.dest, gateStepComplete)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Equal(t, gateStateOld, gateState(t, f.dest))
	require.Equal(t, gateStateAbsent, gateState(t, f.aside), "the rollback consumes the aside")
}

// TestR3DestinationShapes covers the shapes that break the naive version.
func TestR3DestinationShapes(t *testing.T) {
	tests := []struct {
		name  string
		setUp func(t *testing.T, f gateFixture)
	}{
		{
			// The three-step case: nothing to move aside. Step 2's ENOENT
			// tolerance is what makes this the same code path as the rest.
			name:  "the destination does not exist yet",
			setUp: func(_ *testing.T, _ gateFixture) {},
		},
		{
			name:  "the destination is an existing directory holding the old version",
			setUp: func(t *testing.T, f gateFixture) { f.installOld(t) },
		},
		{
			name: "the destination is an empty directory",
			setUp: func(t *testing.T, f gateFixture) {
				require.NoError(t, os.MkdirAll(f.dest, 0o755))
			},
		},
		{
			// A regular file where a directory belongs. os.Rename moves a file
			// as happily as a directory, so the aside step handles this with no
			// special case — but only because nothing in the sequence calls
			// MkdirAll(dest) or os.Remove(dest) expecting a directory.
			name: "the destination is a regular file where a directory is expected",
			setUp: func(t *testing.T, f gateFixture) {
				require.NoError(t, os.WriteFile(f.dest, []byte("not a directory"), 0o644))
			},
		},
		{
			name: "the destination is a dangling symlink",
			setUp: func(t *testing.T, f gateFixture) {
				gateRequireSymlink(t, filepath.Join(f.home, "nothing-here"), f.dest)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			tc.setUp(t, f)
			f.stageNew(t)

			out, err := gateSwap(f.staging, f.dest, gateStepComplete)
			require.NoError(t, err)
			require.NoError(t, out.RemoveAsideErr)
			require.NoError(t, out.SyncDirErr)
			require.Equal(t, gateStateNew, gateState(t, f.dest))
			require.Equal(t, gateStateAbsent, gateState(t, f.aside))
		})
	}
}

// TestR3SwapReplacesRatherThanMerges — the control against a CopyDir
// implementation. only-in-old.md exists in the old tree and not the new, so a
// merge leaves it behind and gateState reports a mixture.
func TestR3SwapReplacesRatherThanMerges(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepComplete)
	require.NoError(t, err)

	require.NoFileExists(t, filepath.Join(f.dest, "only-in-old.md"),
		"a file the new version dropped must not survive the swap")
	require.FileExists(t, filepath.Join(f.dest, "only-in-new.md"))
	nested, err := os.ReadFile(filepath.Join(f.dest, "sub", "nested.txt"))
	require.NoError(t, err)
	require.Equal(t, gateManifest(gateNew)["sub/nested.txt"], string(nested))
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

// --- symlinks ---------------------------------------------------------------

// TestR3ASymlinkAtTheDestinationIsReplacedNotFollowed records a decision.
//
// THE DECISION: amctl replaces a symlink at an entry's destination with a real
// directory. It does NOT resolve the link and swap at the resolved location.
//
// WHY. os.Rename operates on the link, not its target, on every platform in
// scope, so this is also the behaviour we get for free — but it is chosen, not
// inherited, for two reasons:
//
//  1. FR-020. amctl must not write outside the invoking user's home, checked on
//     the RESOLVED path. Following a symlink at the destination is exactly how
//     amctl would write outside the home without ever constructing a path
//     outside it: /home/u/.claude/skills/x -> /etc/whatever. Not following
//     means the write lands where the path says it lands.
//  2. The symlinked-dotfiles case argues the same way. When ~/.claude itself is
//     a symlink into a dotfiles repo, the PARENT is the link and the kernel
//     resolves it during the rename anyway — the entry's own destination is a
//     real directory inside the repo and everything works. A symlink at the
//     ENTRY destination is a different thing: amctl never creates one
//     (extraction refuses symlinks, FR-019), so its presence means a human put
//     it there.
//
// THE CONSEQUENCE, which belongs to T042 and not to swap.go: because a symlink
// at the destination is by definition not something amctl wrote, the caller
// MUST refuse the entry under FR-028 ("MUST NOT remove or overwrite any path
// absent from its own record") unless --force is given. swap.go is unconditional
// by design; the guard is the caller's, and swap.go's doc comment must say so.
func TestR3ASymlinkAtTheDestinationIsReplacedNotFollowed(t *testing.T) {
	f := newGateFixture(t)

	linked := filepath.Join(f.home, "dotfiles", "claude-skills", "acme__lint-go")
	require.NoError(t, os.MkdirAll(linked, 0o755))
	sentinel := filepath.Join(linked, "hand-written.md")
	require.NoError(t, os.WriteFile(sentinel, []byte("a human wrote this"), 0o644))
	gateRequireSymlink(t, linked, f.dest)
	f.stageNew(t)

	// Mid-swap: the aside must be the LINK, and the link's target must be
	// untouched. Checked at step 2 because step 5 removes the aside.
	_, err := gateSwap(f.staging, f.dest, gateStepAsided)
	require.ErrorIs(t, err, errGateInterrupted)
	asideInfo, err := os.Lstat(f.aside)
	require.NoError(t, err)
	require.NotZero(t, asideInfo.Mode()&os.ModeSymlink, "the symlink itself must be what moved aside")
	target, err := os.Readlink(f.aside)
	require.NoError(t, err)
	require.Equal(t, linked, target)

	f.stageNew(t)
	_, err = gateSwap(f.staging, f.dest, gateStepComplete)
	require.NoError(t, err)

	destInfo, err := os.Lstat(f.dest)
	require.NoError(t, err)
	require.Zero(t, destInfo.Mode()&os.ModeSymlink, "the destination must now be a real directory")
	require.True(t, destInfo.IsDir())
	require.Equal(t, gateStateNew, gateState(t, f.dest))

	// The load-bearing assertion: nothing was written through the link, and
	// removing the aside removed the link, not the tree it pointed at.
	body, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "a human wrote this", string(body),
		"the swap must not write through a symlink at the destination")
	entries, err := os.ReadDir(linked)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the symlink's target directory must be untouched")
}

// TestR3ASymlinkPointingOutsideTheHomeIsNotWrittenThrough is the FR-020 half of
// the decision above, stated as an assertion rather than as prose.
func TestR3ASymlinkPointingOutsideTheHomeIsNotWrittenThrough(t *testing.T) {
	outside := t.TempDir() // a second root, standing in for anywhere not under home
	f := newGateFixture(t)

	require.NotEqual(t, outside, f.home)
	require.False(t, strings.HasPrefix(outside, f.home+string(os.PathSeparator)))

	forbidden := filepath.Join(outside, "etc-ish")
	require.NoError(t, os.MkdirAll(forbidden, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(forbidden, "keep.conf"), []byte("do not touch"), 0o600))
	gateRequireSymlink(t, forbidden, f.dest)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepComplete)
	require.NoError(t, err)

	before := []string{"keep.conf"}
	entries, err := os.ReadDir(forbidden)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Equal(t, before, names, "FR-020: nothing may be written or removed outside the home")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

func gateRequireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		require.NoError(t, err)
	}
}

// --- negative controls: what the naive version does -------------------------

// TestR3NaiveRenameOverAnExistingDestination proves step 2 is load-bearing
// rather than ceremony, and pins the measured semantics of both os.Rename and
// the raw syscall so nobody "simplifies" the sequence into either of them.
//
// Without a negative control here, an implementation that dropped the aside
// step would look correct in review — plan.md's own R3 note implies it would at
// least work on POSIX — and would fail on every platform at the first upgrade.
func TestR3NaiveRenameOverAnExistingDestination(t *testing.T) {
	t.Run("os.Rename onto a non-empty directory fails", func(t *testing.T) {
		f := newGateFixture(t)
		f.installOld(t)
		f.stageNew(t)

		err := os.Rename(f.staging, f.dest)
		require.Error(t, err)
		var linkErr *os.LinkError
		require.ErrorAs(t, err, &linkErr)
		gateRequireRenameOntoDirErr(t, err)
		require.Equal(t, gateStateOld, gateState(t, f.dest), "the failed naive rename must change nothing")
		require.Equal(t, gateStateNew, gateState(t, f.staging), "the staged tree must survive to be retried")
	})

	t.Run("os.Rename onto an EMPTY directory fails too even though POSIX would allow it", func(t *testing.T) {
		f := newGateFixture(t)
		require.NoError(t, os.MkdirAll(f.dest, 0o755))
		f.stageNew(t)

		err := os.Rename(f.staging, f.dest)
		require.Error(t, err,
			"Go's os.Rename Lstats the destination and refuses any directory; there is no empty-destination shortcut")
		gateRequireRenameOntoDirErr(t, err)
	})

	t.Run("the raw POSIX call is more permissive which is the trap", func(t *testing.T) {
		f := newGateFixture(t)
		require.NoError(t, os.MkdirAll(f.dest, 0o755))
		f.stageNew(t)

		require.NoError(t, syscall.Rename(f.staging, f.dest),
			"POSIX rename DOES replace an empty destination directory, so dropping to syscall looks like a fix")
		require.Equal(t, gateStateNew, gateState(t, f.dest))

		// ...and then it fails on the very next real upgrade, which is what
		// makes it worse than the EEXIST it was reached for.
		f.stageNew(t)
		require.ErrorIs(t, syscall.Rename(f.staging, f.dest), syscall.ENOTEMPTY,
			"POSIX rename onto a NON-empty directory is ENOTEMPTY: the syscall shortcut only ever worked by accident")
	})

	t.Run("os.Rename onto a symlink is ENOTDIR which the aside step also sidesteps", func(t *testing.T) {
		f := newGateFixture(t)
		linked := filepath.Join(f.home, "elsewhere")
		require.NoError(t, os.MkdirAll(linked, 0o755))
		gateRequireSymlink(t, linked, f.dest)
		f.stageNew(t)

		err := os.Rename(f.staging, f.dest)
		require.Error(t, err, "a symlink at the destination defeats the naive rename as thoroughly as a directory does")
		require.ErrorIs(t, err, syscall.ENOTDIR,
			"Lstat sees a symlink rather than a directory, so os.Rename reaches syscall.Rename and gets ENOTDIR")
	})
}

// gateRequireRenameOntoDirErr asserts the SPECIFIC failure of renaming onto an
// existing directory. A negative control that accepts any error has stopped
// testing anything.
func gateRequireRenameOntoDirErr(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, syscall.EEXIST,
		"os/file_unix.go returns EEXIST for a directory destination before it calls syscall.Rename")
}

// TestR3AStaleAsideBlocksTheNaiveAsideRename is the negative control for step 1
// as a *mechanical* requirement, separate from the recovery argument in
// TestR3ReclaimingALeftoverAsideRestoresARollbackTarget: without step 1, the
// second swap of an entry that crashed once fails at step 2 forever.
//
// Measured note: it fails even when the leftover aside is EMPTY, for the same
// reason as the naive rename above — Go refuses a directory destination
// outright. An implementation that only cleared a NON-empty aside would still
// wedge.
func TestR3AStaleAsideBlocksTheNaiveAsideRename(t *testing.T) {
	tests := []struct {
		name     string
		populate bool
	}{
		{"a non-empty leftover aside blocks step 2", true},
		{"an EMPTY leftover aside blocks step 2 just as hard", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			f.installOld(t)
			require.NoError(t, os.MkdirAll(f.aside, 0o755))
			if tc.populate {
				require.NoError(t, os.WriteFile(filepath.Join(f.aside, "leftover"), []byte("x"), 0o644))
			}

			err := os.Rename(f.dest, f.aside)
			require.Error(t, err, "step 2 cannot run while an aside is in the way")
			gateRequireRenameOntoDirErr(t, err)

			// The sequence handles it because step 1 clears the way first.
			f.stageNew(t)
			out, serr := gateSwap(f.staging, f.dest, gateStepComplete)
			require.NoError(t, serr)
			require.NoError(t, out.RemoveAsideErr)
			require.Equal(t, gateStateNew, gateState(t, f.dest))
			require.Equal(t, gateStateAbsent, gateState(t, f.aside))
		})
	}
}

// --- EXDEV ------------------------------------------------------------------

// TestR3CrossDeviceStagingCollapsesTheWholeScheme settles where the staging
// directory has to live.
//
// THE DECISION: the staging directory MUST be a sibling of the destination —
// `<dest-parent>/.amctl-staging/<digest>` — not a central
// `~/.agent-manager/staging/<digest>`. An atomic swap by rename requires
// staging and destination on the same filesystem, and amctl cannot assume they
// are: an agent directory is frequently a symlink into a dotfiles repo, which
// may be a different mount, an encrypted volume, a network share, or a tmpfs.
//
// AND: swap.go must detect a cross-device rename and fail the entry naming both
// paths. It must NOT fall back to a recursive copy. A copy is not atomic, so
// the fallback would silently convert the one requirement of this task into its
// opposite — a destination that can be observed half-written. Failing closed
// with an actionable message is the correct outcome.
func TestR3CrossDeviceStagingCollapsesTheWholeScheme(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)

	otherFS := gateOtherFilesystemDir(t)
	staging := filepath.Join(otherFS, "sha256-deadbeef")
	require.NoError(t, os.MkdirAll(staging, 0o755))
	gateWriteTree(t, staging, gateNew)

	probe := filepath.Join(otherFS, "probe")
	require.NoError(t, os.MkdirAll(probe, 0o755))
	probeErr := os.Rename(probe, filepath.Join(filepath.Dir(f.dest), "probe"))
	if !gateIsCrossDevice(probeErr) {
		t.Skipf("no second filesystem reachable from %s: rename gave %v", otherFS, probeErr)
	}

	_, err := gateSwap(staging, f.dest, gateStepComplete)
	require.Error(t, err)
	require.True(t, gateIsCrossDevice(err), "the specific failure must be a cross-device rename, got %v", err)

	// The rollback still works, because the aside is a sibling of the
	// destination and therefore always on the destination's filesystem.
	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"a cross-device staging directory must leave the old version in place")
	require.Equal(t, gateStateAbsent, gateState(t, f.aside))
}

// gateOtherFilesystemDir returns a writable directory that is likely to be on a
// different filesystem from t.TempDir(). Only linux has a dependable one
// without privileges.
func gateOtherFilesystemDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("%s: no unprivileged second filesystem to construct EXDEV with; see the R3 notes", runtime.GOOS)
	}
	// t.TempDir() is deliberately NOT used here: it honours TMPDIR, which on
	// every machine this runs on is the same filesystem as the destination —
	// the exact thing this test needs to avoid.
	dir, err := os.MkdirTemp("/dev/shm", "amctl-r3-") //nolint:usetesting // a second filesystem is the point
	if err != nil {
		t.Skipf("linux: /dev/shm not usable as a second filesystem: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func gateIsCrossDevice(err error) bool {
	return err != nil && errors.Is(err, syscall.EXDEV)
}

// --- durability -------------------------------------------------------------

// TestR3ParentDirectoryFsync settles whether the code should fsync.
//
// THE ANSWER: yes on linux and darwin, best-effort and non-fatal. rename(2) is
// atomic with respect to concurrent observers but says
// nothing about durability — POSIX and Linux's rename(2) both stay silent, and
// the standing advice (LWN, "Ensuring data reaches disk", Jeff Layton, 2011;
// SQLite's atomic-commit notes; Dan Luu's "Files are hard", 2015) is that the
// containing directory must be fsynced for a rename to survive a power loss.
// Go gives a real barrier on both platforms: os.File.Sync is fsync(2) on linux
// and fcntl(F_FULLFSYNC) on darwin (see $GOROOT/src/internal/poll/
// fd_fsync_darwin.go, citing golang/go#26650).
//
// WHY IT IS NON-FATAL, and why this is a should rather than a must: the record
// is written AFTER the swap (plan.md's on-disk state model). If the rename is
// lost to a power cut, the record write that follows it is lost too, so the
// record does not end up claiming an entry that is not there. The ordering, not
// the fsync, is what keeps the two consistent. The fsync narrows the window in
// which a durable record could outlive a non-durable rename; it does not create
// the safety.
//
// WHAT IT DOES NOT BUY, which is the part worth writing down: fsyncing the
// parent makes the directory ENTRY durable, not the file CONTENT underneath it.
// On a delayed-allocation filesystem, a power loss shortly after the swap can
// leave the destination present and full of zero-length files — a mixture, and
// a FR-024 violation that no amount of care in swap.go can prevent. Content
// durability is T040's: stage must fsync every extracted file before handing
// the tree over.
func TestR3ParentDirectoryFsync(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	out, err := gateSwap(f.staging, f.dest, gateStepComplete)
	require.NoError(t, err)

	require.NoError(t, out.SyncDirErr, "fsync of the destination's parent directory must succeed")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

// --- shape of the contract --------------------------------------------------

func TestR3AsideNameIsASiblingDerivedFromTheDestination(t *testing.T) {
	f := newGateFixture(t)

	require.Equal(t, f.dest+gateAsideSuffix, f.aside)
	require.Equal(t, filepath.Dir(f.dest), filepath.Dir(f.aside),
		"the aside must be a sibling so step 2 is always an intra-filesystem rename")
	require.NotContains(t, gateAsideSuffix, string(os.PathSeparator),
		"the suffix must not introduce a path element, or the aside leaves the parent directory")
	require.True(t, strings.HasPrefix(gateAsideSuffix, "."),
		"the aside must be hidden on POSIX so an agent scanning its skills directory ignores it")
}

func TestR3RepeatedSwapsLeaveNothingBehind(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)

	for i := range 3 {
		f.stageNew(t)
		out, err := gateSwap(f.staging, f.dest, gateStepComplete)
		require.NoError(t, err, "swap %d", i)
		require.NoError(t, out.RemoveAsideErr, "swap %d", i)
	}

	parent := filepath.Dir(f.dest)
	entries, err := os.ReadDir(parent)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{filepath.Base(f.dest), ".amctl-staging"}, names,
		"nothing but the destination and the staging root may remain in the agent directory")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

// TestR3PlatformsInScope states, as an executable fact, which platform this run
// verified. The unverified-per-platform list is in the R3 notes; the short
// version is that darwin shares every assertion above except the cross-device
// one, and that it is verified only when the cli unit-test job runs on a
// macos-latest runner. Windows is not a target and is refused here rather than
// skipped, so a build for it fails loudly instead of reporting a pass it never
// measured.
func TestR3PlatformsInScope(t *testing.T) {
	require.Contains(t, []string{"linux", "darwin"}, runtime.GOOS,
		"plan.md's Technical Context names four targets over two operating systems")
	t.Logf("R3 verified on %s/%s", runtime.GOOS, runtime.GOARCH)
}
