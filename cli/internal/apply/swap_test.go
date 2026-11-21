// This file is a gate: gateSwap is an independent statement of the rename
// sequence swap.go implements, pinning its ordering, aside name and per-step
// interruption outcomes, so a reordering in swap.go can't pass unnoticed. A
// crash at any step must leave the destination wholly old, wholly new or absent.

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

	"github.com/WindKube/agent-manager/cli/internal/record"
)

// gateAsideSuffix is deterministic, so the removable set is exactly {dest,
// dest+suffix} and cleanup never globs, and a sibling of dest, so step 2 is
// always an intra-filesystem rename.
const gateAsideSuffix = record.AsideSuffix

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

// errGateInterrupted stands in for the process being killed after a step; unlike
// a real error it skips step 3's rollback, because a crash cannot roll back.
var errGateInterrupted = errors.New("interrupted")

// gateOutcome carries the two non-fatal errors; both happen after the new
// version is in place, so failing the entry would misreport a good install.
type gateOutcome struct {
	SyncDirErr     error // step 4
	RemoveAsideErr error // step 5
}

// gateSwap is the reference sequence. A plain os.Rename(staging, dest) fails
// with EEXIST on any existing directory (Go Lstats first), and syscall.Rename
// only works onto an empty one, so dest must be moved aside first. Step 1
// reclaims rather than discards an aside with no dest: it is the only copy of
// the recorded version and step 3's rollback target.
func gateSwap(staging, dest string, stopAfter gateStep) (gateOutcome, error) {
	var out gateOutcome
	aside := dest + gateAsideSuffix

	if stopAfter == gateStepNone {
		return out, errGateInterrupted
	}

	// STEP 1 — reclaim or discard a leftover aside from an interrupted swap.
	if _, err := os.Lstat(aside); err == nil {
		_, destErr := os.Lstat(dest)
		switch {
		case errors.Is(destErr, fs.ErrNotExist):
			if rerr := os.Rename(aside, dest); rerr != nil {
				return out, fmt.Errorf("reclaim leftover %s: %w", aside, rerr)
			}
		default:
			// Crash after step 3: dest is authoritative.
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

	// STEP 2 — move the old version (or a symlink itself) aside; ENOENT means none.
	if err := os.Rename(dest, aside); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return out, fmt.Errorf("move %s aside: %w", dest, err)
	}
	if stopAfter == gateStepAsided {
		return out, errGateInterrupted
	}

	// STEP 3 — move the staged tree into place, rolling back on failure.
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

	// STEP 4 — fsync dest's parent so the rename survives a power loss; non-fatal.
	// File content durability is stage's job.
	out.SyncDirErr = gateSyncDir(filepath.Dir(dest))
	if stopAfter == gateStepSynced {
		return out, errGateInterrupted
	}

	// STEP 5 — remove the aside; non-fatal, reported as a leftover.
	out.RemoveAsideErr = os.RemoveAll(aside)
	return out, nil
}

// gateSyncDir fsyncs a directory; on darwin os.File.Sync is F_FULLFSYNC
// (golang/go#26650), a real barrier there too.
func gateSyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type gateVersion string

const (
	gateOld gateVersion = "old"
	gateNew gateVersion = "new"
)

// gateManifest defines each tree. The file sets differ on purpose, so a swap
// that merges instead of replacing leaves only-in-old.md behind.
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

// Only absent, wholly old and wholly new are permitted at a destination.
const (
	gateStateAbsent   = "absent"
	gateStateOld      = "wholly the old version"
	gateStateNew      = "wholly the new version"
	gateStateMixed    = "a mixture of versions"
	gateStateEmptyDir = "an empty directory"
	gateStateFile     = "a regular file"
	gateStateSymlink  = "a symlink"
)

// gateState compares full content, since a merged tree can carry the new
// VERSION file alongside old files.
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

// stageNew re-creates the staged tree, as a second `amctl sync` would.
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

func TestR3InterruptionAtEveryStepLeavesOldOrNew(t *testing.T) {
	tests := []struct {
		stopAfter    gateStep
		wantDest     string
		wantAside    string
		wantLeftover bool
	}{
		{gateStepNone, gateStateOld, gateStateAbsent, false},
		{gateStepReclaimed, gateStateOld, gateStateAbsent, false},
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
				"the destination must be absent, wholly old or wholly new, got %s", got)
			require.Equal(t, tc.wantDest, got)
			require.Equal(t, tc.wantAside, gateState(t, f.aside))

			// The next run must clean up and converge.
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

// TestR3ReclaimingALeftoverAsideRestoresARollbackTarget fails an implementation
// that discards rather than reclaims the aside left by a crash in the
// dest-absent window.
func TestR3ReclaimingALeftoverAsideRestoresARollbackTarget(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepAsided)
	require.ErrorIs(t, err, errGateInterrupted)
	require.Equal(t, gateStateAbsent, gateState(t, f.dest))
	require.Equal(t, gateStateOld, gateState(t, f.aside))

	// A missing staged tree stands in for any step-3 failure.
	missing := filepath.Join(filepath.Dir(f.staging), "sha256-never-staged")
	_, err = gateSwap(missing, f.dest, gateStepComplete)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist, "the specific failure must be the missing staged tree")

	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"step 1 must reclaim the leftover aside so step 3 has something to roll back to")
}

func TestR3StepThreeFailureRollsBackToTheOldVersion(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)

	_, err := gateSwap(filepath.Join(f.home, "no-such-staging"), f.dest, gateStepComplete)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Equal(t, gateStateOld, gateState(t, f.dest))
	require.Equal(t, gateStateAbsent, gateState(t, f.aside), "the rollback consumes the aside")
}

func TestR3DestinationShapes(t *testing.T) {
	tests := []struct {
		name  string
		setUp func(t *testing.T, f gateFixture)
	}{
		{
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

// TestR3ASymlinkAtTheDestinationIsReplacedNotFollowed pins that a symlink at
// the destination is replaced, never followed: following it is how amctl would
// write outside the home. Refusing it without --force is apply.go's job.
func TestR3ASymlinkAtTheDestinationIsReplacedNotFollowed(t *testing.T) {
	f := newGateFixture(t)

	linked := filepath.Join(f.home, "dotfiles", "claude-skills", "acme__lint-go")
	require.NoError(t, os.MkdirAll(linked, 0o755))
	sentinel := filepath.Join(linked, "hand-written.md")
	require.NoError(t, os.WriteFile(sentinel, []byte("a human wrote this"), 0o644))
	gateRequireSymlink(t, linked, f.dest)
	f.stageNew(t)

	// Checked at step 2 because step 5 removes the aside.
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

	body, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "a human wrote this", string(body),
		"the swap must not write through a symlink at the destination")
	entries, err := os.ReadDir(linked)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the symlink's target directory must be untouched")
}

func TestR3ASymlinkPointingOutsideTheHomeIsNotWrittenThrough(t *testing.T) {
	outside := t.TempDir()
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
	require.Equal(t, before, names, "nothing may be written or removed outside the home")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

func gateRequireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		require.NoError(t, err)
	}
}

// TestR3NaiveRenameOverAnExistingDestination pins os.Rename and syscall.Rename
// semantics so nobody "simplifies" the aside step away.
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

func gateRequireRenameOntoDirErr(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, syscall.EEXIST,
		"os/file_unix.go returns EEXIST for a directory destination before it calls syscall.Rename")
}

// TestR3AStaleAsideBlocksTheNaiveAsideRename: without step 1, an entry that
// crashed once fails step 2 forever, even with an empty leftover aside.
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

			f.stageNew(t)
			out, serr := gateSwap(f.staging, f.dest, gateStepComplete)
			require.NoError(t, serr)
			require.NoError(t, out.RemoveAsideErr)
			require.Equal(t, gateStateNew, gateState(t, f.dest))
			require.Equal(t, gateStateAbsent, gateState(t, f.aside))
		})
	}
}

// TestR3CrossDeviceStagingCollapsesTheWholeScheme is why staging must be a
// sibling of the destination: a cross-device rename fails, and a copy fallback
// would not be atomic.
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

	// The aside is a sibling, so the rollback still works.
	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"a cross-device staging directory must leave the old version in place")
	require.Equal(t, gateStateAbsent, gateState(t, f.aside))
}

func gateOtherFilesystemDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("%s: no unprivileged second filesystem to construct EXDEV with; see the R3 notes", runtime.GOOS)
	}
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

// TestR3ParentDirectoryFsync: rename(2) says nothing about durability, so the
// parent is fsynced. It is non-fatal because the record is written after the
// swap; that ordering, not the fsync, keeps the two consistent.
func TestR3ParentDirectoryFsync(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	out, err := gateSwap(f.staging, f.dest, gateStepComplete)
	require.NoError(t, err)

	require.NoError(t, out.SyncDirErr, "fsync of the destination's parent directory must succeed")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

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

// TestR3PlatformsInScope fails rather than skips on an unsupported OS, so a
// pass is never reported for a platform nobody measured.
func TestR3PlatformsInScope(t *testing.T) {
	require.Contains(t, []string{"linux", "darwin"}, runtime.GOOS,
		"plan.md's Technical Context names four targets over two operating systems")
	t.Logf("R3 verified on %s/%s", runtime.GOOS, runtime.GOARCH)
}
