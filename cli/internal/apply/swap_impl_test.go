// These tests check Swap against the independent gateSwap in swap_test.go, so
// a reordering of the steps in Swap cannot go unnoticed.

package apply

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/record"
)

func TestSwapSharesTheGatesAsideName(t *testing.T) {
	require.Equal(t, gateAsideSuffix, AsideSuffix)
	require.Equal(t, record.AsideSuffix, AsideSuffix,
		"there is one definition of the aside name, in internal/record, because that is the package that has to compute an entry's removable set")

	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)
	res, err := Swap(f.staging, f.dest)
	require.NoError(t, err)
	require.Equal(t, f.aside, res.Aside)
	require.Equal(t, filepath.Dir(res.Dest), filepath.Dir(res.Aside),
		"the aside must be a sibling so step 2 is always an intra-filesystem rename")
	require.ElementsMatch(t, record.Entry{Dest: res.Dest}.RemovablePaths(),
		[]string{res.Dest, res.Aside},
		"the two paths a swap touches must be exactly the entry's removable set")
}

// TestSwapMatchesTheGateAtEveryDestinationShape swaps each shape with both the
// gate and Swap and requires the same outcome.
func TestSwapMatchesTheGateAtEveryDestinationShape(t *testing.T) {
	shapes := []struct {
		name  string
		setUp func(t *testing.T, f gateFixture)
	}{
		{"the destination does not exist yet", func(_ *testing.T, _ gateFixture) {}},
		{"the destination holds the old version", func(t *testing.T, f gateFixture) { f.installOld(t) }},
		{"the destination is an empty directory", func(t *testing.T, f gateFixture) {
			require.NoError(t, os.MkdirAll(f.dest, 0o755))
		}},
		{"the destination is a regular file", func(t *testing.T, f gateFixture) {
			require.NoError(t, os.WriteFile(f.dest, []byte("not a directory"), 0o644))
		}},
		{"the destination is a dangling symlink", func(t *testing.T, f gateFixture) {
			gateRequireSymlink(t, filepath.Join(f.home, "nothing-here"), f.dest)
		}},
		{"a leftover aside is in the way", func(t *testing.T, f gateFixture) {
			f.installOld(t)
			require.NoError(t, os.MkdirAll(f.aside, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(f.aside, "leftover"), []byte("x"), 0o644))
		}},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			gate := newGateFixture(t)
			sh.setUp(t, gate)
			gate.stageNew(t)
			gateOut, gateErr := gateSwap(gate.staging, gate.dest, gateStepComplete)
			require.NoError(t, gateErr)
			require.NoError(t, gateOut.RemoveAsideErr)

			impl := newGateFixture(t)
			sh.setUp(t, impl)
			impl.stageNew(t)
			res, err := Swap(impl.staging, impl.dest)
			require.NoError(t, err)
			require.NoError(t, res.SyncDirErr)
			require.NoError(t, res.RemoveAsideErr)
			require.Empty(t, res.LeftoverAside())

			require.Equal(t, gateState(t, gate.dest), gateState(t, impl.dest))
			require.Equal(t, gateStateNew, gateState(t, impl.dest))
			require.Equal(t, gateStateAbsent, gateState(t, impl.aside))
			require.Equal(t, gateStateAbsent, gateState(t, impl.staging),
				"the staged tree is consumed by the swap")
		})
	}
}

// TestSwapConvergesAfterAnInterruptionAtEveryStep crashes via the gate, then
// runs the real Swap over the result.
func TestSwapConvergesAfterAnInterruptionAtEveryStep(t *testing.T) {
	tests := []struct {
		stopAfter     gateStep
		wantReclaimed bool
		wantDiscarded bool
	}{
		{gateStepNone, false, false},
		{gateStepReclaimed, false, false},
		{gateStepAsided, true, false},
		{gateStepMovedIn, false, true},
		{gateStepSynced, false, true},
		{gateStepComplete, false, false},
	}

	for _, tc := range tests {
		t.Run("a crash "+tc.stopAfter.String()+" converges on the next run", func(t *testing.T) {
			f := newGateFixture(t)
			f.installOld(t)
			f.stageNew(t)

			_, err := gateSwap(f.staging, f.dest, tc.stopAfter)
			if tc.stopAfter == gateStepComplete {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errGateInterrupted)
			}

			f.stageNew(t)
			res, err := Swap(f.staging, f.dest)
			require.NoError(t, err)
			require.Equal(t, tc.wantReclaimed, res.Reclaimed)
			require.Equal(t, tc.wantDiscarded, res.DiscardedAside)
			require.Equal(t, gateStateNew, gateState(t, f.dest))
			require.Equal(t, gateStateAbsent, gateState(t, f.aside),
				"a converged run must leave no aside behind")
		})
	}
}

// TestSwapReclaimsRatherThanDiscardsALeftoverAside: discarding the aside left
// by a crash in the dest-absent window would lose the entry on a second failure.
func TestSwapReclaimsRatherThanDiscardsALeftoverAside(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepAsided)
	require.ErrorIs(t, err, errGateInterrupted)
	require.Equal(t, gateStateAbsent, gateState(t, f.dest))
	require.Equal(t, gateStateOld, gateState(t, f.aside))

	// A missing staged tree stands in for any step-3 failure.
	missing := filepath.Join(filepath.Dir(f.staging), "sha256-never-staged")
	res, err := Swap(missing, f.dest)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist, "the specific failure must be the missing staged tree")
	require.True(t, res.Reclaimed)
	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"step 1 must reclaim the leftover aside so step 3 has something to roll back to")
}

func TestSwapRollsBackToTheOldVersionOnAStepThreeFailure(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(f.staging), 0o755))

	res, err := Swap(filepath.Join(filepath.Dir(f.staging), "sha256-never-staged"), f.dest)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Equal(t, gateStateOld, gateState(t, f.dest))
	require.Equal(t, gateStateAbsent, gateState(t, f.aside), "the rollback consumes the aside")
	require.Empty(t, res.LeftoverAside())
}

func TestSwapReplacesRatherThanMerges(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := Swap(f.staging, f.dest)
	require.NoError(t, err)

	require.NoFileExists(t, filepath.Join(f.dest, "only-in-old.md"),
		"a file the new version dropped must not survive the swap")
	require.FileExists(t, filepath.Join(f.dest, "only-in-new.md"))
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}

func TestSwapReplacesASymlinkAtTheDestinationWithoutWritingThroughIt(t *testing.T) {
	outside := t.TempDir()
	f := newGateFixture(t)
	require.False(t, strings.HasPrefix(outside, f.home+string(os.PathSeparator)))

	forbidden := filepath.Join(outside, "etc-ish")
	require.NoError(t, os.MkdirAll(forbidden, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(forbidden, "keep.conf"), []byte("do not touch"), 0o600))
	gateRequireSymlink(t, forbidden, f.dest)
	f.stageNew(t)

	_, err := Swap(f.staging, f.dest)
	require.NoError(t, err)

	info, err := os.Lstat(f.dest)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeSymlink, "the destination must now be a real directory")
	require.Equal(t, gateStateNew, gateState(t, f.dest))

	entries, err := os.ReadDir(forbidden)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Equal(t, []string{"keep.conf"}, names,
		"nothing may be written or removed outside the home, and removing the aside must remove the link and not its target")
}

// TestSwapRefusesAStagedTreeThatIsNotASibling: the refusal is structural, not
// a wait for EXDEV, since a non-sibling may share a filesystem on one machine
// and not the next.
func TestSwapRefusesAStagedTreeThatIsNotASibling(t *testing.T) {
	tests := []struct {
		name    string
		staging func(t *testing.T, f gateFixture) string
	}{
		{"a staged tree in an unrelated directory", func(t *testing.T, f gateFixture) string {
			p := filepath.Join(f.home, "elsewhere", "sha256-deadbeef")
			require.NoError(t, os.MkdirAll(p, 0o755))
			gateWriteTree(t, p, gateNew)
			return p
		}},
		{"a staged tree on another filesystem", func(t *testing.T, f gateFixture) string {
			_ = f
			p := filepath.Join(gateOtherFilesystemDir(t), "sha256-deadbeef")
			require.NoError(t, os.MkdirAll(p, 0o755))
			gateWriteTree(t, p, gateNew)
			return p
		}},
		{"a relative staged tree", func(_ *testing.T, _ gateFixture) string {
			return filepath.Join(".amctl-staging", "sha256-deadbeef")
		}},
		{"no staged tree at all", func(_ *testing.T, _ gateFixture) string { return "" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			f.installOld(t)
			staging := tc.staging(t, f)

			_, err := Swap(staging, f.dest)
			require.ErrorIs(t, err, ErrStagingPlacement)
			require.Equal(t, gateStateOld, gateState(t, f.dest),
				"a refused entry must leave the machine unchanged")
			require.Equal(t, gateStateAbsent, gateState(t, f.aside),
				"the refusal must fire before step 2 moves anything")
		})
	}
}

// TestCrossDeviceIsRefusedAndNeverCopied tests the classifier directly: a real
// EXDEV can't be reached through Swap without a privileged mount, since os.Root
// refuses symlinks leaving the parent.
func TestCrossDeviceIsRefusedAndNeverCopied(t *testing.T) {
	sep := string(os.PathSeparator)
	staging := filepath.Join(sep, "mnt", "other", ".amctl-staging", "sha256-deadbeef")
	dest := filepath.Join(sep, "home", "u", ".claude", "skills", "acme--lint-go")

	wrapped := crossDevice(&os.LinkError{Op: "renameat", Old: staging, New: dest, Err: syscall.EXDEV}, staging, dest)
	require.ErrorIs(t, wrapped, ErrCrossDevice)
	require.ErrorIs(t, wrapped, syscall.EXDEV, "the underlying errno must stay in the chain")
	require.Contains(t, wrapped.Error(), staging, "the refusal must name the staged tree")
	require.Contains(t, wrapped.Error(), dest, "the refusal must name the destination")
	require.Contains(t, wrapped.Error(), "would not be atomic",
		"the message must say why there is no copy fallback")

	other := errors.New("something else entirely")
	require.Same(t, other, crossDevice(other, staging, dest),
		"only a cross-device error may be restated; anything else must pass through untouched")
	require.False(t, isCrossDevice(nil))
	require.False(t, isCrossDevice(fs.ErrNotExist))
}

// TestSwapReportsALeftoverAsideRatherThanFailingTheEntry makes the old tree
// unremovable via its mode to show step 5 is non-fatal.
func TestSwapReportsALeftoverAsideRatherThanFailingTheEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not restrict root, so the failure cannot be constructed")
	}

	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)
	require.NoError(t, os.Chmod(f.dest, 0o500))
	t.Cleanup(func() { _ = os.Chmod(f.aside, 0o700) })

	res, err := Swap(f.staging, f.dest)
	require.NoError(t, err, "the install succeeded; step 5 must not fail the entry")
	require.Error(t, res.RemoveAsideErr)
	require.Equal(t, f.aside, res.LeftoverAside(),
		"a failed step 5 must be surfaced as a leftover to clean next run")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
	// A partially removed aside is fine: it is not authoritative for anything.
	require.NotEqual(t, gateStateAbsent, gateState(t, f.aside))

	// The leftover is in the removable set, so the next run cleans it without a glob.
	require.Contains(t, record.Entry{Dest: f.dest}.RemovablePaths(), res.LeftoverAside())
	require.NoError(t, os.Chmod(f.aside, 0o700))
	f.stageNew(t)
	second, err := Swap(f.staging, f.dest)
	require.NoError(t, err)
	require.True(t, second.DiscardedAside)
	require.Equal(t, gateStateAbsent, gateState(t, f.aside))
}

func TestSwapRefusesAnUnusableDestination(t *testing.T) {
	tests := []struct {
		name string
		dest string
		want string
	}{
		{"an empty destination", "", "is empty"},
		{"a relative destination", filepath.Join("skills", "acme--x"), "is not absolute"},
		{"an unclean destination", string(os.PathSeparator) + filepath.Join("a", "..", "b") + string(os.PathSeparator), "not a clean path"},
		{"a destination that is the swap's own aside", string(os.PathSeparator) + filepath.Join("home", "u", "x"+AsideSuffix), "aside name"},
		{"a filesystem root", string(os.PathSeparator), "no directory name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			staging := filepath.Join(string(os.PathSeparator), "nowhere", ".amctl-staging", "sha256-x")
			_, err := Swap(staging, tc.dest)
			require.ErrorIs(t, err, ErrDest)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestSwapIsIdempotent(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)

	for i := range 3 {
		f.stageNew(t)
		res, err := Swap(f.staging, f.dest)
		require.NoError(t, err, "swap %d", i)
		require.NoError(t, res.RemoveAsideErr, "swap %d", i)
	}

	entries, err := os.ReadDir(filepath.Dir(f.dest))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{filepath.Base(f.dest), ".amctl-staging"}, names,
		"nothing but the destination and the staging root may remain in the agent directory")
	require.Equal(t, gateStateNew, gateState(t, f.dest))
}
