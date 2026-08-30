// T041's own tests. swap_test.go is the R3 GATE and must not be edited: it
// states the sequence independently, through gateSwap, and this file tests
// Swap against that statement rather than against itself. Two independent
// statements of one sequence are worth their duplication — a test that only
// calls the code under test cannot notice that the code reordered the steps,
// because it reordered with it.

package apply

import (
	"errors"
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

// TestSwapSharesTheGatesAsideName is the drift check R3 asks for by name: "T041
// must assert that swap.go's own aside-suffix constant equals the gate's, or the
// two drift apart silently."
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
		"the two paths a swap touches must be exactly the entry's removable set (FR-028)")
}

// TestSwapMatchesTheGateAtEveryDestinationShape is the differential: the same
// shape is swapped twice, once by the gate's sequence and once by Swap, and the
// two must land in the same place. Expected states come from gateState, which
// compares full contents against both manifests rather than reading a marker.
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

// TestSwapConvergesAfterAnInterruptionAtEveryStep drives the crash through the
// gate — a crash is not something Swap can be asked to do — and then runs the
// real Swap over the wreckage. The flags are hand-derived from the sequence: a
// crash in the dest-absent window leaves an aside to RECLAIM, a crash after the
// new version is in leaves one to DISCARD.
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

// TestSwapReclaimsRatherThanDiscardsALeftoverAside is step 1's negative
// control. An implementation that discarded the leftover passes every test
// above and fails this one: after a crash in the dest-absent window, a second
// failure would leave the entry gone for good.
func TestSwapReclaimsRatherThanDiscardsALeftoverAside(t *testing.T) {
	f := newGateFixture(t)
	f.installOld(t)
	f.stageNew(t)

	_, err := gateSwap(f.staging, f.dest, gateStepAsided)
	require.ErrorIs(t, err, errGateInterrupted)
	require.Equal(t, gateStateAbsent, gateState(t, f.dest))
	require.Equal(t, gateStateOld, gateState(t, f.aside))

	// This run fails at step 3 — the staged tree is missing, standing in for any
	// step-3 failure.
	missing := filepath.Join(filepath.Dir(f.staging), "sha256-never-staged")
	res, err := Swap(missing, f.dest)
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist, "the specific failure must be the missing staged tree")
	require.True(t, res.Reclaimed)
	require.Equal(t, gateStateOld, gateState(t, f.dest),
		"step 1 must reclaim the leftover aside so step 3 has something to roll back to")
}

// TestSwapRollsBackToTheOldVersionOnAStepThreeFailure — FR-015's "leave the
// machine unchanged for it", applied to a swap that has already moved the old
// version aside.
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

// TestSwapReplacesRatherThanMerges — the control against a CopyDir
// implementation. only-in-old.md is in the old tree and not the new, so a merge
// leaves it behind.
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

// TestSwapReplacesASymlinkAtTheDestinationWithoutWritingThroughIt is the FR-020
// half of R3's decision. The guard against touching a symlink at all belongs to
// the caller (FR-028/FR-029 plus --force); Swap is unconditional, and what it
// must never do is follow the link.
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
		"FR-020: nothing may be written or removed outside the home, and removing the aside must remove the link and not its target")
}

// TestSwapRefusesAStagedTreeThatIsNotASibling. The refusal is structural and
// fires before any rename, which is stronger than waiting for EXDEV: a path
// elsewhere in the tree may be on the same filesystem on the machine it was
// written on and on another mount on the next one.
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

// TestCrossDeviceIsRefusedAndNeverCopied covers the EXDEV branch.
//
// NOT ESTABLISHED, and this is why the test is shaped like this: a real EXDEV
// cannot be reached through Swap on this machine. The root is confined to the
// destination's parent, so a second filesystem can only appear as a mount point
// or a symlink INSIDE that parent — a mount needs privileges, and os.Root
// refuses to traverse a symlink that leaves the root (measured: "path escapes
// from parent"). So the mapping is asserted on the classifier directly, and the
// Windows ERROR_NOT_SAME_DEVICE(17) branch remains unexercised exactly as gate
// R3 recorded.
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

// TestSwapReportsALeftoverAsideRatherThanFailingTheEntry — step 5 is non-fatal.
// The failure is constructed by making the old tree unremovable (its own mode
// forbids unlinking its children), which is the portable stand-in for the
// Windows case that motivates the rule: an open handle in the old tree makes
// RemoveAll fail routinely, and failing the entry there reports a broken install
// for a working one.
func TestSwapReportsALeftoverAsideRatherThanFailingTheEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows: directory modes do not prevent unlinking; the motivating case there is an open handle")
	}
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
	// The aside is left PARTIALLY removed here — RemoveAll unlinks what it can
	// before it hits the mode that stops it — and that is fine and worth pinning:
	// the aside is not authoritative for anything. dest is wholly the new version,
	// which is the property FR-024 is about, and the leftover is only a path to
	// clean up.
	require.NotEqual(t, gateStateAbsent, gateState(t, f.aside))

	// The leftover is inside the entry's removable set, so the next run cleans it
	// with no glob and nothing remembered across runs.
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

// TestSwapIsIdempotent — FR-025 for the swap alone: re-installing the same
// version leaves the destination byte-identical and the parent directory holding
// nothing but the destination and the staging root.
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
