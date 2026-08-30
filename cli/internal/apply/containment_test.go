// T042a — FR-020: nothing is written outside the invoking user's home, and the
// check is on the RESOLVED path.
//
// Symlinked agent directories are what make this a real question rather than a
// tautology. `~/.claude` is frequently a symlink into a dotfiles repo, so a
// destination that is lexically under $HOME says nothing about where the bytes
// land, and `~/.claude -> /etc/whatever` is how amctl would write outside the
// home without ever constructing a path outside it. Both directions are
// asserted here: a link OUT is refused, a link to another place INSIDE the home
// still works. Only asserting the first would leave a check that means "no
// symlinks", which breaks the setup R3 says is common.
//
// The destinations in this file come from internal/layout's real registry, not
// from a hand-written path, so what is proved is about the paths amctl actually
// derives.

package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// containFixture is a sandbox holding a home and a sibling directory that is
// deliberately NOT in the home, so "outside" is a real place on this filesystem
// that a walk can inspect rather than an abstraction.
type containFixture struct {
	sandbox string
	home    string
	outside string
}

func newContainFixture(t *testing.T) containFixture {
	t.Helper()
	// EvalSymlinks on the sandbox root, because Home.Contains resolves the path
	// it checks and this fixture compares against paths it built itself. On
	// darwin t.TempDir() hands back /var/folders/..., and /var is a symlink to
	// /private/var — so an unresolved fixture path and a resolved Contains
	// result differ by a prefix that has nothing to do with what is being
	// tested. Resolving here once puts the whole fixture in the same space as
	// the code under test rather than teaching each assertion to compensate.
	sandbox, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	f := containFixture{
		sandbox: sandbox,
		home:    filepath.Join(sandbox, "home"),
		outside: filepath.Join(sandbox, "outside"),
	}
	require.NoError(t, os.MkdirAll(f.home, 0o755))
	require.NoError(t, os.MkdirAll(f.outside, 0o755))
	return f
}

func requireSymlinks(t *testing.T) {
	t.Helper()
	if err := os.Symlink("target", filepath.Join(t.TempDir(), "probe")); err != nil {
		t.Skipf("unprivileged symlinks unavailable on %s: %v", runtime.GOOS, err)
	}
}

// destFor asks internal/layout where an entry goes, through the real registry.
func destFor(t *testing.T, home, id string) string {
	t.Helper()
	reg, err := layout.NewRegistry(layout.Config{HomeDir: home})
	require.NoError(t, err)
	target, err := reg.Resolve(record.TargetClaudeCode)
	require.NoError(t, err)
	p, err := target.Place(layout.Request{ID: id, Version: "1.0.0", Kind: record.KindSkill})
	require.NoError(t, err)
	return p.Dest
}

// syncInto runs a real one-entry sync against home and returns the error.
func syncInto(t *testing.T, home, id string) (*Result, error) {
	t.Helper()
	f := newApplyFixture(t)
	f.home = home
	f.skills = filepath.Join(home, ".claude", "skills")
	f.recPath = filepath.Join(home, ".agent-manager", "hub", record.FileName)

	c := f.add(t, id, "1.0.0", skillBundle(t))
	c.Dest = destFor(t, home, id)
	return f.applier(t).Apply(context.Background(), planOf(c))
}

// ---------------------------------------------------------------------------
// the two symlink directions
// ---------------------------------------------------------------------------

// TestSyncRefusesAnAgentDirectorySymlinkedOutOfTheHome is the FR-020 case that
// matters: every path amctl constructs is under $HOME and the bytes would land
// in /etc.
func TestSyncRefusesAnAgentDirectorySymlinkedOutOfTheHome(t *testing.T) {
	requireSymlinks(t)
	f := newContainFixture(t)
	elsewhere := filepath.Join(f.outside, "claude")
	require.NoError(t, os.MkdirAll(elsewhere, 0o755))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(f.home, ".claude")))

	before := walkTree(t, f.sandbox)
	res, err := syncInto(t, f.home, "acme/lint-go")
	require.ErrorIs(t, err, ErrOutsideHome)
	require.Empty(t, res.Installed)
	require.Len(t, res.Refusals(), 1, "FR-020 is a refusal the user can fix, not an internal failure")

	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before),
		"nothing at all was written outside the home")
	entries, rerr := os.ReadDir(elsewhere)
	require.NoError(t, rerr)
	require.Empty(t, entries, "not even the skills directory was created through the link")
}

// TestSyncFollowsAnAgentDirectorySymlinkedElsewhereInsideTheHome is the other
// half, and without it the check above would be indistinguishable from "amctl
// refuses symlinks" — which breaks the dotfiles-repo setup R3 calls common.
//
// The link is ABSOLUTE on purpose: that is what `ln -s ~/dotfiles/claude
// ~/.claude` produces, and it is the case a structural os.Root check refuses.
// See TestOsRootRefusesAnAbsoluteSymlinkEvenInsideTheRoot.
func TestSyncFollowsAnAgentDirectorySymlinkedElsewhereInsideTheHome(t *testing.T) {
	requireSymlinks(t)
	f := newContainFixture(t)
	dotfiles := filepath.Join(f.home, "dotfiles", "claude")
	require.NoError(t, os.MkdirAll(dotfiles, 0o755))
	require.NoError(t, os.Symlink(dotfiles, filepath.Join(f.home, ".claude")))

	before := walkTree(t, f.sandbox)
	res, err := syncInto(t, f.home, "acme/lint-go")
	require.NoError(t, err, "a dotfiles-repo symlink inside the home is a supported setup")
	require.Len(t, res.Installed, 1)

	// The bytes are through the link, in the dotfiles repo.
	body, rerr := os.ReadFile(filepath.Join(dotfiles, "skills", "acme--lint-go", "SKILL.md"))
	require.NoError(t, rerr)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body))

	// The RECORD stores the requested path, not the resolved one: the record's
	// destination has to be the path internal/layout derives, or the next run's
	// plan reads it as a relocation and removes and re-adds the entry forever.
	rec, rerr := record.Load(filepath.Join(f.home, ".agent-manager", "hub", record.FileName), applyHub)
	require.NoError(t, rerr)
	require.Len(t, rec.Refs(), 1)
	require.Equal(t, filepath.Join(f.home, ".claude", "skills", "acme--lint-go"), rec.Refs()[0].Entry.Dest)

	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before))
}

// TestOsRootRefusesAnAbsoluteSymlinkEvenInsideTheRoot pins the measurement that
// decides why the containment check is not os.Root doing it structurally.
//
// If a later change "simplifies" Home.Contains into a root opened on the home,
// this test is what says the dotfiles case broke — rather than a bug report six
// months later from somebody whose ~/.claude is a link.
func TestOsRootRefusesAnAbsoluteSymlinkEvenInsideTheRoot(t *testing.T) {
	requireSymlinks(t)
	f := newContainFixture(t)
	inside := filepath.Join(f.home, "dotfiles", "claude", "skills")
	require.NoError(t, os.MkdirAll(inside, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(f.outside, "skills"), 0o755))

	require.NoError(t, os.Symlink("dotfiles/claude", filepath.Join(f.home, ".rel-inside")))
	require.NoError(t, os.Symlink(filepath.Join("..", "outside"), filepath.Join(f.home, ".rel-outside")))
	require.NoError(t, os.Symlink(filepath.Join(f.home, "dotfiles", "claude"), filepath.Join(f.home, ".abs-inside")))

	root, err := os.OpenRoot(f.home)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	_, err = root.Lstat(filepath.Join(".rel-inside", "skills"))
	require.NoError(t, err, "a relative link inside the root is allowed")

	_, err = root.Lstat(filepath.Join(".rel-outside", "skills"))
	require.Error(t, err, "a relative link out of the root is refused")
	require.Contains(t, err.Error(), "escapes")

	_, err = root.Lstat(filepath.Join(".abs-inside", "skills"))
	require.Error(t, err,
		"MEASURED: os.Root refuses an ABSOLUTE symlink target even when it points inside the root, "+
			"because it cannot re-anchor an absolute path. `ln -s ~/dotfiles/claude ~/.claude` is absolute, "+
			"so a structural root check on the home would refuse the commonest dotfiles setup there is")
	require.Contains(t, err.Error(), "escapes")

	// And the resolution-based check this package uses gets all three right.
	h, err := OpenHome(f.home)
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".rel-inside", "skills", "acme--lint-go"))
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".abs-inside", "skills", "acme--lint-go"))
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".rel-outside", "skills", "acme--lint-go"))
	require.ErrorIs(t, err, ErrOutsideHome)
}

// ---------------------------------------------------------------------------
// the check happens before anything is opened
// ---------------------------------------------------------------------------

func TestContainsRefusesBeforeAnythingIsCreated(t *testing.T) {
	f := newContainFixture(t)
	h, err := OpenHome(f.home)
	require.NoError(t, err)

	cases := []struct {
		name string
		dest string
	}{
		{"a sibling of the home", filepath.Join(f.outside, "skills", "acme--lint-go")},
		{"an escape by parent reference", filepath.Join(f.home, "..", "outside", "x")},
		{"the home itself", f.home},
		{"a relative path", filepath.Join(".claude", "skills", "x")},
		{"an unclean path", f.home + "/./.claude/skills/x"},
		{"the swap's aside name", filepath.Join(f.home, ".claude", "skills", "x"+AsideSuffix)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := walkTree(t, f.sandbox)
			_, cerr := h.Contains(tc.dest)
			require.Error(t, cerr)
			require.Equal(t, before, walkTree(t, f.sandbox),
				"a refused destination must not have created a single directory on the way to deciding")
		})
	}
}

func TestOpenHomeRefusesAHomeItCannotResolve(t *testing.T) {
	_, err := OpenHome("")
	require.ErrorIs(t, err, ErrOutsideHome)
	_, err = OpenHome("relative/home")
	require.ErrorIs(t, err, ErrOutsideHome)
	_, err = OpenHome(filepath.Join(t.TempDir(), "absent"))
	require.ErrorIs(t, err, ErrOutsideHome)
}

func TestContainsReportsTheResolvedPathItCheckedAndTheRequestedPathToWrite(t *testing.T) {
	requireSymlinks(t)
	f := newContainFixture(t)
	dotfiles := filepath.Join(f.home, "dotfiles", "claude")
	require.NoError(t, os.MkdirAll(dotfiles, 0o755))
	require.NoError(t, os.Symlink(dotfiles, filepath.Join(f.home, ".claude")))

	h, err := OpenHome(f.home)
	require.NoError(t, err)
	requested := filepath.Join(f.home, ".claude", "skills", "acme--lint-go")
	cont, err := h.Contains(requested)
	require.NoError(t, err)
	require.Equal(t, requested, cont.Dest, "the requested path is what gets written and recorded")
	require.Equal(t, filepath.Join(dotfiles, "skills", "acme--lint-go"), cont.Resolved,
		"the resolved path is what FR-020 was checked on")
}

// ---------------------------------------------------------------------------
// the walk over a completed sync, and the proof that it can fail
// ---------------------------------------------------------------------------

// TestACompletedSyncTouchesNoPathOutsideTheHome walks the real filesystem after
// a real multi-entry sync.
func TestACompletedSyncTouchesNoPathOutsideTheHome(t *testing.T) {
	f := newContainFixture(t)

	// Unmanaged neighbours outside the home, so the walk has something to
	// notice if anything strays.
	require.NoError(t, os.MkdirAll(filepath.Join(f.outside, "claude", "skills"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.outside, "claude", "skills", "SKILL.md"),
		[]byte("somebody else's\n"), 0o644))

	fx := newApplyFixture(t)
	fx.home = f.home
	fx.skills = filepath.Join(f.home, ".claude", "skills")
	fx.recPath = filepath.Join(f.home, ".agent-manager", "hub", record.FileName)
	one := fx.add(t, "acme/lint-go", "1.0.0", skillBundle(t))
	one.Dest = destFor(t, f.home, "acme/lint-go")
	two := fx.add(t, "beta/fmt-go", "2.3.4", skillBundle(t))
	two.Dest = destFor(t, f.home, "beta/fmt-go")

	before := walkTree(t, f.sandbox)
	res, err := fx.applier(t).Apply(context.Background(), planOf(one, two))
	require.NoError(t, err)
	require.Len(t, res.Installed, 2)

	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before),
		"a completed sync created and modified paths only inside the home")
}

// TestTheContainmentWalkFailsOnAPlantedEscape is the negative control for the
// walk above. Without it, "no path outside the home was written" is a claim
// about a helper nobody has seen fail.
//
// The escape is planted by calling Stage and Swap directly, which is exactly how
// a future caller would introduce this bug: both are unconditional by design and
// neither checks containment — Home.Contains is the only thing that does, and
// Apply is the only thing that calls it.
func TestTheContainmentWalkFailsOnAPlantedEscape(t *testing.T) {
	f := newContainFixture(t)
	before := walkTree(t, f.sandbox)

	escape := filepath.Join(f.outside, "claude", "skills", "acme--lint-go")
	bundle := skillBundle(t)
	d, err := record.ParseDigest(cache.Compute(bundle).Lockfile())
	require.NoError(t, err)
	staged, err := Stage(context.Background(), StageRequest{Dest: escape, Digest: d, Bundle: bundle})
	require.NoError(t, err, "Stage is unconditional by design: it is not where FR-020 lives")
	_, err = Swap(staged.Path, escape)
	require.NoError(t, err)

	escaped := escapedPaths(t, f.sandbox, f.home, before)
	require.NotEmpty(t, escaped, "THE WALK MUST BE ABLE TO FAIL; if this is empty the assertion above is vacuous")
	require.Contains(t, escaped, relTo(t, f.sandbox, filepath.Join(escape, "SKILL.md")))

	// Remove the planted escape and the walk stops reporting it. It still
	// reports `outside` itself, whose mtime the removal moved — which is the
	// walk being right rather than the walk being noisy: it is measuring the
	// filesystem, not amctl's account of what it did.
	require.NoError(t, os.RemoveAll(filepath.Join(f.outside, "claude")))
	after := escapedPaths(t, f.sandbox, f.home, before)
	require.NotContains(t, after, relTo(t, f.sandbox, filepath.Join(escape, "SKILL.md")))
	for _, p := range after {
		require.NotContains(t, p, "claude", "nothing the plant created is left")
	}
}

func relTo(t *testing.T, base, p string) string {
	t.Helper()
	rel, err := filepath.Rel(base, p)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

// walkTree records every path under root with the metadata a write would move.
func walkTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		info, ierr := d.Info()
		if ierr != nil {
			if errors.Is(ierr, fs.ErrNotExist) {
				return nil
			}
			return ierr
		}
		out[relTo(t, root, p)] = fmt.Sprintf("mode=%v size=%d mtime=%d",
			info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	}))
	return out
}

// escapedPaths is every path under sandbox that changed since before and is NOT
// inside home. It is the assertion FR-020 needs: a difference taken over the
// real filesystem, not over what the CLI said it did.
//
// The home's own PARENT chain is exempt because a sandbox is not a real machine:
// the parent of a home is created by whatever made the home. Nothing else is.
func escapedPaths(t *testing.T, sandbox, home string, before map[string]string) []string {
	t.Helper()
	homeRel := relTo(t, sandbox, home)
	after := walkTree(t, sandbox)

	var escaped []string
	for p, state := range after {
		if p == "." || p == homeRel || isUnder(p, homeRel) {
			continue
		}
		if was, existed := before[p]; !existed || was != state {
			escaped = append(escaped, p)
		}
	}
	sort.Strings(escaped)
	return escaped
}

func isUnder(p, dir string) bool {
	return len(p) > len(dir)+1 && p[:len(dir)] == dir && p[len(dir)] == '/'
}

// TestApplyChecksContainmentForEveryEntryNotJustTheFirst — a per-run check would
// pass every test above while letting the second entry of a two-entry plan write
// anywhere.
func TestApplyChecksContainmentForEveryEntryNotJustTheFirst(t *testing.T) {
	f := newContainFixture(t)
	fx := newApplyFixture(t)
	fx.home = f.home
	fx.skills = filepath.Join(f.home, ".claude", "skills")
	fx.recPath = filepath.Join(f.home, ".agent-manager", "hub", record.FileName)

	good := fx.add(t, "acme/lint-go", "1.0.0", skillBundle(t))
	good.Dest = destFor(t, f.home, "acme/lint-go")
	bad := fx.add(t, "zeta/escape", "1.0.0", skillBundle(t))
	bad.Dest = filepath.Join(f.outside, "claude", "skills", "zeta--escape")

	before := walkTree(t, f.sandbox)
	res, err := fx.applier(t).Apply(context.Background(), planOf(good, bad))
	require.ErrorIs(t, err, ErrOutsideHome)
	require.Len(t, res.Installed, 1)
	require.Equal(t, good.ID, res.Installed[0].Change.ID)
	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before))

	rec, rerr := record.Load(fx.recPath, applyHub)
	require.NoError(t, rerr)
	require.Len(t, rec.Refs(), 1, "the refused entry is not recorded")
}
