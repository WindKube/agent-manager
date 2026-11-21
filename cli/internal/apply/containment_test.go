// Nothing is written outside the home, checked on the resolved path. Both
// directions are asserted: a symlink out of the home is refused, and one to
// elsewhere inside it still works, or the check would just mean "no symlinks".

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

// containFixture holds a home and a sibling directory outside it.
type containFixture struct {
	sandbox string
	home    string
	outside string
}

func newContainFixture(t *testing.T) containFixture {
	t.Helper()
	// On darwin t.TempDir() is under /var, a symlink to /private/var; resolve
	// once so fixture paths match what Contains returns.
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
	require.Len(t, res.Refusals(), 1, "containment is a refusal the user can fix, not an internal failure")

	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before),
		"nothing at all was written outside the home")
	entries, rerr := os.ReadDir(elsewhere)
	require.NoError(t, rerr)
	require.Empty(t, entries, "not even the skills directory was created through the link")
}

// TestSyncFollowsAnAgentDirectorySymlinkedElsewhereInsideTheHome uses an
// absolute link, as `ln -s ~/dotfiles/claude ~/.claude` makes, which a
// structural os.Root check would refuse.
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

	body, rerr := os.ReadFile(filepath.Join(dotfiles, "skills", "acme--lint-go", "SKILL.md"))
	require.NoError(t, rerr)
	require.Equal(t, "---\nname: lint-go\n---\nthe body\n", string(body))

	// The record stores the requested path, or the next plan sees a relocation.
	rec, rerr := record.Load(filepath.Join(f.home, ".agent-manager", "hub", record.FileName), applyHub)
	require.NoError(t, rerr)
	require.Len(t, rec.Refs(), 1)
	require.Equal(t, filepath.Join(f.home, ".claude", "skills", "acme--lint-go"), rec.Refs()[0].Entry.Dest)

	require.Empty(t, escapedPaths(t, f.sandbox, f.home, before))
}

// TestOsRootRefusesAnAbsoluteSymlinkEvenInsideTheRoot pins why Home.Contains
// is not an os.Root on the home: that would break a symlinked ~/.claude.
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

	h, err := OpenHome(f.home)
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".rel-inside", "skills", "acme--lint-go"))
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".abs-inside", "skills", "acme--lint-go"))
	require.NoError(t, err)
	_, err = h.Contains(filepath.Join(f.home, ".rel-outside", "skills", "acme--lint-go"))
	require.ErrorIs(t, err, ErrOutsideHome)
}

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
		"the resolved path is what containment was checked on")
}

func TestACompletedSyncTouchesNoPathOutsideTheHome(t *testing.T) {
	f := newContainFixture(t)

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

// TestTheContainmentWalkFailsOnAPlantedEscape is the walk's negative control.
// It plants the escape via Stage and Swap, which never check containment; only
// Apply calls Home.Contains.
func TestTheContainmentWalkFailsOnAPlantedEscape(t *testing.T) {
	f := newContainFixture(t)
	before := walkTree(t, f.sandbox)

	escape := filepath.Join(f.outside, "claude", "skills", "acme--lint-go")
	bundle := skillBundle(t)
	d, err := record.ParseDigest(cache.Compute(bundle).Lockfile())
	require.NoError(t, err)
	staged, err := Stage(context.Background(), StageRequest{Dest: escape, Digest: d, Bundle: bundle})
	require.NoError(t, err, "Stage is unconditional by design: it is not where containment lives")
	_, err = Swap(staged.Path, escape)
	require.NoError(t, err)

	escaped := escapedPaths(t, f.sandbox, f.home, before)
	require.NotEmpty(t, escaped, "THE WALK MUST BE ABLE TO FAIL; if this is empty the assertion above is vacuous")
	require.Contains(t, escaped, relTo(t, f.sandbox, filepath.Join(escape, "SKILL.md")))

	// The walk still reports `outside` itself, whose mtime the removal moved.
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

// escapedPaths is every path under sandbox that changed since before and is
// not inside home. The home's parent chain is exempt, as the fixture created it.
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
