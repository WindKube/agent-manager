// This file measures idempotence on the FILESYSTEM, not on the CLI's report.
//
// The claim is "a second run against an unchanged hub makes no filesystem
// modification", and the only witness worth having is the filesystem itself. A
// build that re-downloaded every bundle, re-extracted it, re-swapped the
// destination and rewrote state.json with byte-identical content would report
// "nothing to do" and exit 0 quite happily — every counter it keeps is a
// counter of what it DECIDED, not of what it wrote. sync_test.go's
// TestASecondSyncChangesNothing asserts the verb's own account; this file
// asserts the tree, over the whole home: the agent directories, the
// hand-written skill beside them, `~/.agent-manager/<hub>/state.json` and the
// bundle cache.
//
// # THE FIVE CHANNELS, AND WHICH FAILURE EACH ONE CATCHES
//
// A single signal is not enough, because the three shapes a broken sync takes
// are each invisible to some of them:
//
//   - the path set — an added or removed file. Granularity-free.
//   - content sha256, size, mode, symlink target — a re-extract that produced
//     different bytes, and a permission change (which moves ctime, not mtime,
//     so no timestamp check sees it at all).
//   - mtime — an IN-PLACE rewrite of identical bytes. This is the only channel
//     that sees it: same path, same size, same hash, same inode. It is
//     therefore not corroboration here, it is the primary signal for the most
//     likely defect, which is why the granularity work below is not optional.
//   - file identity (os.SameFile) — an atomic swap that replaces the
//     destination with identical bytes. If the extractor ever restored mtimes
//     from the archive header, mtime would go blind and this is what still
//     fires. Sound in ONE direction only: SameFile false proves a replacement,
//     SameFile true does not prove there was none — an inode number can be
//     reused. Used as a detector, never as a licence.
//   - the request log — run two must not re-download a bundle. The cache is
//     the second most likely place for a silent rewrite, and a re-download that
//     landed identical bytes is invisible to every channel above (cache.Put
//     writes the same file), so it is observed on the wire.
//
// # MTIME GRANULARITY, WHICH IS A REAL TRAP AND IS MEASURED, NOT ASSUMED
//
// Many filesystems store 1-second mtimes; HFS+ is 1 s and exFAT is 2 s. Two
// syncs inside one tick have identical mtimes whatever happened between them,
// so an mtime comparison over a fast test would be quietly vacuous — passing
// because it cannot see, which is the failure mode this suite's rules single
// out. idemMtimeSettle measures the property actually needed — "after how long
// is a write DISTINGUISHABLE by stored mtime here?" — by writing, sleeping and
// writing again with a doubling delay, and the test then waits that long
// between the two syncs. So any write run two performs lands in a later tick
// than run one's, on whatever filesystem the suite happens to be on. If no
// delay up to four seconds separates two writes, the mtime channel is dropped
// with a loud log and the other four still carry the assertion; papering over
// it by comparing mtimes anyway would be worse than saying so.
//
// TestTheIdempotenceCheckSeesWhatABrokenSyncWouldDo and
// TestARealReinstallOfIdenticalBytesIsSeenByThisCheck are the negative
// controls: eight synthetic mutations, one per channel, plus a re-install
// driven by production code. Without them "no differences" is a claim about a
// comparison nobody proved could fail.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/output"
)

// ---------------------------------------------------------------- snapshots

// idemNode is one path as it exists on disk. info is kept so os.SameFile can
// answer the identity question, which needs the FileInfo and not a field of it:
// the inode number lives in a per-platform Sys() value, and os.SameFile is the
// portable way to ask.
type idemNode struct {
	dir   bool
	mode  fs.FileMode
	size  int64
	sha   string
	link  string
	mtime time.Time
	info  fs.FileInfo
}

// idemSnapshot walks every path under home, including `~/.agent-manager`.
//
// Lstat, not Stat: a symlink is recorded as a symlink and its target string
// compared, because a check that followed links could not tell a replaced link
// from an unchanged one.
//
// Directory mtimes ARE recorded, unlike sync_test.go's treeSnapshot, which
// drops them because the per-home lock and the record's temp file move the
// state root's own mtime on every run. Dropping them would miss a directory
// whose child was re-created, so they are kept and the one directory that
// legitimately moves is named, asserted to move, and excluded by name.
func idemSnapshot(t *testing.T, home string) map[string]idemNode {
	t.Helper()
	out := map[string]idemNode{}
	err := filepath.WalkDir(home, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(home, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		info, ierr := os.Lstat(p)
		if ierr != nil {
			return ierr
		}
		n := idemNode{
			dir:   info.IsDir(),
			mode:  info.Mode(),
			size:  info.Size(),
			mtime: info.ModTime(),
			info:  info,
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			n.link, ierr = os.Readlink(p)
			if ierr != nil {
				return ierr
			}
		case info.Mode().IsRegular():
			b, berr := os.ReadFile(p) //nolint:gosec // a test reading its own temp home
			if berr != nil {
				return berr
			}
			sum := sha256.Sum256(b)
			n.sha = hex.EncodeToString(sum[:])
		}
		out[filepath.ToSlash(rel)] = n
		return nil
	})
	require.NoError(t, err)
	return out
}

// idemChange is one difference between two snapshots. Structured rather than a
// string so the test can decide per CHANNEL what is allowed, instead of
// pattern-matching its own error messages.
type idemChange struct {
	rel    string
	what   string
	detail string
}

func (c idemChange) String() string { return fmt.Sprintf("%s: %s (%s)", c.rel, c.what, c.detail) }

// idemDiff reports every difference between two snapshots of the same home.
//
// withMtime is false only when idemMtimeSettle could not establish that this
// filesystem distinguishes two writes at all; see the package comment.
func idemDiff(before, after map[string]idemNode, withMtime bool) []idemChange {
	var out []idemChange
	add := func(rel, what, format string, args ...any) {
		out = append(out, idemChange{rel: rel, what: what, detail: fmt.Sprintf(format, args...)})
	}
	for rel, b := range before {
		a, ok := after[rel]
		if !ok {
			add(rel, "removed", "present in the first snapshot, gone in the second")
			continue
		}
		switch {
		case b.mode.Type() != a.mode.Type():
			// A kind change is reported INSTEAD of the field comparisons: the
			// hash of a file and the target of a symlink are not comparable
			// quantities, and reporting five differences for one event buries
			// the one that says what happened.
			add(rel, "kind", "%s -> %s", b.mode.Type(), a.mode.Type())
			continue
		case b.mode != a.mode:
			add(rel, "mode", "%s -> %s", b.mode, a.mode)
		}
		if b.size != a.size {
			add(rel, "size", "%d -> %d bytes", b.size, a.size)
		}
		if b.sha != a.sha {
			add(rel, "content", "sha256 %s -> %s", short(b.sha), short(a.sha))
		}
		if b.link != a.link {
			add(rel, "link", "%q -> %q", b.link, a.link)
		}
		if !os.SameFile(b.info, a.info) {
			add(rel, "identity", "replaced by a different file, so something renamed or re-created it")
		}
		if withMtime && !b.mtime.Equal(a.mtime) {
			add(rel, "mtime", "%s -> %s", b.mtime.Format(time.RFC3339Nano), a.mtime.Format(time.RFC3339Nano))
		}
	}
	for rel := range after {
		if _, ok := before[rel]; !ok {
			add(rel, "added", "absent from the first snapshot")
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].rel != out[j].rel {
			return out[i].rel < out[j].rel
		}
		return out[i].what < out[j].what
	})
	return out
}

func short(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

func idemHasChange(changes []idemChange, rel, what string) bool {
	for _, c := range changes {
		if c.rel == rel && c.what == what {
			return true
		}
	}
	return false
}

func idemChangesFor(changes []idemChange, rel string) []idemChange {
	var out []idemChange
	for _, c := range changes {
		if c.rel == rel {
			out = append(out, c)
		}
	}
	return out
}

func idemLines(changes []idemChange) string {
	if len(changes) == 0 {
		return "  (none)"
	}
	lines := make([]string, 0, len(changes))
	for _, c := range changes {
		lines = append(lines, "  "+c.String())
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- mtime granularity

// idemMtimeSettle measures how long the test filesystem needs before a write is
// distinguishable by stored mtime, and returns a delay to wait between the two
// syncs plus whether mtime is usable as a channel at all.
//
// It measures the property the test needs rather than "the granularity": write,
// stat, sleep d, write, stat, and double d until the two stored mtimes differ.
// That is one measurement instead of a chain of inferences from a claimed tick
// size, and it is correct on a 1 s HFS+ volume, a 2 s exFAT one and a
// nanosecond tmpfs alike. The returned delay is twice the first d that worked,
// for slack against a boundary landing badly.
func idemMtimeSettle(t *testing.T) (time.Duration, bool) {
	t.Helper()
	// A directory of its own, on the same filesystem as the test home (both come
	// from t.TempDir): probing inside the home would move the very mtimes the
	// test is about to compare.
	path := filepath.Join(t.TempDir(), "mtime-probe")
	write := func(i int) time.Time {
		require.NoError(t, os.WriteFile(path, []byte{byte(i)}, 0o600))
		info, err := os.Stat(path)
		require.NoError(t, err)
		return info.ModTime()
	}
	i := 0
	for d := time.Millisecond; d <= 4*time.Second; d *= 2 {
		i++
		before := write(i)
		time.Sleep(d)
		i++
		after := write(i)
		if !after.Equal(before) {
			t.Logf("mtime channel: two writes %s apart are distinguishable here (%s vs %s, "+
				"nanosecond fields %d and %d); waiting %s between the two syncs",
				d, before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano),
				before.Nanosecond(), after.Nanosecond(), 2*d)
			return 2 * d, true
		}
	}
	// Not a skip and not a failure: the other four channels still hold, and
	// saying so is better than comparing timestamps that cannot differ.
	t.Logf("mtime channel DROPPED: no delay up to 4s made two writes distinguishable on this "+
		"filesystem (%s), so an identical in-place rewrite cannot be detected by mtime here; "+
		"the path set, content hashes, modes and file identity still carry the assertion", path)
	return 0, false
}

// ---------------------------------------------------------------- request log

// idemRequestLog records request paths in order. It is how "run two did not
// re-download a bundle" is observed on the wire rather than inferred from the
// CLI's report, which is the whole point of this file.
type idemRequestLog struct {
	next http.RoundTripper

	mu   sync.Mutex
	seen []string
}

func (l *idemRequestLog) RoundTrip(req *http.Request) (*http.Response, error) {
	l.mu.Lock()
	l.seen = append(l.seen, req.Method+" "+req.URL.Path)
	l.mu.Unlock()
	next := l.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

func (l *idemRequestLog) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

func (l *idemRequestLog) since(mark int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen[mark:]...)
}

// idemEnv wires a sync env with the request log spliced in front of the
// transport the fake handed over, so TLS still verifies.
func idemEnv(t *testing.T) (*syncEnv, *idemRequestLog, syncFlags) {
	t.Helper()
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	log := &idemRequestLog{next: env.deps.httpClient.Transport}
	env.deps.httpClient = &http.Client{Transport: log}
	// The decoys are not decoration here: without them "the other agent
	// directories were not touched" would be a statement about directories that
	// do not exist, and the hand-written skill in ~/.claude/skills is the path
	// this check protects.
	plantDecoyAgentDirectories(t, env.home)
	return env, log, baselineFlags(tg)
}

// idemRel is a path's key in a snapshot: home-relative and slash-separated.
func idemRel(t *testing.T, home, path string) string {
	t.Helper()
	rel, err := filepath.Rel(home, path)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

// installedSkills are the directories the fake's healthy profile installs, in
// their disambiguated form. Hand-written from the fixture rather
// than read back from the tree, so a run that installed nothing fails here
// instead of making the whole measurement vacuous.
var installedSkills = []string{"acme--code-review", "acme--lint-guard", "example--doc-writer"}

// ---------------------------------------------------------------- the property

func TestASecondSyncModifiesNothingOnDisk(t *testing.T) {
	env, log, flags := idemEnv(t)
	settle, mtimeUsable := idemMtimeSettle(t)

	code, _, diag, err := env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code, "the first sync must actually install something")
	require.Equal(t, append(installedSkills, "my-own-skill"), skillDirs(t, env.skillsRoot()),
		"the measurement is worthless unless the first run installed the whole profile")

	first := idemSnapshot(t, env.home)
	require.NotEmpty(t, first)
	recordRel := idemRel(t, env.home, env.recordPath(t))
	require.Contains(t, first, recordRel, "the record must exist before its non-modification means anything")

	mark := log.mark()
	time.Sleep(settle)

	code, result, diag, err := env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code)
	require.Contains(t, result.String(), "nothing to do")

	second := idemSnapshot(t, env.home)
	changes := idemDiff(first, second, mtimeUsable)

	// The self-check. `~/.agent-manager` gets the write probe and the sync
	// lock created and unlinked inside it on EVERY run, so its own mtime must
	// move. If it did not, the settle was too short or mtime is not being
	// compared, and every "unchanged" assertion below would be passing because
	// it cannot see rather than because nothing happened.
	if mtimeUsable {
		require.True(t, idemHasChange(changes, DirName, "mtime"),
			"the write probe and the sync lock are created and unlinked inside %s on every run, so its "+
				"mtime MUST have moved; that it did not means this test's mtime channel is dead:\n%s",
			DirName, idemLines(changes))
	}

	// The record first, and ahead of the general comparison rather than after it,
	// because a `require` stops at the first failure: behind the sweep below this
	// assertion could never fire and would be a dead check with a good message.
	// It earns its place because it is the most likely violation that LOOKS
	// legitimate — record.Save returns `wrote bool` and skips a write whose bytes
	// match, so a moved mtime here is a real defect and not a test artefact.
	require.Empty(t, idemChangesFor(changes, recordRel),
		"FR-025: %s was rewritten by the second sync; record.Save must skip a write whose bytes are "+
			"unchanged:\n%s", recordRel, idemLines(idemChangesFor(changes, recordRel)))

	// Everything else must be untouched. The state root itself is excluded by
	// NAME, and only for mtime and size — the two fields a created-and-unlinked
	// child can move — never for its contents, which are compared path by path
	// like every other path. Measured on this filesystem, mtime is the only one
	// that actually moves and the whole difference list after run two is one
	// line; size is allowed as well because a directory's reported size is
	// block-granular and a transient child grows it on some filesystems, which
	// would otherwise fail this test for the lock rather than for the tree.
	var offenders []idemChange
	for _, c := range changes {
		if c.rel == DirName && (c.what == "mtime" || c.what == "size") {
			continue
		}
		offenders = append(offenders, c)
	}
	require.Empty(t, offenders,
		"FR-025/SC-002: the second sync modified the filesystem:\n%s", idemLines(offenders))

	// And the cache: run two must not re-download. A re-download that landed
	// identical bytes leaves no trace on disk at all, so it is observed here.
	after := log.since(mark)
	require.NotEmpty(t, after, "the second run must really have talked to the hub")
	var bundles []string
	for _, p := range after {
		if strings.Contains(p, "/v1/bundles/") {
			bundles = append(bundles, p)
		}
	}
	require.Empty(t, bundles, "FR-025: the second sync re-downloaded %d bundle(s): %v", len(bundles), bundles)
	require.Condition(t, func() bool {
		for _, p := range after {
			if strings.Contains(p, "/revisions/") {
				return true
			}
		}
		return false
	}, "the second run must have fetched the lockfile, or it did nothing and proved nothing: %v", after)
}

// ---------------------------------------------------------------- negative controls

func TestTheIdempotenceCheckSeesWhatABrokenSyncWouldDo(t *testing.T) {
	// Each case is a mutation a plausibly broken sync performs on run two,
	// applied to a converged tree, and the assertion is that idemDiff names the
	// path and the channel. Without this the property test's "no differences" is
	// unfalsifiable.
	settle, mtimeUsable := idemMtimeSettle(t)

	skillDir := func(env *syncEnv) string { return filepath.Join(env.skillsRoot(), installedSkills[0]) }

	cases := []struct {
		name string
		// mutate performs the mutation and returns the home-relative path whose
		// change is expected.
		mutate func(t *testing.T, env *syncEnv) string
		what   string
		// needsMtime marks the mutations that ONLY mtime can see.
		needsMtime bool
	}{
		{
			name: "an identical in-place rewrite of an installed file is caught, and only mtime can see it",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := filepath.Join(skillDir(env), "SKILL.md")
				rewriteIdentically(t, p)
				return idemRel(t, env.home, p)
			},
			what:       "mtime",
			needsMtime: true,
		},
		{
			name: "an identical in-place rewrite of the installation record is caught",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := env.recordPath(t)
				rewriteIdentically(t, p)
				return idemRel(t, env.home, p)
			},
			what:       "mtime",
			needsMtime: true,
		},
		{
			name: "a directory whose child was re-created is caught by its mtime",
			mutate: func(t *testing.T, env *syncEnv) string {
				dir := filepath.Join(skillDir(env), "references")
				p := filepath.Join(dir, ".transient")
				require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
				require.NoError(t, os.Remove(p))
				return idemRel(t, env.home, dir)
			},
			what:       "mtime",
			needsMtime: true,
		},
		{
			name: "a re-extract that produced different bytes is caught by the content hash",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := filepath.Join(skillDir(env), "SKILL.md")
				b, err := os.ReadFile(p) //nolint:gosec // a test reading its own temp home
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(p, append(b, '\n'), 0o600))
				return idemRel(t, env.home, p)
			},
			what: "content",
		},
		{
			name: "an atomic swap that preserved both the bytes and the mtime is caught by file identity",
			mutate: func(t *testing.T, env *syncEnv) string {
				// The extractor sets no timestamps today, so this models the
				// build in which it starts restoring them from the archive
				// header: same path, same bytes, same mode, same mtime, new
				// inode. mtime and the hash both go blind; identity does not.
				p := filepath.Join(skillDir(env), "SKILL.md")
				info, err := os.Lstat(p)
				require.NoError(t, err)
				b, err := os.ReadFile(p) //nolint:gosec // a test reading its own temp home
				require.NoError(t, err)
				tmp := p + ".replacement"
				require.NoError(t, os.WriteFile(tmp, b, info.Mode().Perm()))
				require.NoError(t, os.Chtimes(tmp, info.ModTime(), info.ModTime()))
				require.NoError(t, os.Rename(tmp, p))
				return idemRel(t, env.home, p)
			},
			what: "identity",
		},
		{
			name: "a file added under an installed entry is caught",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := filepath.Join(skillDir(env), "extra.md")
				require.NoError(t, os.WriteFile(p, []byte("new\n"), 0o600))
				return idemRel(t, env.home, p)
			},
			what: "added",
		},
		{
			name: "a file removed from an installed entry is caught",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := filepath.Join(skillDir(env), "SKILL.md")
				require.NoError(t, os.Remove(p))
				return idemRel(t, env.home, p)
			},
			what: "removed",
		},
		{
			name: "a permission-only change is caught, which no timestamp check would see",
			mutate: func(t *testing.T, env *syncEnv) string {
				p := filepath.Join(skillDir(env), "scripts", "check.sh")
				info, err := os.Lstat(p)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(p, info.Mode().Perm()^0o111))
				return idemRel(t, env.home, p)
			},
			what: "mode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needsMtime && !mtimeUsable {
				t.Skip("mtime is not a usable channel on this filesystem; see idemMtimeSettle's log")
			}
			env, _, flags := idemEnv(t)
			_, _, diag, err := env.run(t, output.FormatHuman, flags)
			require.NoError(t, err, diag.String())

			before := idemSnapshot(t, env.home)
			time.Sleep(settle)
			rel := tc.mutate(t, env)
			after := idemSnapshot(t, env.home)

			changes := idemDiff(before, after, mtimeUsable)
			require.True(t, idemHasChange(changes, rel, tc.what),
				"the check missed a %s change at %s; it reported:\n%s", tc.what, rel, idemLines(changes))
		})
	}
}

// rewriteIdentically writes a file's own bytes back over it, preserving its
// mode. This is what a sync that re-installs unconditionally does to every file
// it manages, and the reason the mtime channel exists.
func rewriteIdentically(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	b, err := os.ReadFile(path) //nolint:gosec // a test reading its own temp home
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, info.Mode().Perm()))
}

// TestARealReinstallOfIdenticalBytesIsSeenByThisCheck is the negative control
// driven by PRODUCTION code rather than by a synthetic touch, which is the only
// kind that proves the check would fire against a real defect.
//
// Deleting the record puts the second sync in exactly the state a build with
// broken change detection is in permanently: every entry looks like an install.
// apply's guard finds amctl's own marker at the destination with no record
// row — its "interrupted between the install and the record write" case — and
// re-installs, which re-extracts and re-swaps BYTE-IDENTICAL content. The
// verb's own report is honest about what it decided; only the filesystem
// knows the work was done twice.
func TestARealReinstallOfIdenticalBytesIsSeenByThisCheck(t *testing.T) {
	env, log, flags := idemEnv(t)
	settle, mtimeUsable := idemMtimeSettle(t)

	_, _, diag, err := env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())

	first := idemSnapshot(t, env.home)
	handWritten := idemRel(t, env.home, filepath.Join(env.skillsRoot(), "my-own-skill", "SKILL.md"))
	require.Contains(t, first, handWritten)

	mark := log.mark()
	time.Sleep(settle)
	require.NoError(t, os.Remove(env.recordPath(t)))

	code, _, diag, err := env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code, "a re-install is a change, and the verb says so")

	changes := idemDiff(first, idemSnapshot(t, env.home), mtimeUsable)
	skillRel := idemRel(t, env.home, filepath.Join(env.skillsRoot(), installedSkills[0], "SKILL.md"))
	require.True(t, idemHasChange(changes, skillRel, "identity"),
		"the swap replaced %s with identical bytes and the check did not notice, so it could not have "+
			"noticed a broken sync doing the same thing on every run; it reported:\n%s",
		skillRel, idemLines(changes))

	// The same run must still not have touched the hand-written skill beside
	// the installed ones, and must not have re-downloaded: the cache still
	// holds every bundle, so a re-install is a local operation.
	require.Empty(t, idemChangesFor(changes, handWritten),
		"a forced re-install modified a path amctl's record never claimed")
	for _, p := range log.since(mark) {
		require.NotContains(t, p, "/v1/bundles/",
			"the re-install re-downloaded a bundle the cache already held")
	}
}
