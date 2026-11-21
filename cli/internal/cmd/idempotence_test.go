// This file measures idempotence on the filesystem, not on the CLI's report:
// a build that rewrote everything with identical bytes would still report
// "nothing to do". Five channels each catch a different defect: the path set,
// content/mode/symlink target, mtime (the only witness of an in-place identical
// rewrite), file identity (an atomic swap), and the request log (a re-download).
// Mtime granularity is measured by idemMtimeSettle rather than assumed.
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

// idemNode keeps info so os.SameFile can answer the identity question portably.
type idemNode struct {
	dir   bool
	mode  fs.FileMode
	size  int64
	sha   string
	link  string
	mtime time.Time
	info  fs.FileInfo
}

// idemSnapshot walks every path under home with Lstat, so a replaced symlink
// is visible. Directory mtimes are kept; the state root, which legitimately
// moves on every run, is excluded by name.
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

type idemChange struct {
	rel    string
	what   string
	detail string
}

func (c idemChange) String() string { return fmt.Sprintf("%s: %s (%s)", c.rel, c.what, c.detail) }

// idemDiff reports every difference between two snapshots; withMtime is false
// when this filesystem cannot distinguish two writes.
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
			// A kind change replaces the field comparisons, which would be meaningless across kinds.
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

// idemMtimeSettle returns how long to wait between syncs so a write is
// distinguishable by stored mtime, doubling a probe delay until two writes
// differ, and whether mtime is usable at all.
func idemMtimeSettle(t *testing.T) (time.Duration, bool) {
	t.Helper()
	// Outside the test home: probing inside it would move the mtimes under test.
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
	// Not a skip: the other four channels still hold.
	t.Logf("mtime channel DROPPED: no delay up to 4s made two writes distinguishable on this "+
		"filesystem (%s), so an identical in-place rewrite cannot be detected by mtime here; "+
		"the path set, content hashes, modes and file identity still carry the assertion", path)
	return 0, false
}

// idemRequestLog records request paths, so a re-download is observed on the wire.
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

// idemEnv splices the request log in front of the fake's transport, so TLS still verifies.
func idemEnv(t *testing.T) (*syncEnv, *idemRequestLog, syncFlags) {
	t.Helper()
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	log := &idemRequestLog{next: env.deps.httpClient.Transport}
	env.deps.httpClient = &http.Client{Transport: log}
	// Without the decoys "other agent directories were not touched" would be vacuous.
	plantDecoyAgentDirectories(t, env.home)
	return env, log, baselineFlags(tg)
}

func idemRel(t *testing.T, home, path string) string {
	t.Helper()
	rel, err := filepath.Rel(home, path)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

// installedSkills is hand-written from the fixture, so a run that installed
// nothing fails rather than making the measurement vacuous.
var installedSkills = []string{"acme--code-review", "acme--lint-guard", "example--doc-writer"}

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

	// Self-check: the state root's mtime must move on every run (probe and lock),
	// or every "unchanged" assertion below is blind.
	if mtimeUsable {
		require.True(t, idemHasChange(changes, DirName, "mtime"),
			"the write probe and the sync lock are created and unlinked inside %s on every run, so its "+
				"mtime MUST have moved; that it did not means this test's mtime channel is dead:\n%s",
			DirName, idemLines(changes))
	}

	// record.Save skips a byte-identical write, so a moved mtime here is a real
	// defect. Checked before the sweep, since require stops at the first failure.
	require.Empty(t, idemChangesFor(changes, recordRel),
		"%s was rewritten by the second sync; record.Save must skip a write whose bytes are "+
			"unchanged:\n%s", recordRel, idemLines(idemChangesFor(changes, recordRel)))

	// The state root is excluded by name, for mtime and size only: a transient
	// child (the lock) moves both on some filesystems.
	var offenders []idemChange
	for _, c := range changes {
		if c.rel == DirName && (c.what == "mtime" || c.what == "size") {
			continue
		}
		offenders = append(offenders, c)
	}
	require.Empty(t, offenders,
		"the second sync modified the filesystem:\n%s", idemLines(offenders))

	// A re-download that landed identical bytes leaves no trace on disk.
	after := log.since(mark)
	require.NotEmpty(t, after, "the second run must really have talked to the hub")
	var bundles []string
	for _, p := range after {
		if strings.Contains(p, "/v1/bundles/") {
			bundles = append(bundles, p)
		}
	}
	require.Empty(t, bundles, "the second sync re-downloaded %d bundle(s): %v", len(bundles), bundles)
	require.Condition(t, func() bool {
		for _, p := range after {
			if strings.Contains(p, "/revisions/") {
				return true
			}
		}
		return false
	}, "the second run must have fetched the lockfile, or it did nothing and proved nothing: %v", after)
}

func TestTheIdempotenceCheckSeesWhatABrokenSyncWouldDo(t *testing.T) {
	// Negative controls: each mutation is something a broken run two might do,
	// and idemDiff must name its path and channel.
	settle, mtimeUsable := idemMtimeSettle(t)

	skillDir := func(env *syncEnv) string { return filepath.Join(env.skillsRoot(), installedSkills[0]) }

	cases := []struct {
		name   string
		mutate func(t *testing.T, env *syncEnv) string
		what   string
		// needsMtime marks the mutations that only mtime can see.
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
				// Models an extractor restoring archive mtimes: same bytes, mode and mtime,
				// new inode. Only identity can see it.
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

// rewriteIdentically writes a file's own bytes back over it, as an
// unconditional re-install would.
func rewriteIdentically(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	b, err := os.ReadFile(path) //nolint:gosec // a test reading its own temp home
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, info.Mode().Perm()))
}

// TestARealReinstallOfIdenticalBytesIsSeenByThisCheck is the negative control
// driven by production code: deleting the record makes run two re-install
// byte-identical content, which only the filesystem can see.
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

	// The cache still holds every bundle, so a re-install must not re-download.
	require.Empty(t, idemChangesFor(changes, handWritten),
		"a forced re-install modified a path amctl's record never claimed")
	for _, p := range log.since(mark) {
		require.NotContains(t, p, "/v1/bundles/",
			"the re-install re-downloaded a bundle the cache already held")
	}
}
