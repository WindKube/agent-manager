// This file is `amctl sync` end to end against the fake hub.
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/deliver"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const syncHost = "sync-test-host"

func startSyncFake(t *testing.T) fake.Target {
	t.Helper()
	// TLS: a plaintext fake would test the plaintext refusal instead of the sync.
	h := fake.New(fake.Options{TLS: true})
	t.Cleanup(h.Close)
	return h.Target()
}

// countingRoundTripper counts requests on the wire; every "no request was
// made" assertion reads this counter, never an error message.
type countingRoundTripper struct {
	next http.RoundTripper

	mu sync.Mutex
	n  int
	// before runs before each request, to observe the machine mid-sync without a production hook.
	before func(*http.Request)
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n++
	hook := c.before
	c.mu.Unlock()
	if hook != nil {
		hook(req)
	}
	next := c.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

func (c *countingRoundTripper) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// syncEnv is one test's world: a scratch HOME, a hub, and the deps sync runs
// with. The token comes via AMCTL_TOKEN so no test depends on a running Secret Service.
type syncEnv struct {
	home    string
	target  fake.Target
	deps    syncDeps
	counted *countingRoundTripper
}

func newSyncEnv(t *testing.T, tg fake.Target) *syncEnv {
	t.Helper()
	home := testHome(t)
	counted := &countingRoundTripper{next: tg.HTTPClient.Transport}
	env := &syncEnv{home: home, target: tg, counted: counted}
	env.deps = syncDeps{
		httpClient: &http.Client{Transport: counted},
		hostname:   func() (string, error) { return syncHost, nil },
		backends:   fileBackendOnly(),
		lookupEnv: func(name string) (string, bool) {
			if name == credentials.TokenEnvVar {
				return tg.Token, true
			}
			return "", false
		},
		now: func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) },
	}
	return env
}

func (e *syncEnv) skillsRoot() string { return filepath.Join(e.home, ".claude", "skills") }

func (e *syncEnv) recordPath(t *testing.T) string {
	t.Helper()
	h, err := ParseHub(e.target.BaseURL)
	require.NoError(t, err)
	return record.Path(filepath.Join(e.home, DirName, h.Dir))
}

func (e *syncEnv) loadRecord(t *testing.T) *record.Record {
	t.Helper()
	h, err := ParseHub(e.target.BaseURL)
	require.NoError(t, err)
	rec, err := record.Load(e.recordPath(t), h.URL)
	require.NoError(t, err)
	return rec
}

func (e *syncEnv) run(t *testing.T, format output.Format, flags syncFlags) (code Code, result, diag *syncBuffer, err error) {
	t.Helper()
	opts, result, diag := testOptions(e.target.BaseURL, format)
	err = runSync(context.Background(), opts, flags, e.deps)
	return ExitCode(opts.Outcome, err), result, diag, err
}

func baselineFlags(tg fake.Target) syncFlags {
	return syncFlags{profiles: []string{tg.Fixtures.Profile}}
}

type treeEntry struct {
	Mode    fs.FileMode
	Size    int64
	SHA256  string
	Link    string
	ModTime time.Time
}

// treeSnapshot walks root with Lstat, so a replaced symlink is visible.
func treeSnapshot(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	out := map[string]treeEntry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
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
		e := treeEntry{Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime()}
		if info.IsDir() {
			// Directories record mode only: the per-home lock and the record's temp file
			// move their mtime and size on every run. idempotence_test.go covers mtimes.
			e.Size, e.ModTime = 0, time.Time{}
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			e.Link, ierr = os.Readlink(p)
			if ierr != nil {
				return ierr
			}
		case info.Mode().IsRegular():
			b, rerr := os.ReadFile(p) //nolint:gosec // a test walking its own temp dir
			if rerr != nil {
				return rerr
			}
			sum := sha256.Sum256(b)
			e.SHA256 = hex.EncodeToString(sum[:])
		}
		out[filepath.ToSlash(rel)] = e
		return nil
	})
	require.NoError(t, err)
	return out
}

func requireUnchanged(t *testing.T, label string, before, after map[string]treeEntry) {
	t.Helper()
	for p, want := range before {
		got, ok := after[p]
		require.True(t, ok, "%s: %s was removed by the sync", label, p)
		require.Equal(t, want, got, "%s: %s was modified by the sync", label, p)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// plantDecoyAgentDirectories creates the agent directories a sync must not
// touch, so "no other directory was written" isn't vacuous.
func plantDecoyAgentDirectories(t *testing.T, home string) {
	t.Helper()
	// Both codex roots, the documented one and the older widely published one.
	writeFile(t, filepath.Join(home, ".agents", "skills", "someones-skill", "SKILL.md"), "not amctl's\n")
	writeFile(t, filepath.Join(home, ".codex", "skills", "someones-skill", "SKILL.md"), "not amctl's\n")
	// A hand-written skill in the very directory amctl installs into.
	writeFile(t, filepath.Join(home, ".claude", "skills", "my-own-skill", "SKILL.md"), "mine, hand written\n")
	// XDG paths the agent does not read.
	writeFile(t, filepath.Join(home, ".config", "claude", "skills", "xdg-skill", "SKILL.md"), "not read by the agent\n")
}

func skillDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestSyncInstallsEveryLockfileEntryAtItsLockedVersion(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	plantDecoyAgentDirectories(t, env.home)
	before := treeSnapshot(t, env.home)

	code, result, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code, "a sync that installed three entries changed the tree")

	// The tree, not the report: a sync that printed a perfect result and wrote nothing must fail.
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer", "my-own-skill"},
		skillDirs(t, env.skillsRoot()))
	for _, dir := range []string{"acme--code-review", "acme--lint-guard", "example--doc-writer"} {
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, layout.SkillEntryFile))
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, "references", "usage.md"))
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, "scripts", "check.sh"))
		markerBytes, rerr := os.ReadFile(filepath.Join(env.skillsRoot(), dir, layout.MarkerFileName))
		require.NoError(t, rerr)
		marker, perr := layout.ParseMarker(markerBytes)
		require.NoError(t, perr)
		require.Equal(t, record.TargetClaudeCode, marker.Target)
		require.NotEmpty(t, marker.Version)
	}

	after := treeSnapshot(t, env.home)
	requireUnchanged(t, "another agent's directory", map[string]treeEntry{
		".agents/skills/someones-skill/SKILL.md":   before[".agents/skills/someones-skill/SKILL.md"],
		".codex/skills/someones-skill/SKILL.md":    before[".codex/skills/someones-skill/SKILL.md"],
		".config/claude/skills/xdg-skill/SKILL.md": before[".config/claude/skills/xdg-skill/SKILL.md"],
		".claude/skills/my-own-skill/SKILL.md":     before[".claude/skills/my-own-skill/SKILL.md"],
	}, after)

	// `head` is a request, never a state: the record holds the resolved number.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	require.Equal(t, int(tg.Fixtures.HeadRevision), prof.Revision)
	require.Equal(t, []record.Target{record.TargetClaudeCode}, prof.Targets)
	require.Len(t, prof.Entries, 3)

	require.Contains(t, diag.String(), "flagged-awaiting-approval")
	require.Contains(t, diag.String(), "version-rejected")
	require.Contains(t, diag.String(), "pin-target-missing")
	require.Contains(t, diag.String(), "would have resolved to 1.9.0")
	require.Contains(t, result.String(), "synced "+tg.Fixtures.Profile)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
	require.Equal(t, tg.Fixtures.Profile, reports[0].Profile)
	require.Equal(t, tg.Fixtures.HeadRevision, reports[0].Revision)
	require.Equal(t, syncHost, reports[0].Host)
	require.Equal(t, []hub.SyncReportTargets{"claude-code"}, reports[0].Targets)
}

func requireFileExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err, "%s should exist", path)
	require.True(t, info.Mode().IsRegular(), "%s should be a regular file", path)
}

func TestASecondSyncChangesNothing(t *testing.T) {
	// Verb-level idempotence; idempotence_test.go measures the filesystem.
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	afterFirst := treeSnapshot(t, env.home)

	code, result, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code, "a converged machine must not report changes")
	require.Contains(t, result.String(), "nothing to do")

	afterSecond := treeSnapshot(t, env.home)
	requireUnchanged(t, "the whole tree", afterFirst, afterSecond)
	require.Equal(t, len(afterFirst), len(afterSecond), "the second run created nothing")
}

// TestHomeUnsetIsRefusedBeforeAnyRequest asserts the request count, not the
// message, since a late refusal would produce the same text.
func TestHomeUnsetIsRefusedBeforeAnyRequest(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// The platform's own variable: hardcoding HOME would assert nothing elsewhere.
	t.Setenv(homeEnvVar(), "")

	code, result, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHomeUnset)
	require.True(t, IsRefusal(err), "an unset home is a refusal the user can fix")
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, homeEnvVar())
	require.Equal(t, 0, env.counted.count(),
		"the home is refused BEFORE any network request, and this counts them on the wire")
	require.Empty(t, result.String(), "a refused sync emits no result document")

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, reports)
}

func TestAnUnwritableHomeIsRefusedBeforeAnyRequest(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	require.NoError(t, os.Chmod(env.home, 0o500))
	t.Cleanup(func() { _ = os.Chmod(env.home, 0o700) })

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, ErrHomeUnwritable)
	require.Equal(t, CodeRefused, code)
	require.Equal(t, 0, env.counted.count(), "the write probe runs before the network, not after it")
}

// TestNoCredentialIsRefusedNamingWhatSuppliesOne: asking the hub first would
// yield a 401 that misdirects the user to the hub.
func TestNoCredentialIsRefusedNamingWhatSuppliesOne(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	env.deps.lookupEnv = func(string) (string, bool) { return "", false }

	code, result, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "amctl login")
	require.ErrorContains(t, err, credentials.TokenEnvVar)
	require.Equal(t, 0, env.counted.count(), "no credential means no request, not a 401")
	require.Empty(t, result.String())
}

func TestAnExpiredCredentialIsRefusedRatherThanTried(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	env.deps.lookupEnv = func(string) (string, bool) { return "", false }

	h, err := ParseHub(tg.BaseURL)
	require.NoError(t, err)
	store := openTestStore(t, env.home)
	expired := credentials.Issued(h.URL, "expired-token", 60, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	expired.Identity = syncHost
	require.NoError(t, store.Save(expired))

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "expired")
	require.ErrorContains(t, err, "amctl login")
	require.Equal(t, 0, env.counted.count(),
		"an expired token would earn a 401 that reads as the hub's fault; refuse locally instead")
}

func TestSyncUsesAStoredCredentialWhenTheEnvironmentHasNone(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	env.deps.lookupEnv = func(string) (string, bool) { return "", false }

	h, err := ParseHub(tg.BaseURL)
	require.NoError(t, err)
	store := openTestStore(t, env.home)
	cred := credentials.Issued(h.URL, tg.Token, 3600, env.deps.now())
	cred.Identity = syncHost
	require.NoError(t, store.Save(cred))

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	require.Greater(t, env.counted.count(), 0)
}

func TestALockfileNamingTwoTargetsInstallsIntoBoth(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	flags := syncFlags{profiles: []string{tg.Fixtures.BothTargets}}
	code, result, _, err := env.run(t, output.FormatJSON, flags)
	require.NoError(t, err)
	require.Equal(t, CodeChanged, code)

	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))
	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, filepath.Join(env.home, ".agents", "skills")))

	var doc struct {
		Result struct {
			Added []struct {
				Target string `json:"target"`
			} `json:"added"`
			Skipped []json.RawMessage `json:"skipped"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Len(t, doc.Result.Added, 2)
	require.Equal(t, "claude-code", doc.Result.Added[0].Target)
	require.Equal(t, "codex", doc.Result.Added[1].Target)
	require.Empty(t, doc.Result.Skipped)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
}

// withdrawnLockfile is built in the test, not served by the fake, so the
// conformance fixtures never carry a target the schema is about to reject.
func withdrawnLockfile(t *testing.T, targets ...string) *hub.Lockfile {
	t.Helper()
	tg := make([]hub.LockfileTargets, 0, len(targets))
	for _, name := range targets {
		tg = append(tg, hub.LockfileTargets(name))
	}
	return &hub.Lockfile{
		SchemaVersion: "1.0.0",
		Profile:       hub.LockfileProfile{Slug: "base", Name: "base"},
		Revision:      1,
		Gate:          "block",
		Targets:       tg,
		Entries: []hub.LockfileEntry{{
			Id: "acme/code-review", Kind: hub.Skill, Version: "2.4.1",
			Digest:     "sha256:" + strings.Repeat("ab", 32),
			ObjectKey:  "bundles/acme/code-review/2.4.1/bundle.tar.zst",
			Resolution: "pinned", Verdict: "clean",
		}},
		Skipped: []hub.LockfileSkip{},
	}
}

// lockfileNamingCodex has n skill entries, so a test can tell "one line" from "one line per entry".
func lockfileNamingCodex(n int, targets ...string) *hub.Lockfile {
	tg := make([]hub.LockfileTargets, 0, len(targets))
	for _, name := range targets {
		tg = append(tg, hub.LockfileTargets(name))
	}
	entries := make([]hub.LockfileEntry, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("acme/pkg-%d", i)
		entries = append(entries, hub.LockfileEntry{
			Id: id, Kind: hub.Skill, Version: "1.0.0",
			Digest:     "sha256:" + strings.Repeat("ab", 32),
			ObjectKey:  "bundles/" + id + "/1.0.0/bundle.tar.zst",
			Resolution: "pinned", Verdict: "clean",
		})
	}
	return &hub.Lockfile{
		SchemaVersion: "1.0.0",
		Profile:       hub.LockfileProfile{Slug: "base", Name: "base"},
		Revision:      1,
		Gate:          "block",
		Targets:       tg,
		Entries:       entries,
		Skipped:       []hub.LockfileSkip{},
	}
}

// TestSkippedTargetUnwritableEntriesCollapseToOneLine: several entries under an
// unwritable target print one line naming the target and count, not one per entry.
func TestSkippedTargetUnwritableEntriesCollapseToOneLine(t *testing.T) {
	lf := lockfileNamingCodex(3, "claude-code", "codex")

	opts, _, diag := testOptions("https://hub.example.com", output.FormatHuman)
	r := &syncRun{opts: opts, s: opts.Streams()}
	reg, err := layout.NewRegistry(layout.Config{HomeDir: filepath.Join(t.TempDir(), "home")})
	require.NoError(t, err)
	targets, _ := r.resolveTargets(reg, []*hub.Lockfile{lf})
	// No target this build knows refuses today, so the unwritable one is made up.
	for i := range targets {
		if targets[i].Name == record.TargetCodex {
			targets[i] = plan.Target{Name: record.TargetCodex, Err: fmt.Errorf("codex: %w", layout.ErrR2Unresolved)}
		}
	}
	p, err := plan.Compute(plan.Inputs{Lockfiles: []*hub.Lockfile{lf}, Targets: targets})
	require.NoError(t, err)
	require.Len(t, p.Skipped, 3, "the plan itself still carries one skip per entry")

	r.reportSkips(p)
	codexLines := 0
	for _, line := range strings.Split(strings.TrimRight(diag.String(), "\n"), "\n") {
		if strings.Contains(line, "codex") {
			codexLines++
			require.Contains(t, line, "3 entries")
			require.Contains(t, line, "cannot write")
		}
	}
	require.Equal(t, 1, codexLines, "one collapsed line, not one per entry")

	var res output.SyncResult
	appendSkips(&res, p)
	var human strings.Builder
	require.NoError(t, res.Human(&human))
	skipLines := 0
	for _, line := range strings.Split(strings.TrimRight(human.String(), "\n"), "\n") {
		if strings.Contains(line, "skip") {
			skipLines++
			require.Contains(t, line, "3 entries")
			require.Contains(t, line, "target-unwritable")
		}
	}
	require.Equal(t, 1, skipLines, "the human result collapses the same way")
}

func planForTargets(t *testing.T, lf *hub.Lockfile) (p plan.Plan, diagnostics string) {
	t.Helper()
	opts, _, diag := testOptions("https://hub.example.com", output.FormatHuman)
	r := &syncRun{opts: opts, s: opts.Streams()}
	reg, err := layout.NewRegistry(layout.Config{HomeDir: filepath.Join(t.TempDir(), "home")})
	require.NoError(t, err)
	targets, _ := r.resolveTargets(reg, []*hub.Lockfile{lf})
	p, cerr := plan.Compute(plan.Inputs{Lockfiles: []*hub.Lockfile{lf}, Targets: targets})
	require.NoError(t, cerr)
	return p, diag.String()
}

// TestAWithdrawnTargetIsReportedAndTheSyncContinues: a withdrawn target is a
// legal enum value with no user-side fix, so it must not refuse the sync.
func TestAWithdrawnTargetIsReportedAndTheSyncContinues(t *testing.T) {
	p, diag := planForTargets(t, withdrawnLockfile(t, "claude-code", "agents-md"))

	require.False(t, p.Refuses(), "a withdrawn target must not refuse a profile that also names a writable one")
	require.Empty(t, p.Conflicts)
	require.Len(t, p.Add, 1, "the claude-code entry still installs")
	require.Equal(t, record.TargetClaudeCode, p.Add[0].Target)
	require.Contains(t, diag, "agents-md",
		"the difference between what the profile named and what was written is reported")
	require.Contains(t, diag, "will not write")
}

// TestAProfileWhoseTargetsAreAllWithdrawnIsRefused: carrying on past a withdrawn
// target is safe only while something else is still written.
func TestAProfileWhoseTargetsAreAllWithdrawnIsRefused(t *testing.T) {
	p, _ := planForTargets(t, withdrawnLockfile(t, "agents-md"))

	require.True(t, p.Refuses())
	require.Len(t, p.Conflicts, 1)
	require.Equal(t, plan.ConflictNoWritableTarget, p.Conflicts[0].Kind)
	require.Contains(t, p.Conflicts[0].String(), "install nothing and still exit 0")
	require.Empty(t, p.Add)
}

// Every other profile must name one root, or directory-level assertions would look in one of two.
func TestOnlyTheTwoTargetFixtureNamesCodex(t *testing.T) {
	tg := startSyncFake(t)

	both := readLockfile(t, tg, tg.Fixtures.BothTargets)
	require.Contains(t, both["targets"], "codex")

	happy := readLockfile(t, tg, tg.Fixtures.Profile)
	require.Equal(t, []any{"claude-code"}, happy["targets"])
}

func readLockfile(t *testing.T, tg fake.Target, slug string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tg.BaseURL+"/v1/profiles/"+slug+"/revisions/head", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tg.Token)
	resp, err := tg.HTTPClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var doc map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&doc))
	return doc
}

// TestSyncFollowsASymlinkedAgentDirectoryInsideTheHome: agent directories are
// often symlinks into a dotfiles repo, so containment is checked on the resolved
// path rather than refusing a link.
func TestSyncFollowsASymlinkedAgentDirectoryInsideTheHome(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	dotfiles := filepath.Join(env.home, "dotfiles", "claude")
	require.NoError(t, os.MkdirAll(dotfiles, 0o700))
	require.NoError(t, os.Symlink(dotfiles, filepath.Join(env.home, ".claude")))

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	requireFileExists(t, filepath.Join(dotfiles, "skills", "acme--code-review", layout.SkillEntryFile))
	// The record holds the requested path: recording the resolution would make the
	// next run see a relocation and remove-and-re-add forever.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	for _, e := range prof.Entries {
		require.True(t, strings.HasPrefix(e.Dest, filepath.Join(env.home, ".claude", "skills")),
			"the record stores the requested destination, %q", e.Dest)
	}
}

// Negative control: otherwise "checked on the resolved path" is indistinguishable from no check.
func TestSyncRefusesAnAgentDirectoryThatLeavesTheHome(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	outside := t.TempDir() // a sibling of the home, not inside it
	require.NoError(t, os.Symlink(outside, filepath.Join(env.home, ".claude")))

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, apply.ErrOutsideHome)
	require.Equal(t, CodeRefused, code, "a destination outside the home is a refusal, not a crash")
	require.ErrorContains(t, err, "outside")
	require.ErrorContains(t, err, "will not follow a link out of it")
	require.NotContains(t, diag.String(), "outside",
		"the containment refusal is the returned error; the diagnostic stream carries only the hub's skips")

	entries, rerr := os.ReadDir(outside)
	require.NoError(t, rerr)
	require.Empty(t, entries, "amctl must not follow a link out of the home")
}

// A partial success must be distinguishable from a total failure.
func TestAForbiddenBundleSkipsThatEntryAndTheRestStillInstalls(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, diag, err := env.run(t, output.FormatJSON,
		syncFlags{profiles: []string{tg.Fixtures.ForbiddenBundle}})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code,
		"the hub withheld one version and served the rest: a success with changes, not a failure")

	// Order is installable, 403, installable: aborting on the 403 would miss the third.
	require.Equal(t, []string{"acme--code-review", "example--doc-writer"}, skillDirs(t, env.skillsRoot()))

	var doc struct {
		Result struct {
			Added   []struct{ Package string } `json:"added"`
			Skipped []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"skipped"`
			Partial bool `json:"partial"`
		} `json:"result"`
	}
	dec := json.NewDecoder(strings.NewReader(result.String()))
	require.NoError(t, dec.Decode(&doc))
	require.False(t, dec.More(), "one document on the result stream")
	require.Len(t, doc.Result.Added, 2)
	require.True(t, doc.Result.Partial, "a locally skipped entry makes the sync partial")

	var found bool
	for _, sk := range doc.Result.Skipped {
		if sk.Package == tg.Fixtures.ForbiddenEntryID {
			found = true
			require.Contains(t, sk.Reason, "403")
		}
	}
	require.True(t, found, "the skipped entry is named in the result, not only on stderr")

	// A record row for something absent becomes a refusal next run.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.ForbiddenBundle)
	require.True(t, ok)
	require.Len(t, prof.Entries, 2)
	for _, e := range prof.Entries {
		require.NotEqual(t, tg.Fixtures.ForbiddenEntryID, e.ID)
	}

	// A local skip, which is not the lockfile's own `skipped`.
	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
	require.NotNil(t, reports[0].Skipped)
	require.Equal(t, []string{tg.Fixtures.ForbiddenEntryID}, *reports[0].Skipped)
}

// Contrast with the test above: a 403 is the hub's decision, a digest mismatch
// is a corrupted or substituted object, so the exit codes differ.
func TestADigestMismatchFailsThatEntryAndExitsNonZero(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, diag, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.DigestMismatch}})
	require.Error(t, err)
	require.ErrorIs(t, err, hub.ErrDigestMismatch)
	require.False(t, IsRefusal(err), "a substituted bundle is not the user's to fix")
	require.Equal(t, CodeFailure, code)
	require.NotEqual(t, CodeChanged, code, "distinct from the forbidden-bundle partial success")

	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))
	require.Contains(t, diag.String(), "sha256:")
	require.Contains(t, diag.String(), "the lockfile locked")

	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.DigestMismatch)
	require.True(t, ok)
	require.Len(t, prof.Entries, 1)
}

// TestAnAbandonedEntryIsNamedInTheReportAndTheResult: a digest mismatch is what
// an audit trail most needs, so it must reach the report's `skipped` and a JSON array.
func TestAnAbandonedEntryIsNamedInTheReportAndTheResult(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, _, err := env.run(t, output.FormatJSON,
		syncFlags{profiles: []string{tg.Fixtures.DigestMismatch}})
	require.Error(t, err)
	require.Equal(t, CodeFailure, code, "naming the entry must not soften the exit code")

	var doc struct {
		Result struct {
			Added   []struct{ Package string } `json:"added"`
			Skipped []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"skipped"`
			Failed []struct {
				Package string `json:"package"`
				Version string `json:"version"`
				Reason  string `json:"reason"`
			} `json:"failed"`
			Partial bool `json:"partial"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.True(t, doc.Result.Partial)
	require.Len(t, doc.Result.Added, 1)
	require.Empty(t, doc.Result.Skipped,
		"an abandoned entry is not a skip: a skip exits 0 and this run does not")
	require.Len(t, doc.Result.Failed, 1)
	require.Equal(t, "contoso/stale-digest", doc.Result.Failed[0].Package)
	require.Equal(t, "1.0.0", doc.Result.Failed[0].Version)
	require.Contains(t, doc.Result.Failed[0].Reason, "the lockfile locked",
		"the reason must carry both digests, not merely say that something failed")

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
	require.NotNil(t, reports[0].Skipped,
		"the hub is told this machine is missing an entry, or its audit row is a lie")
	require.Equal(t, []string{"contoso/stale-digest"}, *reports[0].Skipped)
}

// TestAStoreRefusingThePresignedURLFailsTheEntryRatherThanSkippingIt: an object
// store's 403 after the 307 (expired signature, clock skew) is an infrastructure
// failure, not the hub's scan-gate 403 that skips and exits 0.
func TestAStoreRefusingThePresignedURLFailsTheEntryRatherThanSkippingIt(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	require.NotEmpty(t, tg.Fixtures.StalePresignedBundle)

	code, result, diag, err := env.run(t, output.FormatJSON,
		syncFlags{profiles: []string{tg.Fixtures.StalePresignedBundle}})
	require.Error(t, err)
	require.ErrorIs(t, err, hub.ErrOffload)
	require.NotErrorIs(t, err, hub.ErrForbidden,
		"the store refusing a pre-signed URL is not the organisation's gate")
	require.Equal(t, CodeFailure, code)
	require.NotEqual(t, CodeChanged, code,
		"exiting 0 here is the failure this test exists for: under `set -e` nothing would notice")

	// Per-entry, not an abort.
	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))
	require.NotContains(t, diag.String(), "scan gate")

	var doc struct {
		Result struct {
			Skipped []struct{ Package string } `json:"skipped"`
			Failed  []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"failed"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Empty(t, doc.Result.Skipped)
	require.Len(t, doc.Result.Failed, 1)
	require.Equal(t, tg.Fixtures.StalePresignedEntryID, doc.Result.Failed[0].Package)
	require.Contains(t, doc.Result.Failed[0].Reason, "object store")
}

// TestTheLockIsHeldForTheWholeMutation observes the lock file from the
// transport's pre-request callback, mid-sync.
func TestTheLockIsHeldForTheWholeMutation(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	var mu sync.Mutex
	var observed []bool
	env.counted.before = func(*http.Request) {
		_, err := os.Lstat(filepath.Join(env.home, DirName, LockFileName))
		mu.Lock()
		observed = append(observed, err == nil)
		mu.Unlock()
	}

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	mu.Lock()
	seen := append([]bool(nil), observed...)
	mu.Unlock()
	require.NotEmpty(t, seen, "the sync made no request, so nothing was observed")
	for i, held := range seen {
		require.True(t, held, "the sync lock was not held during request %d", i)
	}
	require.NoFileExists(t, filepath.Join(env.home, DirName, LockFileName),
		"the lock is released when the sync finishes")
}

func TestAConcurrentSyncIsRefusedWithoutTouchingTheHub(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	home, err := ResolveHome()
	require.NoError(t, err)
	held, err := Acquire(home)
	require.NoError(t, err)
	t.Cleanup(func() { _ = held.Release() })

	code, result, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, ErrLocked)
	require.Equal(t, CodeRefused, code, "refused, never interleaved")
	require.Empty(t, result.String())
	require.Equal(t, 0, env.counted.count(),
		"the lock is taken before the first request, so a refused run costs the hub nothing")
}

// panicOnWrite panics inside WithLock, since Emit runs with the lock held.
type panicOnWrite struct{}

func (panicOnWrite) Write([]byte) (int, error) { panic("the result stream exploded") }

// A panic that left the lock behind would block the machine until it goes stale.
func TestThePanickingSyncStillReleasesTheLock(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	opts := &Options{Hub: tg.BaseURL, Output: string(output.FormatHuman), result: panicOnWrite{}, diag: io.Discard}
	opts.streams = output.NewStreams(output.FormatHuman, panicOnWrite{}, io.Discard)

	func() {
		defer func() {
			r := recover()
			require.NotNil(t, r, "the injected panic did not happen, so nothing was proved")
		}()
		_ = runSync(context.Background(), opts, baselineFlags(tg), env.deps)
	}()

	require.NoFileExists(t, filepath.Join(env.home, DirName, LockFileName),
		"WithLock releases on the way out of a panic")

	// Really released: a second run gets the lock. The panic hit the last write,
	// so the tree had already converged.
	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.NotErrorIs(t, err, ErrLocked)
	require.Equal(t, CodeNoChanges, code)
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer"},
		skillDirs(t, env.skillsRoot()))
}

func TestJSONOutputLeavesStdoutOneParseableDocument(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	opts, result, diag := testOptions(tg.BaseURL, output.FormatJSON)
	opts.Verbose = true // every Debugf line now goes somewhere, and must not be stdout
	opts.streams.SetVerbose(true)
	require.NoError(t, runSync(context.Background(), opts, baselineFlags(tg), env.deps))

	dec := json.NewDecoder(strings.NewReader(result.String()))
	var doc struct {
		Kind   string `json:"kind"`
		Result struct {
			Hub      string   `json:"hub"`
			Profiles []string `json:"profiles"`
			Revision string   `json:"revision"`
			Added    []struct {
				Package string `json:"package"`
				To      string `json:"to"`
				Target  string `json:"target"`
				Path    string `json:"path"`
			} `json:"added"`
			Skipped []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"skipped"`
		} `json:"result"`
	}
	require.NoError(t, dec.Decode(&doc))
	require.False(t, dec.More(), "exactly one document, however much went to stderr")
	require.Equal(t, "sync", doc.Kind)
	require.Equal(t, []string{tg.Fixtures.Profile}, doc.Result.Profiles)
	require.Equal(t, "7", doc.Result.Revision)
	require.Len(t, doc.Result.Added, 3)
	require.Len(t, doc.Result.Skipped, 3)
	for _, a := range doc.Result.Added {
		require.Equal(t, "claude-code", a.Target)
		require.NotEmpty(t, a.Path)
		require.NotEmpty(t, a.To)
	}

	require.Contains(t, diag.String(), "resolving profile "+tg.Fixtures.Profile)
	require.Contains(t, diag.String(), "fetching ")
	require.NotContains(t, result.String(), "resolving profile")
	require.NotContains(t, result.String(), "warning:")

	// require.False, never NotContains: a failing NotContains prints its haystack,
	// putting the token into the output internal/leakscan scans.
	require.False(t, strings.Contains(result.String(), tg.Token), "the bearer token reached the result stream")
	require.False(t, strings.Contains(diag.String(), tg.Token), "the bearer token reached the diagnostic stream")
}

func TestParseRevisions(t *testing.T) {
	cases := []struct {
		name     string
		profiles []string
		flags    []string
		want     map[string]string
		refuses  string
	}{
		{
			name: "no flag means head for every profile", profiles: []string{"a", "b"},
			want: map[string]string{"a": revisionHead, "b": revisionHead},
		},
		{
			name: "an explicit head applies to every profile", profiles: []string{"a", "b"}, flags: []string{"head"},
			want: map[string]string{"a": revisionHead, "b": revisionHead},
		},
		{
			name: "a bare number pins the single profile", profiles: []string{"a"}, flags: []string{"7"},
			want: map[string]string{"a": "7"},
		},
		{
			name: "a bare number cannot mean two profiles at once", profiles: []string{"a", "b"}, flags: []string{"7"},
			refuses: "cannot apply to 2 profiles",
		},
		{
			name:     "a qualified form pins one and leaves the rest at head",
			profiles: []string{"a", "b"}, flags: []string{"a=7"},
			want: map[string]string{"a": "7", "b": revisionHead},
		},
		{
			name:     "qualified forms pin several profiles in one run",
			profiles: []string{"a", "b"}, flags: []string{"a=7", "b=3"},
			want: map[string]string{"a": "7", "b": "3"},
		},
		{
			name:     "a qualified head is allowed, so a mixed run can be explicit",
			profiles: []string{"a", "b"}, flags: []string{"a=7", "b=head"},
			want: map[string]string{"a": "7", "b": revisionHead},
		},
		{
			name:     "the bare and qualified forms are not merged",
			profiles: []string{"a", "b"}, flags: []string{"head", "a=7"},
			refuses: "mixes the bare form",
		},
		{
			name:     "two bare numbers name no profile at all",
			profiles: []string{"a"}, flags: []string{"7", "8"},
			refuses: "a revision is per profile",
		},
		{
			name:     "a profile this run is not syncing is refused, not ignored",
			profiles: []string{"a"}, flags: []string{"b=7"},
			refuses: `names profile "b"`,
		},
		{
			name:     "one profile has one revision per run",
			profiles: []string{"a"}, flags: []string{"a=7", "a=8"},
			refuses: "twice",
		},
		{
			name: "revision zero is not a revision", profiles: []string{"a"}, flags: []string{"0"},
			refuses: "revisions start at 1",
		},
		{
			name: "a negative revision is not a revision", profiles: []string{"a"}, flags: []string{"-3"},
			refuses: "revisions start at 1",
		},
		{
			name: "a word that is not head is not a revision", profiles: []string{"a"}, flags: []string{"latest"},
			refuses: "neither `head` nor a revision number",
		},
		{
			name:     "an empty value is refused rather than treated as head",
			profiles: []string{"a"}, flags: []string{""},
			refuses: "empty value",
		},
		{
			name:     "a qualified form with no profile is refused",
			profiles: []string{"a"}, flags: []string{"=7"},
			refuses: "no profile before",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRevisions(tc.flags, tc.profiles)
			if tc.refuses != "" {
				require.Error(t, err)
				require.True(t, IsRefusal(err), "a bad --revision is the user's to fix")
				require.ErrorContains(t, err, tc.refuses)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestChooseProfiles(t *testing.T) {
	t.Run("the flag wins and keeps its order", func(t *testing.T) {
		got, err := chooseProfiles([]string{"b", "a", "b"}, record.New("https://h"))
		require.NoError(t, err)
		require.Equal(t, []string{"b", "a"}, got)
	})

	t.Run("an empty value is refused", func(t *testing.T) {
		_, err := chooseProfiles([]string{"  "}, record.New("https://h"))
		require.True(t, IsRefusal(err))
		require.ErrorContains(t, err, "--profile")
	})

	t.Run("no flag re-converges the profiles already in the record", func(t *testing.T) {
		rec := record.New("https://h")
		rec.SetProfile(record.Profile{Slug: "later", Revision: 2})
		rec.SetProfile(record.Profile{Slug: "earlier", Revision: 1})
		got, err := chooseProfiles(nil, rec)
		require.NoError(t, err)
		require.Equal(t, []string{"earlier", "later"}, got)
	})

	t.Run("a never-synced machine is refused naming the flag", func(t *testing.T) {
		_, err := chooseProfiles(nil, record.New("https://h"))
		require.True(t, IsRefusal(err), "no TTY, so name the flag rather than guess a profile")
		require.ErrorContains(t, err, "--profile")
	})
}

// The prior revision holds a different version of the same package, so this
// cannot pass by fetching head.
func TestAPinnedRevisionInstallsThatExactStateAndIsRecorded(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	prior := fmt.Sprintf("%d", tg.Fixtures.PriorRevision)
	code, _, diag, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{prior}})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// Revision 6 holds only acme/code-review, at 2.4.0 rather than head's 2.4.1.
	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	require.Equal(t, int(tg.Fixtures.PriorRevision), prof.Revision)
	require.Len(t, prof.Entries, 1)
	require.Equal(t, "2.4.0", prof.Entries[0].Version)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
	require.Equal(t, tg.Fixtures.PriorRevision, reports[0].Revision,
		"the report carries the revision that was installed, not `head`")
}

func TestARevisionThatIsGoneIsRefusedNamingIt(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, _, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"999"}})
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "999")
	require.NoFileExists(t, env.recordPath(t))
}

func TestAMissingProfileIsRefusedAndDistinguishedFromUnreachable(t *testing.T) {
	// Not-found must not read as unreachable.
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, _, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.MissingProfile}})
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.NotErrorIs(t, err, hub.ErrUnreachable)
	require.Equal(t, hub.ClassNotFound, hub.ClassOf(err))
	require.Equal(t, CodeRefused, code)
}

func TestAnUnrecognisedSkipReasonIsReportedVerbatim(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, diag, err := env.run(t, output.FormatJSON,
		syncFlags{profiles: []string{tg.Fixtures.UnknownSkipReason}})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	var doc struct {
		Result struct {
			Skipped []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"skipped"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Len(t, doc.Result.Skipped, 1)
	require.Equal(t, "acme/from-the-future", doc.Result.Skipped[0].Package)
	require.Equal(t, "quarantined-by-org-policy", doc.Result.Skipped[0].Reason,
		"the hub's own value, neither translated nor dropped: this client ships separately from the hub")
	require.Contains(t, diag.String(), "does not recognise that reason")
}

func TestOfflineFailsNamingWhatIsMissingAndInstallsNothing(t *testing.T) {
	// The refusal must come before the first entry is staged, so the skills root
	// must not exist afterwards. Known gap: --offline still fetches the lockfile,
	// since nothing caches one.
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	opts, result, _ := testOptions(tg.BaseURL, output.FormatHuman)
	opts.Offline = true
	err := runSync(context.Background(), opts, baselineFlags(tg), env.deps)

	require.ErrorIs(t, err, hub.ErrOffline)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, ExitCode(opts.Outcome, err))
	require.ErrorContains(t, err, "sha256:")
	require.NoDirExists(t, env.skillsRoot(), "an offline miss must leave nothing behind")
	require.Empty(t, result.String())
}

func TestOfflineCompletesFromTheCacheAlone(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	_, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())

	require.NoError(t, os.RemoveAll(env.skillsRoot()))
	require.NoError(t, os.Remove(env.recordPath(t)))

	opts, _, diag2 := testOptions(tg.BaseURL, output.FormatHuman)
	opts.Offline = true
	require.NoError(t, runSync(context.Background(), opts, baselineFlags(tg), env.deps), diag2.String())
	require.Equal(t, CodeChanged, opts.Outcome)
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer"},
		skillDirs(t, env.skillsRoot()))
}

func TestACorruptRecordIsRefusedRatherThanOverwritten(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	path := env.recordPath(t)
	writeFile(t, path, "{ this is not json\n")
	before := treeSnapshot(t, env.home)

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, record.ErrCorrupt)
	require.True(t, IsRefusal(err), "an unreadable record is a refusal, not a reason to start again")
	require.Equal(t, CodeRefused, code)
	require.Equal(t, 0, env.counted.count(), "the record is read before the lockfile is fetched")

	after := treeSnapshot(t, env.home)
	requireUnchanged(t, "the record", before, after)
}

func TestAnotherHubsRecordIsRefused(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	other := record.New("https://somewhere.else.example")
	wrote, err := record.Save(env.recordPath(t), other)
	require.NoError(t, err)
	require.True(t, wrote)

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, record.ErrHubMismatch)
	require.Equal(t, CodeRefused, code)
}

func TestAnUnreachableHubIsNotMistakenForAnythingElse(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	// Not a 500: the classification exists so these two read differently.
	env.target.BaseURL = "https://127.0.0.1:1/"

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, hub.ErrUnreachable)
	require.Equal(t, hub.ClassUnreachable, hub.ClassOf(err))
	require.Equal(t, CodeFailure, code, "a network fault is not a refusal: retrying may work")
	require.False(t, errors.Is(err, hub.ErrUnauthorised))
}

func TestAPlaintextHubIsRefusedWithoutTheFlag(t *testing.T) {
	h := fake.New(fake.Options{})
	t.Cleanup(h.Close)
	tg := h.Target()
	env := newSyncEnv(t, tg)

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, hub.ErrInsecureHub)
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, hub.PlaintextFlagName)
	require.Equal(t, 0, env.counted.count())
}

// TestTwoProfilesResolvingOnePackageToTwoVersionsIsRefused is only reachable in
// a single run, which is why --revision accepts `<profile>=<revision>`.
func TestTwoProfilesResolvingOnePackageToTwoVersionsIsRefused(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// Revision 6 holds acme/code-review 2.4.0; the unknown-skip profile holds 2.4.1.
	code, result, diag, err := env.run(t, output.FormatJSON, syncFlags{
		profiles:  []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason},
		revisions: []string{tg.Fixtures.Profile + "=6", tg.Fixtures.UnknownSkipReason + "=head"},
	})
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)

	for _, want := range []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason, "2.4.0", "2.4.1", "acme/code-review"} {
		require.Contains(t, diag.String(), want)
	}
	require.NoDirExists(t, env.skillsRoot())
	require.NoFileExists(t, env.recordPath(t))

	var doc struct {
		Result struct {
			Conflicts []struct {
				Package string `json:"package"`
			} `json:"conflicts"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Len(t, doc.Result.Conflicts, 1)
	require.Equal(t, "acme/code-review", doc.Result.Conflicts[0].Package)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, reports)
}

// The report body has one profile field, so a two-profile sync is two
// reports, each with its own revision.
func TestTwoProfilesAtHeadAreEachReportedWithTheirOwnRevision(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, diag, err := env.run(t, output.FormatJSON, syncFlags{
		profiles: []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason},
	})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// One number would be a different state in each profile.
	var doc struct {
		Result struct {
			Profiles []string `json:"profiles"`
			Revision string   `json:"revision"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Equal(t, []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason}, doc.Result.Profiles)
	require.Equal(t, tg.Fixtures.Profile+"@7, "+tg.Fixtures.UnknownSkipReason+"@1", doc.Result.Revision)

	rec := env.loadRecord(t)
	require.Len(t, rec.Profiles, 2)
	claimants := rec.ClaimantsOf(filepath.Join(env.skillsRoot(), "acme--code-review"))
	require.Len(t, claimants, 2, "two profiles legitimately claim one destination")

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 2)
	got := map[string]int64{}
	for _, r := range reports {
		got[r.Profile] = r.Revision
	}
	require.Equal(t, map[string]int64{tg.Fixtures.Profile: 7, tg.Fixtures.UnknownSkipReason: 1}, got)
}

// Once per sync, not per machine: an idempotent run that reported nothing
// would make a converged machine look abandoned.
func TestEachSyncIsReportedOnceSoTwoSyncsAreTwoReports(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	for i := range 2 {
		_, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
		require.NoError(t, err, "run %d: %s", i, diag.String())
	}
	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 2)
	for _, r := range reports {
		require.Equal(t, tg.Fixtures.HeadRevision, r.Revision)
	}
}

// The bytes are already on disk; failing the sync would be the wrong correction.
func TestAFailedSyncReportDoesNotFailTheSync(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// Fail only POST /v1/sync, or this would test a broken hub.
	env.deps.httpClient = &http.Client{Transport: &failPathTransport{
		next: env.counted, path: "/v1/sync", status: http.StatusServiceUnavailable,
	}}

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, "a failed report must not fail the sync")
	require.Equal(t, CodeChanged, code)
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer"},
		skillDirs(t, env.skillsRoot()))

	require.Contains(t, diag.String(), "was not reported")
	require.Contains(t, diag.String(), "not retried")

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, reports)
}

// failPathTransport fails one path (or prefix) with its own status and passes everything else through.
type failPathTransport struct {
	next   http.RoundTripper
	path   string
	prefix string
	status int
}

func (f *failPathTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	hit := (f.path != "" && req.URL.Path == f.path) ||
		(f.prefix != "" && strings.HasPrefix(req.URL.Path, f.prefix))
	if !hit {
		return f.next.RoundTrip(req)
	}
	return &http.Response{
		StatusCode: f.status,
		Status:     fmt.Sprintf("%d injected", f.status),
		Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
		Body:       io.NopCloser(strings.NewReader(`{"status":503,"title":"Service Unavailable"}`)),
		Request:    req,
	}, nil
}

// The fingerprint recorded at install is what the upgrade is verified against.
func TestAnUpgradeOfAnUnmodifiedEntryNeedsNoForce(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	pinned := syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"6"}}
	_, _, diag, err := env.run(t, output.FormatHuman, pinned)
	require.NoError(t, err, diag.String())

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	prof, _ := env.loadRecord(t).ProfileBySlug(tg.Fixtures.Profile)
	for _, e := range prof.Entries {
		if e.ID == "acme/code-review" {
			require.Equal(t, "2.4.1", e.Version)
		}
	}
}

// internal/apply needs a positive unmodified verdict before it overwrites, so
// an entry without a fingerprint refuses until --force.
func TestAnUpgradeOfAnUnfingerprintedEntryRefusesUntilForced(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	pinned := syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"6"}}
	_, _, diag, err := env.run(t, output.FormatHuman, pinned)
	require.NoError(t, err, diag.String())

	stripped := env.loadRecord(t)
	for i := range stripped.Profiles {
		for j := range stripped.Profiles[i].Entries {
			stripped.Profiles[i].Entries[j].Fingerprint = record.Fingerprint{}
		}
	}
	_, err = record.Save(env.recordPath(t), stripped)
	require.NoError(t, err)

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, apply.ErrUnverifiable)
	require.True(t, IsRefusal(err), "preserved and reported, not overwritten")
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "--force")

	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	for _, e := range prof.Entries {
		if e.ID == "acme/code-review" {
			require.Equal(t, "2.4.0", e.Version)
		}
	}

	// --force names what it overwrites before doing so.
	forced := baselineFlags(tg)
	forced.force = true
	code, _, diag, err = env.run(t, output.FormatHuman, forced)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)
	require.Contains(t, diag.String(), "--force is overwriting")
	rec = env.loadRecord(t)
	prof, _ = rec.ProfileBySlug(tg.Fixtures.Profile)
	for _, e := range prof.Entries {
		if e.ID == "acme/code-review" {
			require.Equal(t, "2.4.1", e.Version)
		}
	}
}

// A removal this build cannot execute must be a reported failure, never a
// silent no-op that exits 0 with the withdrawn package still installed.
func TestAPlannedRemovalFailsLoudlyWhileThereIsNoPruner(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	_, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Len(t, skillDirs(t, env.skillsRoot()), 3)

	// Revision 6 holds one of the three entries, so the other two must be removed.
	code, _, _, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"6"}, force: true})
	require.Error(t, err)
	require.ErrorIs(t, err, apply.ErrPruneUnavailable)
	require.Equal(t, CodeFailure, code)
	require.ErrorContains(t, err, "no-longer-in-profile")
	require.Len(t, skillDirs(t, env.skillsRoot()), 3)
}

// Every bundle answers 403, so nothing installs: the hub must get no report
// claiming this revision, yet the exit code stays 0 since a gate decision is
// not a failure. `partial` and the skipped list tell a caller.
func TestAProfileThatLandedNothingIsNotReportedAsSynced(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	env.deps.httpClient = &http.Client{Transport: &failPathTransport{
		next: env.counted, prefix: "/v1/bundles/", status: http.StatusForbidden,
	}}

	code, result, diag, err := env.run(t, output.FormatJSON, baselineFlags(tg))
	require.NoError(t, err, "a gate that withholds every version is not a CLI failure")
	require.Equal(t, CodeNoChanges, code)

	require.NoDirExists(t, env.skillsRoot())
	require.Contains(t, diag.String(), "nothing was installed, so no sync was reported")

	var doc struct {
		Result struct {
			Added   []struct{} `json:"added"`
			Skipped []struct {
				Package string `json:"package"`
				Reason  string `json:"reason"`
			} `json:"skipped"`
			Partial bool `json:"partial"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Empty(t, doc.Result.Added)
	require.True(t, doc.Result.Partial, "the machine-readable signal a caller must switch on, since the exit code is 0")
	// Three hub skips plus three local ones.
	require.Len(t, doc.Result.Skipped, 6)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, reports, "no audit row may claim a revision this machine does not have")
}

// TestASyncReinstallsADestinationTheRecordClaimsAndTheDiskHasLost: plan labels
// such an entry unchanged since the disk isn't its input, so apply must notice
// the destination is gone, or sync reports success over an empty path forever.
func TestASyncReinstallsADestinationTheRecordClaimsAndTheDiskHasLost(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// Pick a directory the first sync installed, so a fixture rename can't make this vacuous.
	entries, err := os.ReadDir(env.skillsRoot())
	require.NoError(t, err)
	require.NotEmpty(t, entries, "the first sync installed nothing, so this test has no subject")
	victim := filepath.Join(env.skillsRoot(), entries[0].Name())

	before := treeSnapshot(t, victim)
	require.NotEmpty(t, before, "the subject must have had content to lose")
	require.NoError(t, os.RemoveAll(victim))

	code, result, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())

	require.Equal(t, CodeChanged, code,
		"a machine whose tree no longer matches its record has NOT converged, so this run changed something")
	require.NotContains(t, result.String(), "nothing to do",
		"reporting nothing to do over a destination that is gone is the worst failure")
	require.Contains(t, diag.String(), "but nothing is there; re-installing",
		"apply.guard's absent-destination branch is the one that must have run")
	require.NotContains(t, diag.String(), "--force",
		"an ABSENT destination needs no override: there is nothing to verify as unmodified")

	require.DirExists(t, victim)
	// Content, not mtime: a reinstall legitimately writes new timestamps.
	requireSameContent(t, "the reinstalled entry", before, treeSnapshot(t, victim))

	// Convergent: a third run has nothing left to do.
	code, result, diag, err = env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code)
	require.Contains(t, result.String(), "nothing to do")
}

// requireSameContent compares everything except mtime; requireUnchanged must
// keep mtime since it asserts no write happened.
func requireSameContent(t *testing.T, what string, want, got map[string]treeEntry) {
	t.Helper()
	require.Equal(t, len(want), len(got), "%s: the path set differs", what)
	for path, w := range want {
		g, ok := got[path]
		require.True(t, ok, "%s: %s did not come back", what, path)
		w.ModTime, g.ModTime = time.Time{}, time.Time{}
		require.Equal(t, w, g, "%s: %s came back different", what, path)
	}
}

func TestAPluginIsDecomposedIntoEveryTargetsOwnLocations(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	flags := syncFlags{profiles: []string{tg.Fixtures.Plugin}}
	code, result, diag, err := env.run(t, output.FormatJSON, flags)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	require.Equal(t, []string{"acme--toolkit--review"}, skillDirs(t, env.skillsRoot()))
	require.Equal(t, []string{"acme--toolkit--review"}, skillDirs(t, filepath.Join(env.home, ".agents", "skills")))
	require.NoDirExists(t, filepath.Join(env.home, ".config", "opencode", "skills"))

	var doc struct {
		Result struct {
			Added   []json.RawMessage `json:"added"`
			Skipped []output.Skip     `json:"skipped"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.String()), &doc))
	require.Len(t, doc.Result.Added, 3)
	require.Len(t, doc.Result.Skipped, 2)
	require.Equal(t, "claude-code", doc.Result.Skipped[0].Target)
	require.Equal(t, "mcp-server lint", doc.Result.Skipped[0].Component)
	require.Equal(t, deliver.SkipNoClaudeCLI, doc.Result.Skipped[0].Reason)
	require.Equal(t, "opencode", doc.Result.Skipped[1].Target)
	require.Equal(t, "skill review", doc.Result.Skipped[1].Component)
	require.Contains(t, doc.Result.Skipped[1].Reason, "served by")

	codex, err := os.ReadFile(filepath.Join(env.home, ".codex", "config.toml"))
	require.NoError(t, err)
	require.Equal(t, "[mcp_servers.toolkit-lint]\ncommand = \"lint-mcp\"\nargs = [\"--stdio\"]\n", string(codex))
	openCode, err := os.ReadFile(filepath.Join(env.home, ".config", "opencode", "opencode.json"))
	require.NoError(t, err)
	require.Contains(t, string(openCode), `"toolkit-lint": {`)

	code, _, diag, err = env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code)
}

func TestSyncReportsThisMachinesInventoryUnderOneKeptID(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	flags := syncFlags{profiles: []string{tg.Fixtures.Plugin}}

	_, _, diag, err := env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())
	_, _, diag, err = env.run(t, output.FormatHuman, flags)
	require.NoError(t, err, diag.String())

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 2)

	kept, err := os.ReadFile(filepath.Join(filepath.Dir(env.recordPath(t)), record.MachineIDFileName))
	require.NoError(t, err)
	id, err := uuid.Parse(strings.TrimSpace(string(kept)))
	require.NoError(t, err)
	for _, rep := range reports {
		require.NotNil(t, rep.MachineId)
		require.Equal(t, id, *rep.MachineId, "one id, kept across syncs")
		require.Equal(t, runtime.GOOS, *rep.Os)
		require.Equal(t, runtime.GOARCH, *rep.Arch)
		require.Equal(t, Version, *rep.AmctlVersion)
	}

	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Plugin)
	require.True(t, ok)
	first, second := *reports[0].Installed, *reports[1].Installed
	require.Len(t, first, len(prof.Entries))
	require.Len(t, second, len(prof.Entries))
	for i := range first {
		require.True(t, first[i].Changed != nil && *first[i].Changed, "the first sync wrote %s", first[i].Id)
		require.Nil(t, second[i].Changed, "the second sync wrote nothing")
	}

	require.NotNil(t, reports[0].SkippedComponents)
	var components []string
	for _, sk := range *reports[0].SkippedComponents {
		components = append(components, string(sk.Target)+" "+sk.Component)
	}
	require.Equal(t, []string{"claude-code mcp-server lint", "opencode skill review"}, components)
	require.Nil(t, reports[1].SkippedComponents, "an untouched entry's skips are the hub's to carry over")
}
