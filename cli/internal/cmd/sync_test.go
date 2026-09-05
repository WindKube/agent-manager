// This file is `amctl sync` end to end against the fake hub.
//
// The fake serves the shipping case directly: Fixtures.Profile and the other
// functional profiles name `["claude-code"]`, matching the real hub's own
// seeded lockfile, and Fixtures.UnwritableTarget is a profile of its own
// naming `["claude-code", "codex"]` so the unwritable-target refusal is
// exercised by a test that asks for it.
// TestTheUnwritableFixtureIsTheOnlyOneNamingCodex keeps that refusal test from
// going vacuous if the fixtures drift.
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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/credentials"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/output"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// syncHost is the hostname the sync report is filed under, injected so no
// assertion depends on the machine the suite runs on.
const syncHost = "sync-test-host"

// ---------------------------------------------------------------- the fake

func startSyncFake(t *testing.T) fake.Target {
	t.Helper()
	// TLS: amctl refuses a plaintext hub without --allow-plaintext-hub
	// so a plain-http fake would test the refusal instead of the sync.
	h := fake.New(fake.Options{TLS: true})
	t.Cleanup(h.Close)
	return h.Target()
}

// ---------------------------------------------------------------- wiring

// countingRoundTripper counts requests ON THE WIRE. Every "no request was made"
// assertion in this file is an observation of this counter, never an inference
// from an error message: a refusal whose wording changed would otherwise silently
// stop testing the ordering being tested.
type countingRoundTripper struct {
	next http.RoundTripper

	mu sync.Mutex
	n  int
	// before, when set, runs before each request. It is how a test observes the
	// state of the machine MID-SYNC without any hook in production code.
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
// with. The token arrives through AMCTL_TOKEN rather than the credential store
// so that no test depends on whether a Secret Service is running, and so the
// AMCTL_TOKEN precedence path is the one exercised by default;
// TestSyncUsesAStoredCredentialWhenTheEnvironmentHasNone covers the other.
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

// run runs the verb the way a user does, minus cobra, and returns the exit code,
// both streams and the error — in that order, so the error is last.
func (e *syncEnv) run(t *testing.T, format output.Format, flags syncFlags) (code Code, result, diag *syncBuffer, err error) {
	t.Helper()
	opts, result, diag := testOptions(e.target.BaseURL, format)
	err = runSync(context.Background(), opts, flags, e.deps)
	return ExitCode(opts.Outcome, err), result, diag, err
}

func baselineFlags(tg fake.Target) syncFlags {
	return syncFlags{profiles: []string{tg.Fixtures.Profile}}
}

// ---------------------------------------------------------------- tree snapshots

// treeEntry is one path as it exists on disk, in enough detail to prove
// byte-for-byte non-modification.
type treeEntry struct {
	Mode    fs.FileMode
	Size    int64
	SHA256  string
	Link    string
	ModTime time.Time
}

// treeSnapshot walks root and records every path. It uses Lstat, so a symlink is
// recorded as a symlink rather than followed — a check that followed links could
// not tell a replaced link from an unchanged one.
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
			// A DIRECTORY records its mode only. Its mtime and size move
			// whenever anything inside it is created or removed, and two things
			// a sync legitimately does move them: the per-home sync lock, which
			// is created and unlinked inside ~/.agent-manager on every run, and
			// the record's temp-file-then-rename write. Comparing them would
			// make every assertion here fail for the lock rather than for the
			// tree. What it costs is blindness to a file that was both added
			// and removed inside an unchanged directory; the strong form of that
			// property, measured by mtime across the whole tree, is
			// idempotence_test.go's.
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

// requireUnchanged asserts that every path present in before is byte-identical
// afterwards. It is used for the directories a sync must not touch.
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

// plantDecoyAgentDirectories creates the agent directories a sync must NOT
// touch, each with a file in it. Without them, "no other agent directory was
// written" would be a claim about directories that never existed, which is the
// assertion passing for the wrong reason.
func plantDecoyAgentDirectories(t *testing.T, home string) {
	t.Helper()
	// The codex roots, both the documented one and the widely published older
	// one. A build that guessed at codex would write into one of these.
	writeFile(t, filepath.Join(home, ".agents", "skills", "someones-skill", "SKILL.md"), "not amctl's\n")
	writeFile(t, filepath.Join(home, ".codex", "skills", "someones-skill", "SKILL.md"), "not amctl's\n")
	// A hand-written claude-code skill in the very directory amctl installs
	// into. The whole point of leaving hand-written files alone.
	writeFile(t, filepath.Join(home, ".claude", "skills", "my-own-skill", "SKILL.md"), "mine, hand written\n")
	// The XDG paths measured to be ones the agent does not read.
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

// ---------------------------------------------------------------- the happy path

func TestSyncInstallsEveryLockfileEntryAtItsLockedVersion(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	plantDecoyAgentDirectories(t, env.home)
	before := treeSnapshot(t, env.home)

	code, result, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code, "a sync that installed three entries changed the tree")

	// The tree, asserted against the lockfile rather than against the report:
	// a sync that printed a perfect result and wrote nothing would pass any
	// test that only read the result.
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer", "my-own-skill"},
		skillDirs(t, env.skillsRoot()))
	for _, dir := range []string{"acme--code-review", "acme--lint-guard", "example--doc-writer"} {
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, layout.SkillEntryFile))
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, "references", "usage.md"))
		requireFileExists(t, filepath.Join(env.skillsRoot(), dir, "scripts", "check.sh"))
		// The marker names which package and version it is, with no hub.
		markerBytes, rerr := os.ReadFile(filepath.Join(env.skillsRoot(), dir, layout.MarkerFileName))
		require.NoError(t, rerr)
		marker, perr := layout.ParseMarker(markerBytes)
		require.NoError(t, perr)
		require.Equal(t, record.TargetClaudeCode, marker.Target)
		require.NotEmpty(t, marker.Version)
	}

	// Only the enabled target's directory was written.
	after := treeSnapshot(t, env.home)
	requireUnchanged(t, "another agent's directory", map[string]treeEntry{
		".agents/skills/someones-skill/SKILL.md":   before[".agents/skills/someones-skill/SKILL.md"],
		".codex/skills/someones-skill/SKILL.md":    before[".codex/skills/someones-skill/SKILL.md"],
		".config/claude/skills/xdg-skill/SKILL.md": before[".config/claude/skills/xdg-skill/SKILL.md"],
		".claude/skills/my-own-skill/SKILL.md":     before[".claude/skills/my-own-skill/SKILL.md"],
	}, after)

	// The record names the revision the hub actually resolved, as a
	// number. `head` is a request, never a state.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	require.Equal(t, int(tg.Fixtures.HeadRevision), prof.Revision)
	require.Equal(t, []record.Target{record.TargetClaudeCode}, prof.Targets)
	require.Len(t, prof.Entries, 3)

	// Every hub skip reported with the hub's own reason.
	require.Contains(t, diag.String(), "flagged-awaiting-approval")
	require.Contains(t, diag.String(), "version-rejected")
	require.Contains(t, diag.String(), "pin-target-missing")
	require.Contains(t, diag.String(), "would have resolved to 1.9.0")
	require.Contains(t, result.String(), "synced "+tg.Fixtures.Profile)

	// Exactly one report, naming the profile, the resolved revision,
	// this host and the target written.
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
	// Idempotence at the verb level. The strong form — zero filesystem
	// modification measured by mtime across the whole tree — is
	// idempotence_test.go's; this asserts the verb's own account and the
	// record's, which is what selects the exit code.
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

// ---------------------------------------------------------------- refusals before any request

// TestHomeUnsetIsRefusedBeforeAnyRequest checks the ordering and exit code, and the
// assertion is the REQUEST COUNT, not the message. Prepare validates the home
// with a real write before the network callback runs, and a refusal that started
// happening after the first request would still produce the same error text.
func TestHomeUnsetIsRefusedBeforeAnyRequest(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// Unset the platform's own home variable, whichever it is: hardcoding HOME
	// would make this test assert nothing where that is not the one consulted.
	t.Setenv(homeEnvVar(), "")

	code, result, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHomeUnset)
	require.True(t, IsRefusal(err), "an unset home is a refusal the user can fix")
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, homeEnvVar())
	require.Equal(t, 0, env.counted.count(),
		"FR-039: the home is refused BEFORE any network request, and this counts them on the wire")
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

// TestNoCredentialIsRefusedNamingWhatSuppliesOne. Asking the hub first
// would produce a 401, which sends the reader to look at the hub when the real
// answer is that this machine never logged in.
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

// ---------------------------------------------------------------- the codex refusal

// TestALockfileNamingCodexIsSkippedAndClaudeCodeStillInstalls is GAP 2's
// verb-level check for a target this build cannot write. It syncs
// Fixtures.UnwritableTarget — the one profile naming both contract targets —
// and asserts codex is reported as a skip, never silently, while claude-code
// still installs: one target this build cannot write must not block the
// other, the same way one poisoned package must not block its siblings.
func TestALockfileNamingCodexIsSkippedAndClaudeCodeStillInstalls(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	flags := syncFlags{profiles: []string{tg.Fixtures.UnwritableTarget}}
	code, result, diag, err := env.run(t, output.FormatJSON, flags)
	require.NoError(t, err)
	require.Equal(t, CodeChanged, code)
	require.Contains(t, diag.String(), "codex")
	require.Contains(t, diag.String(), "cannot write")

	// claude-code installed despite codex being unwritable.
	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))

	// The result document names the skip and the target it could not write, so
	// a script does not have to parse the prose on stderr.
	var doc struct {
		Kind   string `json:"kind"`
		Result struct {
			Added []struct {
				Target string `json:"target"`
			} `json:"added"`
			Skipped []struct {
				Target string `json:"target"`
				Reason string `json:"reason"`
			} `json:"skipped"`
		} `json:"result"`
	}
	dec := json.NewDecoder(strings.NewReader(result.String()))
	require.NoError(t, dec.Decode(&doc))
	require.False(t, dec.More())
	require.Equal(t, "sync", doc.Kind)
	require.Len(t, doc.Result.Added, 1)
	require.Equal(t, "claude-code", doc.Result.Added[0].Target)
	require.Len(t, doc.Result.Skipped, 1)
	require.Equal(t, "codex", doc.Result.Skipped[0].Target)
	require.Equal(t, plan.SkipTargetUnwritable, doc.Result.Skipped[0].Reason)

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1, "a sync that installed something is reported")
}

// ------------------------------------------------- the withdrawn target

// withdrawnLockfile is a lockfile built in the test rather than served by the
// fake, on purpose: `agents-md` is still in the frozen enum on this branch and
// PR #16 removes it, so seeding it into the fake's catalogue would put a value
// in the conformance fixtures that the schema is about to reject. What is under
// test here is the WIRING — what the sync verb does with a target
// layout.Registry has withdrawn — and that needs no server.
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

// lockfileNamingCodex is withdrawnLockfile's shape with n skill entries
// instead of one, so a test can tell "one line" from "one line per entry".
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

// TestSkippedTargetUnwritableEntriesCollapseToOneLine is GAP 2's follow-up:
// a profile with several entries under a target this build cannot write must
// print ONE line naming the target and the count, on the diagnostic stream
// and in the human result, not one line per entry — the noise a live sync of
// example/platform-engineer produced before this test existed.
func TestSkippedTargetUnwritableEntriesCollapseToOneLine(t *testing.T) {
	lf := lockfileNamingCodex(3, "claude-code", "codex")

	opts, _, diag := testOptions("https://hub.example.com", output.FormatHuman)
	r := &syncRun{opts: opts, s: opts.Streams()}
	reg, err := layout.NewRegistry(layout.Config{HomeDir: filepath.Join(t.TempDir(), "home")})
	require.NoError(t, err)
	targets, _ := r.resolveTargets(reg, []*hub.Lockfile{lf})
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

// TestAWithdrawnTargetIsReportedAndTheSyncContinues is the wiring contradiction
// this test exists to pin.
//
// internal/layout argues at length that a withdrawn target must NOT refuse the
// sync — `agents-md` is the lockfile schema's own example value and a legal
// member of the frozen enum, the target list is the hub's, and there is nothing
// a user can change — and it built ErrWithdrawnTarget to say so. resolveTargets
// used to drop that sentinel into its `default` branch beside the refusal, so a
// profile naming agents-md exited 3 and installed nothing, with no user-side
// fix. The registry did the right thing and the verb did not use it.
func TestAWithdrawnTargetIsReportedAndTheSyncContinues(t *testing.T) {
	p, diag := planForTargets(t, withdrawnLockfile(t, "claude-code", "agents-md"))

	require.False(t, p.Refuses(), "a withdrawn target must not refuse a profile that also names a writable one")
	require.Empty(t, p.Conflicts)
	require.Len(t, p.Add, 1, "the claude-code entry still installs")
	require.Equal(t, record.TargetClaudeCode, p.Add[0].Target)
	require.Contains(t, diag, "agents-md",
		"FR-011's spirit: the difference between what the profile named and what was written is reported")
	require.Contains(t, diag, "will not write")
}

// TestAProfileWhoseTargetsAreAllWithdrawnIsRefused is the negative control for
// the test above, and the reason "reported, not fatal" is safe to do at all.
//
// Reporting a withdrawn target and carrying on is right only while something
// else is still being written. A profile that named nothing but withdrawn
// targets would otherwise install nothing and exit 0, which is verbatim the
// warn-and-continue outcome the refusal is meant to stop.
func TestAProfileWhoseTargetsAreAllWithdrawnIsRefused(t *testing.T) {
	p, _ := planForTargets(t, withdrawnLockfile(t, "agents-md"))

	require.True(t, p.Refuses())
	require.Len(t, p.Conflicts, 1)
	require.Equal(t, plan.ConflictNoWritableTarget, p.Conflicts[0].Kind)
	require.Contains(t, p.Conflicts[0].String(), "install nothing and still exit 0")
	require.Empty(t, p.Add)
}

// TestTheUnwritableFixtureIsTheOnlyOneNamingCodex is what keeps the skip test
// from going vacuous. TestALockfileNamingCodexIsSkippedAndClaudeCodeStillInstalls
// would pass trivially if Fixtures.UnwritableTarget stopped naming codex only
// because the skip moved earlier for some other reason, and every happy-path
// test in this file would break confusingly if Fixtures.Profile started naming
// it. Both halves are asserted against the served lockfile, not against the
// fixture struct, because the served document is what the client actually
// parses.
func TestTheUnwritableFixtureIsTheOnlyOneNamingCodex(t *testing.T) {
	tg := startSyncFake(t)

	unwritable := readLockfile(t, tg, tg.Fixtures.UnwritableTarget)
	require.Contains(t, unwritable["targets"], "codex",
		"the skip fixture must really name codex, or the skip test proves nothing")

	happy := readLockfile(t, tg, tg.Fixtures.Profile)
	require.Equal(t, []any{"claude-code"}, happy["targets"],
		"the functional profile must be syncable, or every test built on it is testing the refusal")
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

// ---------------------------------------------------------------- symlinked agent directories

// TestSyncFollowsASymlinkedAgentDirectoryInsideTheHome is the edge case that
// makes containment a real question rather than a tautology: agent directories are
// frequently symlinks into a dotfiles repository, so the containment check runs
// on the RESOLVED path and must not simply refuse a link.
func TestSyncFollowsASymlinkedAgentDirectoryInsideTheHome(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	dotfiles := filepath.Join(env.home, "dotfiles", "claude")
	require.NoError(t, os.MkdirAll(dotfiles, 0o700))
	require.NoError(t, os.Symlink(dotfiles, filepath.Join(env.home, ".claude")))

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// The bytes landed in the dotfiles repository, through the link.
	requireFileExists(t, filepath.Join(dotfiles, "skills", "acme--code-review", layout.SkillEntryFile))
	// And the RECORD holds the requested path, not the resolved one: recording
	// the resolution would make the next run read it as a relocation and
	// remove-and-re-add the entry forever.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	for _, e := range prof.Entries {
		require.True(t, strings.HasPrefix(e.Dest, filepath.Join(env.home, ".claude", "skills")),
			"the record stores the requested destination, %q", e.Dest)
	}
}

// TestSyncRefusesAnAgentDirectoryThatLeavesTheHome is the negative control for
// the test above. Without it, "the check runs on the resolved path" would be
// indistinguishable from "there is no check".
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

	// Nothing was written through the link.
	entries, rerr := os.ReadDir(outside)
	require.NoError(t, rerr)
	require.Empty(t, entries, "amctl must not follow a link out of the home")
}

// ---------------------------------------------------------------- partial success

// TestAForbiddenBundleSkipsThatEntryAndTheRestStillInstalls is the mid-sync
// case, and the exit code is the second half of the assertion: a partial success
// must be distinguishable from a total failure.
func TestAForbiddenBundleSkipsThatEntryAndTheRestStillInstalls(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, diag, err := env.run(t, output.FormatJSON,
		syncFlags{profiles: []string{tg.Fixtures.ForbiddenBundle}})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code,
		"the hub withheld one version and served the rest: a success with changes, not a failure")

	// The fixture's order is installable, 403, installable. A sync that aborted
	// on the 403 would leave the third entry uninstalled.
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
	require.False(t, dec.More(), "FR-035: one document on the result stream")
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

	// The record claims exactly what is on disk, and not the skipped entry: a
	// record row for something absent becomes a refusal next run.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.ForbiddenBundle)
	require.True(t, ok)
	require.Len(t, prof.Entries, 2)
	for _, e := range prof.Entries {
		require.NotEqual(t, tg.Fixtures.ForbiddenEntryID, e.ID)
	}

	// The report names it as a LOCAL skip, which is not the same list as
	// the lockfile's own `skipped`.
	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Len(t, reports, 1)
	require.NotNil(t, reports[0].Skipped)
	require.Equal(t, []string{tg.Fixtures.ForbiddenEntryID}, *reports[0].Skipped)
}

// TestADigestMismatchFailsThatEntryAndExitsNonZero is the
// contrast the test above needs: both runs install some entries and not others,
// and the exit codes must differ because one is the hub's decision and the other
// is a corrupted or substituted object.
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

	// Nothing from that bundle reached the tree, and the entry beside it
	// still installed.
	require.Equal(t, []string{"acme--code-review"}, skillDirs(t, env.skillsRoot()))
	// Both digests are named, which is the requirement.
	require.Contains(t, diag.String(), "sha256:")
	require.Contains(t, diag.String(), "the lockfile locked")

	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.DigestMismatch)
	require.True(t, ok)
	require.Len(t, prof.Entries, 1)
}

// TestAnAbandonedEntryIsNamedInTheReportAndTheResult is the half the test above
// never looked at: what the hub is told, and what a script reading --output json
// can see.
//
// A digest mismatch is the single event an audit trail most needs to carry —
// somebody substituted or corrupted the object this machine was told to install
// — and the report used to go out with no `skipped` field at all, so the hub's
// row read "synced digest-mismatch r1 to this host (claude-code)" for a machine
// that is missing contoso/stale-digest. hub.Report.SkippedLocally's own doc says
// a bundle "whose bytes did not match the digest the lockfile locked" belongs
// there. In the JSON the entry appeared in NO array: only `partial` said
// anything had gone wrong, and it did not say which package.
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

// ------------------------------------------- the 307 whose target refuses

// TestAStoreRefusingThePresignedURLFailsTheEntryRatherThanSkippingIt is the
// offload path's negative control at the verb level.
//
// getBundle answers 307 to a short-lived pre-signed URL. When the OBJECT STORE
// then answers 403 — an expired signature, clock skew, a proxy in front of the
// store; S3, GCS and MinIO all answer 403 for those — the CLI used to read it as
// the hub's own 403, which is defined as the organisation's scan gate and
// answers by skipping the entry and exiting 0. That is the "installs nothing and
// reports success" outcome this exists to prevent, over an infrastructure
// failure the next run would have fixed by asking for a fresh signature.
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

	// The entry beside it still installed, so this is per-entry and not an abort.
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

// ---------------------------------------------------------------- the lock

// TestTheLockIsHeldForTheWholeMutation observes the lock file from inside the
// run, on the real code path, with no hook in production code: the transport's
// pre-request callback fires while the sync is mid-flight, so if the lock were
// taken late or released early this would see it.
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
	require.Equal(t, CodeRefused, code, "FR-038: refused, never interleaved")
	require.Empty(t, result.String())
	require.Equal(t, 0, env.counted.count(),
		"the lock is taken before the first request, so a refused run costs the hub nothing")
}

// panicOnWrite is a result stream that panics. It is how a panic is injected
// INSIDE the locked region without a test hook in sync.go: Emit runs inside
// WithLock, so this panics with the lock held.
type panicOnWrite struct{}

func (panicOnWrite) Write([]byte) (int, error) { panic("the result stream exploded") }

// TestThePanickingSyncStillReleasesTheLock is why WithLock exists rather than a
// bare Acquire plus a defer at each call site. A panic that left the lock behind
// would make the machine unusable for 90 seconds, and a released one is what
// lets the very next run proceed.
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

	// And the proof that it is really released rather than merely absent: a
	// second run gets the lock instead of ErrLocked. The panic was injected at
	// the result stream, which is written last, so that run had already
	// converged the tree — hence no changes the second time.
	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.NotErrorIs(t, err, ErrLocked)
	require.Equal(t, CodeNoChanges, code)
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer"},
		skillDirs(t, env.skillsRoot()))
}

// ---------------------------------------------------------------- one document on the result stream

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

	// The progress went to the diagnostic stream, and none of it to the result.
	require.Contains(t, diag.String(), "resolving profile "+tg.Fixtures.Profile)
	require.Contains(t, diag.String(), "fetching ")
	require.NotContains(t, result.String(), "resolving profile")
	require.NotContains(t, result.String(), "warning:")

	// The token must not be anywhere in either stream. Asserted with
	// require.False and a hand-written message, never with NotContains — a
	// failing NotContains prints its haystack, which would put the token into
	// the output internal/leakscan's run-wide scan reads and turn one red test
	// into a permanent second failure in another package.
	require.False(t, strings.Contains(result.String(), tg.Token), "the bearer token reached the result stream")
	require.False(t, strings.Contains(diag.String(), tg.Token), "the bearer token reached the diagnostic stream")
}

// ---------------------------------------------------------------- --revision and --profile

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
		require.True(t, IsRefusal(err), "FR-037: no TTY, so name the flag rather than guess a profile")
		require.ErrorContains(t, err, "--profile")
	})
}

// TestAPinnedRevisionInstallsThatExactStateAndIsRecorded: a machine can
// be pinned to a known state. The fixture's prior revision holds a DIFFERENT
// version of the same package, so this cannot pass by fetching head.
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
	// Not-found must not read as unreachable, or the user goes hunting a
	// network fault that is not there.
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, _, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.MissingProfile}})
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.NotErrorIs(t, err, hub.ErrUnreachable)
	require.Equal(t, hub.ClassNotFound, hub.ClassOf(err))
	require.Equal(t, CodeRefused, code)
}

// ---------------------------------------------------------------- an unknown skip reason

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

// ---------------------------------------------------------------- --offline

func TestOfflineFailsNamingWhatIsMissingAndInstallsNothing(t *testing.T) {
	// The refusal has to arrive before the first entry is staged, or the
	// "MUST NOT leave a partially installed tree" half is false; the assertion
	// is that the skills root does not exist at all afterwards.
	//
	// NOT COVERED here, and a gap deliberately left open rather than closed:
	// --offline still fetches the LOCKFILE over the network, because nothing
	// caches one. On an aeroplane the run therefore fails at getRevision with
	// ErrUnreachable rather than completing from cache, which is not fully
	// offline. Closing it needs a persisted lockfile per synced revision.
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

	// Remove the installed tree but keep the bundle cache, then sync offline.
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

// ---------------------------------------------------------------- the record

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

// ---------------------------------------------------------------- errors

func TestAnUnreachableHubIsNotMistakenForAnythingElse(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)
	// A closed listener on a port nothing is on. Deliberately not a 500: the classification
	// exists so these two do not read the same.
	env.target.BaseURL = "https://127.0.0.1:1/"

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.ErrorIs(t, err, hub.ErrUnreachable)
	require.Equal(t, hub.ClassUnreachable, hub.ClassOf(err))
	require.Equal(t, CodeFailure, code, "a network fault is not a refusal: retrying may work")
	require.False(t, errors.Is(err, hub.ErrUnauthorised))
}

func TestAPlaintextHubIsRefusedWithoutTheFlag(t *testing.T) {
	// The plaintext refusal, at the verb. hub.New composes the message so the flag it names
	// cannot disagree with the one root.go registers.
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

// ---------------------------------------------------------------- several profiles at once

// TestTwoProfilesResolvingOnePackageToTwoVersionsIsRefused is the
// seventh acceptance scenario. It is only reachable in a SINGLE run, which is
// the whole reason --revision accepts the `<profile>=<revision>` form: telling
// the operator to sync one profile at a time would silently give up this check.
func TestTwoProfilesResolvingOnePackageToTwoVersionsIsRefused(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// Revision 6 of the baseline holds acme/code-review 2.4.0; the unknown-skip
	// profile holds 2.4.1. One package, two versions, two profiles.
	code, result, diag, err := env.run(t, output.FormatJSON, syncFlags{
		profiles:  []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason},
		revisions: []string{tg.Fixtures.Profile + "=6", tg.Fixtures.UnknownSkipReason + "=head"},
	})
	require.Error(t, err)
	require.True(t, IsRefusal(err))
	require.Equal(t, CodeRefused, code)

	// Both profiles and both versions are named, which is the requirement.
	for _, want := range []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason, "2.4.0", "2.4.1", "acme/code-review"} {
		require.Contains(t, diag.String(), want)
	}
	// Refused BEFORE anything was written.
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

// TestTwoProfilesAtHeadAreEachReportedWithTheirOwnRevision is the multi-profile
// happy path, and the report assertion is the point: the body has ONE profile
// field, so a two-profile sync is two reports, each carrying its own resolved
// revision.
func TestTwoProfilesAtHeadAreEachReportedWithTheirOwnRevision(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, result, diag, err := env.run(t, output.FormatJSON, syncFlags{
		profiles: []string{tg.Fixtures.Profile, tg.Fixtures.UnknownSkipReason},
	})
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// The revision field names BOTH, because one number would be a different
	// state in each profile and printing one of them would be a lie about the
	// other.
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

// TestEachSyncIsReportedOnceSoTwoSyncsAreTwoReports pins the reading of the report requirement's
// "exactly once": once per SYNC, not once per machine. The hub's sync_event table
// is the fleet's record of when each machine last converged, so an idempotent run
// that reported nothing would make a converged machine look abandoned.
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

// TestAFailedSyncReportDoesNotFailTheSync, at the verb. The bytes are
// already on disk, and refusing to admit it would be the wrong correction.
func TestAFailedSyncReportDoesNotFailTheSync(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	// Fail only POST /v1/sync, and only that: everything else must succeed, or
	// this would be a test of a broken hub rather than of a broken report.
	env.deps.httpClient = &http.Client{Transport: &failPathTransport{
		next: env.counted, path: "/v1/sync", status: http.StatusServiceUnavailable,
	}}

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, "a failed report must not fail the sync")
	require.Equal(t, CodeChanged, code)
	require.Equal(t,
		[]string{"acme--code-review", "acme--lint-guard", "example--doc-writer"},
		skillDirs(t, env.skillsRoot()))

	// The second half: it is reported on the diagnostic stream, and the
	// message says why there is no retry.
	require.Contains(t, diag.String(), "was not reported")
	require.Contains(t, diag.String(), "not retried")

	reports, cerr := tg.Control.SyncReports()
	require.NoError(t, cerr)
	require.Empty(t, reports)
}

// failPathTransport answers one path, or everything under one prefix, with a
// status of its own, and passes everything else through. Narrow on purpose: a
// transport that failed indiscriminately would test a broken hub rather than the
// one endpoint each case is about.
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

// ---------------------------------------------------------------- the fingerprint/prune gaps

// TestAnUpgradeOfAnUnfingerprintedEntryRefusesUntilForced documents a real
// consequence of the fingerprinter not existing yet, and asserts it fails in the safe
// direction. internal/apply requires a POSITIVE unmodified verdict before it
// overwrites, and an entry installed by this build carries no fingerprint, so
// every upgrade refuses naming --force rather than assuming the destination is
// untouched. Assuming unmodified is the direction that destroys somebody's edit.
func TestAnUpgradeOfAnUnfingerprintedEntryRefusesUntilForced(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	pinned := syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"6"}}
	_, _, diag, err := env.run(t, output.FormatHuman, pinned)
	require.NoError(t, err, diag.String())

	code, _, _, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.Error(t, err)
	require.ErrorIs(t, err, apply.ErrUnverifiable)
	require.True(t, IsRefusal(err), "FR-029: preserved and reported, not overwritten")
	require.Equal(t, CodeRefused, code)
	require.ErrorContains(t, err, "--force")

	// The old version is still installed and still recorded, untouched.
	rec := env.loadRecord(t)
	prof, ok := rec.ProfileBySlug(tg.Fixtures.Profile)
	require.True(t, ok)
	for _, e := range prof.Entries {
		if e.ID == "acme/code-review" {
			require.Equal(t, "2.4.0", e.Version)
		}
	}

	// --force overrides it and NAMES what it is overwriting before doing so.
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

// TestAPlannedRemovalFailsLoudlyWhileThereIsNoPruner documents the other gap.
// A removal this build cannot execute must be a reported failure and never
// a silent no-op: the whole point is that a package the hub withdrew
// leaves the machine, and a sync that exits 0 having left it there is the lie
// this fails closed to avoid.
func TestAPlannedRemovalFailsLoudlyWhileThereIsNoPruner(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	_, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Len(t, skillDirs(t, env.skillsRoot()), 3)

	// Revision 6 holds one of the three entries, so the other two left the
	// profile and must be removed.
	code, _, _, err := env.run(t, output.FormatHuman,
		syncFlags{profiles: []string{tg.Fixtures.Profile}, revisions: []string{"6"}, force: true})
	require.Error(t, err)
	require.ErrorIs(t, err, apply.ErrPruneUnavailable)
	require.Equal(t, CodeFailure, code)
	require.ErrorContains(t, err, "no-longer-in-profile")
	// Still on disk, and said so, rather than quietly abandoned.
	require.Len(t, skillDirs(t, env.skillsRoot()), 3)
}

// TestAProfileThatLandedNothingIsNotReportedAsSynced is the honest half of the
// partial-success decision, and it is the one most likely to be got wrong.
//
// Every bundle answers 403, so every entry is a local skip and nothing installs.
// Two things must be true: the hub must NOT receive a report claiming this
// machine is at that revision — a false row in the audit trail is worse than a
// missing one — and the exit code must still be 0, because a gate decision is
// the hub's and not a failure this CLI could fix. What tells a caller apart is
// `partial` and the skipped list, not the exit status.
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

// ---------------------------------------------------------------- convergence when the disk disagrees with the record

// for the state a record-only "unchanged" decision cannot see: the record
// claims the locked version and the destination is GONE.
//
// internal/plan is a pure function of the lockfile, the record and the comparer
// (plan/doc.go), so the disk is not one of its inputs and it labels such an entry
// OpUnchanged. Before internal/apply's presentAndGone, those entries were copied
// straight into the result and `sync` reported "nothing to do" over an empty
// path — the worst failure, reported success having written nothing, and
// permanent: the record and the lockfile agree forever, so no later run would fix
// it either.
//
// Two ways in, and this test uses the second because it is the one a user can
// reach without a debugger:
//
//   - a sync killed after the record write and before the staging discard, then
//     one rename. That is interrupt_test.go's aside-window state, and hitting it
//     on purpose needs a real kill.
//   - somebody deletes an installed skill directory. Identical from here, and it
//     is the ordinary case: the record still names the version, nothing is there.
func TestASyncReinstallsADestinationTheRecordClaimsAndTheDiskHasLost(t *testing.T) {
	tg := startSyncFake(t)
	env := newSyncEnv(t, tg)

	code, _, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeChanged, code)

	// Pick a directory the first sync actually installed, rather than naming one:
	// a fixture rename would otherwise turn this test green by testing nothing.
	entries, err := os.ReadDir(env.skillsRoot())
	require.NoError(t, err)
	require.NotEmpty(t, entries, "the first sync installed nothing, so this test has no subject")
	victim := filepath.Join(env.skillsRoot(), entries[0].Name())

	before := treeSnapshot(t, victim)
	require.NotEmpty(t, before, "the subject must have had content to lose")
	require.NoError(t, os.RemoveAll(victim))

	// The record is untouched, so it still claims the locked version at a path
	// that is now absent. This is the state under test.
	code, result, diag, err := env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())

	require.Equal(t, CodeChanged, code,
		"a machine whose tree no longer matches its record has NOT converged, so this run changed something")
	require.NotContains(t, result.String(), "nothing to do",
		"reporting nothing to do over a destination that is gone is FR-021's worst failure")
	require.Contains(t, diag.String(), "but nothing is there; re-installing",
		"apply.guard's absent-destination branch is the one that must have run")
	require.NotContains(t, diag.String(), "--force",
		"an ABSENT destination needs no override: there is nothing to verify as unmodified")

	require.DirExists(t, victim)
	// Content, not mtime: a reinstall legitimately writes new timestamps, so the
	// claim here is that the same paths came back with the same bytes and modes.
	requireSameContent(t, "the reinstalled entry", before, treeSnapshot(t, victim))

	// And it is convergent, not oscillating: a third run has nothing left to do.
	code, result, diag, err = env.run(t, output.FormatHuman, baselineFlags(tg))
	require.NoError(t, err, diag.String())
	require.Equal(t, CodeNoChanges, code)
	require.Contains(t, result.String(), "nothing to do")
}

// requireSameContent compares two snapshots on everything except mtime. It is
// separate from requireUnchanged, which asserts NO WRITE HAPPENED and must keep
// comparing mtime — that is the only channel that sees an in-place rewrite of
// identical bytes (see idempotence_test.go). Here a write is expected and the
// question is whether it restored the same tree.
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
