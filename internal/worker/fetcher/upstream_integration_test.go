//go:build integration

package fetcher_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/fetch"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/fetcher"
)

// tagForge answers the tag listing with whatever the test currently says
// the repository has, or with a 500 while failing is set.
type tagForge struct {
	mu      sync.Mutex
	tags    []string
	failing bool
}

func (f *tagForge) set(failing bool, tags ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing, f.tags = failing, tags
}

func newTagForge(t *testing.T) (forge *tagForge, base string) {
	t.Helper()
	forge = &tagForge{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forge.mu.Lock()
		defer forge.mu.Unlock()
		if r.URL.Path != "/api/v3/repos/org/plugin/tags" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if forge.failing {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"boom"}`))
			return
		}
		entries := make([]string, 0, len(forge.tags))
		for _, tag := range forge.tags {
			entries = append(entries, fmt.Sprintf(`{"name":%q,"commit":{"sha":%q}}`, tag, forgeCommit))
		}
		_, _ = w.Write([]byte("[" + strings.Join(entries, ",") + "]"))
	}))
	t.Cleanup(server.Close)
	return forge, server.URL
}

// trackedPackage registers publisher/platform-toolkit@1.3.0 from the forge and
// turns tracking on, as its owner would.
func trackedPackage(t *testing.T, base, publisher, pattern string) string {
	t.Helper()
	ctx := context.Background()
	registered, err := commands.RegisterPackage(ctx, db, principal(), commands.Registration{
		Source: fetch.SourceGit, URL: base + "/org/plugin", Ref: "v1.3.0", Subdirectory: "kit",
		Publisher: publisher, Name: "platform-toolkit",
	})
	require.NoError(t, err)
	namespace, _, _ := strings.Cut(publisher, "/")
	require.NoError(t, commands.SetPackageTracking(ctx, db, principal(), namespace, "platform-toolkit", true, pattern))
	t.Cleanup(func() {
		_, cleanupErr := pool.Exec(context.Background(), `update package set track_upstream = false where id = $1`, registered.PackageID)
		require.NoError(t, cleanupErr)
	})
	return registered.PackageID
}

func newUpstream(t *testing.T, base string) *fetcher.Upstream {
	t.Helper()
	client, err := fetch.New(fetch.Options{Timeout: 20 * time.Second, Allowlist: []string{loopbackOf(t, base)}})
	require.NoError(t, err)
	// As am_fetcher, to run on the role's real grants.
	upstream, err := fetcher.NewUpstream(worker.Deps{DB: workerDB, Fetch: client, Log: zerolog.New(io.Discard)})
	require.NoError(t, err)
	return upstream
}

func semvers(t *testing.T, packageID string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`select semver from version where package_id = $1 order by semver_sort`, packageID)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var semver string
		require.NoError(t, rows.Scan(&semver))
		out = append(out, semver)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestTheUpstreamCheckRegistersNewTagsLikeARegistrationAndOnlyOnce(t *testing.T) {
	ctx := context.Background()
	forge, base := newTagForge(t)
	packageID := trackedPackage(t, base, "upstream/team", "v*")
	upstream := newUpstream(t, base)

	forge.set(false, "v1.2.0", "v1.3.0", "v1.4.0", "v2.0.0-rc.1", "v2.0.0", "nightly")
	require.NoError(t, upstream.CheckAll(ctx))

	require.Equal(t, []string{"1.3.0", "1.4.0", "2.0.0"}, semvers(t, packageID))
	for _, semver := range []string{"1.4.0", "2.0.0"} {
		var versionID string
		require.NoError(t, pool.QueryRow(ctx,
			`select id::text from version where package_id = $1 and semver = $2 and source_ref = $3
			   and not visible and digest is null and verdict = 'scanning'`,
			packageID, semver, "v"+semver).Scan(&versionID))

		// The ordinary fetch job, so fetch, scan and gate apply unchanged.
		job := pendingFetchJob(t, versionID)
		require.Equal(t, fetcher.JobSource{
			Kind: fetch.SourceGit, URL: base + "/org/plugin", Ref: "v" + semver, Subdirectory: "kit",
		}, job.Source)

		require.Equal(t, 1, countRows(t, `select count(*) from audit_event
		  where actor = 'fetcher' and actor_kind = 'system' and kind = 'fetch'
		    and subject_kind = 'version' and subject_id = $1
		    and data->>'action' = 'registered' and data->>'trigger' = 'new upstream tag'
		    and text like '%(new upstream tag)'`, "upstream/platform-toolkit@"+semver))
	}
	require.Equal(t, 1, countRows(t, `select count(*) from package where id = $1
	  and last_checked_at is not null and last_check_error is null and source_ref = 'v2.0.0'`, packageID))

	before := countRows(t, `select count(*) from audit_event where namespace = 'upstream'`)
	outboxBefore := countRows(t, `select count(*) from outbox where job_kind = 'fetch'`)
	require.NoError(t, upstream.CheckAll(ctx))
	require.Equal(t, []string{"1.3.0", "1.4.0", "2.0.0"}, semvers(t, packageID), "a second run registers nothing")
	require.Equal(t, before, countRows(t, `select count(*) from audit_event where namespace = 'upstream'`))
	require.Equal(t, outboxBefore, countRows(t, `select count(*) from outbox where job_kind = 'fetch'`))
}

func TestTheUpstreamCheckCatchesUpABacklogFiveAtATime(t *testing.T) {
	ctx := context.Background()
	forge, base := newTagForge(t)
	packageID := trackedPackage(t, base, "backlog/team", "v*")
	upstream := newUpstream(t, base)

	tags := []string{"v1.3.0"}
	for minor := 4; minor <= 10; minor++ {
		tags = append(tags, fmt.Sprintf("v1.%d.0", minor))
	}
	forge.set(false, tags...)

	require.NoError(t, upstream.CheckAll(ctx))
	require.Equal(t, []string{"1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0"}, semvers(t, packageID))
	require.NoError(t, upstream.CheckAll(ctx))
	require.Equal(t, []string{"1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.8.0", "1.9.0", "1.10.0"},
		semvers(t, packageID))
}

func TestAFailingUpstreamIsRecordedOnThePackageAndAuditedOncePerChange(t *testing.T) {
	ctx := context.Background()
	forge, base := newTagForge(t)
	packageID := trackedPackage(t, base, "flaky/team", "v*")
	upstream := newUpstream(t, base)
	transitions := func(action string) int {
		return countRows(t, `select count(*) from audit_event
		  where subject_id = 'flaky/platform-toolkit' and actor = 'fetcher' and data->>'action' = $1`, action)
	}

	forge.set(true)
	require.NoError(t, upstream.CheckAll(ctx), "one forge failing does not fail the job")
	require.NoError(t, upstream.CheckAll(ctx))

	var lastError string
	require.NoError(t, pool.QueryRow(ctx, `select last_check_error from package where id = $1`, packageID).Scan(&lastError))
	require.Contains(t, lastError, "500")
	require.Equal(t, 1, transitions("upstream-check-failed"), "the same failure twice is one change")
	require.Equal(t, []string{"1.3.0"}, semvers(t, packageID))

	forge.set(false, "v1.3.0")
	require.NoError(t, upstream.CheckAll(ctx))
	require.Equal(t, 1, transitions("upstream-check-recovered"))
	require.Equal(t, 1, countRows(t, `select count(*) from package where id = $1 and last_check_error is null`, packageID))
}

func TestTrackingIsTheOwnersOrACatalogAdminsAndOnlyForGit(t *testing.T) {
	ctx := context.Background()
	_, base := newTagForge(t)
	trackedPackage(t, base, "tracking/team", "v*")

	require.Equal(t, 1, countRows(t, `select count(*) from audit_event
	  where subject_kind = 'package' and subject_id = 'tracking/platform-toolkit'
	    and data->>'action' = 'tracking-changed' and data->>'trackUpstream' = 'true' and data->>'tagPattern' = 'v*'`))

	stranger := principal()
	stranger.Role = models.OrgRoleReadOnly
	stranger.IdentityID = models.NewID()
	err := commands.SetPackageTracking(ctx, db, stranger, "tracking", "platform-toolkit", false, "")
	var refused *commands.PackageNotPermittedError
	require.ErrorAs(t, err, &refused)
	require.Contains(t, err.Error(), "upstream tracking")

	err = commands.SetPackageTracking(ctx, db, principal(), "tracking", "platform-toolkit", true, "v[")
	require.ErrorIs(t, err, commands.ErrRegistration)

	_, err = commands.RegisterPackage(ctx, db, principal(), commands.Registration{
		Source: fetch.SourceArchiveURL, URL: "https://cdn.example.dev/platform-toolkit-1.4.0.zip",
		Publisher: "tracking/team", Name: "platform-toolkit", Version: "1.4.0",
	})
	require.NoError(t, err)
	require.Equal(t, 1, countRows(t, `select count(*) from package
	  where namespace = 'tracking' and name = 'platform-toolkit' and not track_upstream`),
		"moving off git ends tracking rather than tripping package_tracks_only_git")
	err = commands.SetPackageTracking(ctx, db, principal(), "tracking", "platform-toolkit", true, "")
	require.ErrorIs(t, err, commands.ErrRegistration)

	var payload []byte
	require.NoError(t, pool.QueryRow(ctx, `select data from audit_event
	  where subject_id = 'tracking/platform-toolkit' and data->>'action' = 'source-changed'`).Scan(&payload))
	var data map[string]any
	require.NoError(t, json.Unmarshal(payload, &data))
	require.Equal(t, "archive-url", data["sourceKind"])
}
