package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

func TestTheRuntimeScreenTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failAs int
		id     string
		status int
	}{
		{name: "genuinely empty", id: `id="runtime-discarded-empty"`, status: http.StatusOK},
		{name: "refused by role", failAs: http.StatusForbidden, id: `id="runtime-refused"`, status: http.StatusForbidden},
		{
			name: "the api did not answer", failAs: http.StatusServiceUnavailable,
			id: `id="runtime-unavailable"`, status: http.StatusBadGateway,
		},
		{name: "no usable session", failAs: http.StatusUnauthorized, id: `id="runtime-signed-out"`, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, h := newServer(t)
			api.Data.Runtime = apiclient.RuntimeReport{}
			if tc.failAs != 0 {
				api.Fail("getRuntime", tc.failAs)
			}
			rec := get(t, h, "/runtime")
			require.Equal(t, tc.status, rec.Code)
			body := rec.Body.String()
			require.Contains(t, body, tc.id)

			for _, other := range []string{
				"runtime-refused", "runtime-unavailable", "runtime-signed-out",
			} {
				if strings.Contains(tc.id, other) {
					continue
				}
				require.NotContainsf(t, body, `id="`+other+`"`, "this state also renders %q", other)
			}
		})
	}
}

// TestTheRuntimeScreenSeparatesDiscardedFromRetrying is the whole point of the
// two lists: a job whose retries are exhausted must never render beside one
// still retrying on its own, and each must say which it is.
func TestTheRuntimeScreenSeparatesDiscardedFromRetrying(t *testing.T) {
	api, h := newServer(t)
	at := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	api.Data.Runtime = apiclient.RuntimeReport{
		Queues: []apiclient.QueueSummary{{Queue: apiclient.QueueSummaryQueueFetch}, {Queue: apiclient.QueueSummaryQueueScan}},
		Errors: apiclient.RuntimeErrors{
			Discarded: []apiclient.RuntimeJob{{
				Id: 1, Queue: apiclient.RuntimeJobQueueScan, Kind: "scan", Attempt: 5, MaxAttempts: 5, FinalizedAt: &at,
				Errors: []apiclient.JobAttemptError{{At: at, Attempt: 5, Error: "signature mismatch"}},
			}},
			Retrying: []apiclient.RuntimeJob{{
				Id: 2, Queue: apiclient.RuntimeJobQueueFetch, Kind: "fetch", Attempt: 2, MaxAttempts: 5, ScheduledAt: at.Add(time.Hour),
				Errors: []apiclient.JobAttemptError{{At: at.Add(45 * time.Minute), Attempt: 2, Error: "connection reset"}},
			}},
		},
	}
	body := get(t, h, "/runtime").Body.String()

	discarded := strings.Index(body, "signature mismatch")
	retrying := strings.Index(body, "connection reset")
	require.Positive(t, discarded, "the discarded job's error is missing")
	require.Positive(t, retrying, "the retrying job's error is missing")
	require.Less(t, discarded, retrying, "the two lists are not in their own sections, in order")
	require.Contains(t, body, "5/5")
	require.Contains(t, body, "2/5")
}

// TestRuntimeQueueCountsUseRiversOwnVocabulary is the whole reason River's
// states are not collapsed: every one of the seven must be readable on the
// page, distinct from every other.
func TestRuntimeQueueCountsUseRiversOwnVocabulary(t *testing.T) {
	api, h := newServer(t)
	api.Data.Runtime = apiclient.RuntimeReport{Queues: []apiclient.QueueSummary{{
		Queue:  apiclient.QueueSummaryQueueFetch,
		Counts: apiclient.QueueJobCounts{Available: 3, Scheduled: 2, Running: 1, Retryable: 4, Completed: 100, Discarded: 5, Cancelled: 6},
	}}}
	body := get(t, h, "/runtime").Body.String()

	for _, label := range []string{"Available", "Scheduled", "Running", "Retryable", "Completed", "Discarded", "Cancelled"} {
		require.Containsf(t, body, label, "%s is missing from the state table", label)
	}
}

// TestRuntimeChartLabelsItsOwnUnits is the requirement that a bar chart with no
// readable units is worse than a table: the bucket width and the axis clock
// must be on the page, not just the bars.
func TestRuntimeChartLabelsItsOwnUnits(t *testing.T) {
	history := make([]apiclient.RunBucket, 24)
	now := time.Now().UTC().Truncate(time.Hour)
	for i := range history {
		history[i] = apiclient.RunBucket{StartsAt: now.Add(time.Duration(i-23) * time.Hour), Fetch: int64(i), Scan: 1}
	}
	api, h := newServer(t)
	api.Data.Runtime = apiclient.RuntimeReport{RunHistory: history, BucketMinutes: 60}
	body := get(t, h, "/runtime").Body.String()

	require.Contains(t, body, "1 hour")
	require.Contains(t, body, "UTC")
	// The pair's bars stand side by side, so the axis names the tallest single
	// bar — the last bucket's fetch 23, not its fetch 23 plus scan 1.
	require.Contains(t, body, "tallest bar 23 jobs")
}

// TestRuntimeHeaderHasAPlainRefreshLink is the counterpart to the catalog's
// refresh button: this screen has no fragment endpoint, so its refresh must
// be an honest full-page navigation to /runtime rather than a datastar round
// trip to a route that does not exist.
func TestRuntimeHeaderHasAPlainRefreshLink(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/runtime").Body.String()

	require.Contains(t, body, `href="/runtime"`, "the refresh control must reload this same screen")
	require.Contains(t, body, `aria-label="Refresh runtime report"`,
		"an icon-only control needs a name a screen reader can announce")
	require.Contains(t, body, `class="am-btn am-btn-icon"`,
		"the refresh control must reuse the catalog header's own button styling")
	require.Contains(t, body, `<span class="am-icon-refresh"`,
		"the refresh control must reuse the catalog header's own icon glyph")

	require.NotContains(t, body, "@get('/runtime')",
		"there is no fragment endpoint for this screen; the refresh must not pretend there is one")
}
