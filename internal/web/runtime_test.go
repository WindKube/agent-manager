package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

func TestTheRuntimeScreenTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source *governance
		id     string
		status int
	}{
		{
			name:   "genuinely empty",
			source: &governance{},
			id:     `id="runtime-discarded-empty"`,
			status: http.StatusOK,
		},
		{
			name:   "refused by role",
			source: &governance{err: hub.ErrForbidden},
			id:     `id="runtime-refused"`,
			status: http.StatusForbidden,
		},
		{
			name:   "the api did not answer",
			source: &governance{err: errBoom},
			id:     `id="runtime-unavailable"`,
			status: http.StatusBadGateway,
		},
		{
			name:   "no usable session",
			source: &governance{err: view.ErrSignedOut},
			id:     `id="runtime-signed-out"`,
			status: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, govHandler(tc.source, fixture.SignedInViewers(), nil), "/runtime")
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

// A hub with no source wired is a deployment fault; it must not render as a
// queue with nothing in it.
func TestRuntimeWithNoSourceRendersUnavailableNotEmpty(t *testing.T) {
	h := web.New(web.Deps{
		Catalog: &governance{}, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	rec := get(t, h, "/runtime")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="runtime-unavailable"`)
}

// TestTheRuntimeScreenSeparatesDiscardedFromRetrying is the whole point of the
// two lists: a job whose retries are exhausted must never render beside one
// still retrying on its own, and each must say which it is.
func TestTheRuntimeScreenSeparatesDiscardedFromRetrying(t *testing.T) {
	source := &governance{runtime: view.Runtime{
		Queues: []view.QueueCounts{{Queue: "fetch"}, {Queue: "scan"}},
		Discarded: []view.JobRow{
			{ID: 1, Queue: "scan", Kind: "scan", Attempt: 5, MaxAttempts: 5, When: "2026-09-10 08:00 UTC",
				Errors: []view.ErrorEntry{{At: "2026-09-10 08:00 UTC", Attempt: 5, Error: "signature mismatch"}}},
		},
		Retrying: []view.JobRow{
			{ID: 2, Queue: "fetch", Kind: "fetch", Attempt: 2, MaxAttempts: 5, When: "2026-09-10 09:00 UTC",
				Errors: []view.ErrorEntry{{At: "2026-09-10 08:45 UTC", Attempt: 2, Error: "connection reset"}}},
		},
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/runtime").Body.String()

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
	source := &governance{runtime: view.Runtime{
		Queues: []view.QueueCounts{
			{Queue: "fetch", Available: 3, Scheduled: 2, Running: 1, Retryable: 4, Completed: 100, Discarded: 5, Cancelled: 6},
		},
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/runtime").Body.String()

	for _, label := range []string{"Available", "Scheduled", "Running", "Retryable", "Completed", "Discarded", "Cancelled"} {
		require.Containsf(t, body, label, "%s is missing from the state table", label)
	}
}

// TestRuntimeChartLabelsItsOwnUnits is the requirement that a bar chart with no
// readable units is worse than a table: the bucket width and the axis clock
// must be on the page, not just the bars.
func TestRuntimeChartLabelsItsOwnUnits(t *testing.T) {
	history := make([]view.RunBucket, 24)
	now := time.Now().UTC().Truncate(time.Hour)
	for i := range history {
		history[i] = view.RunBucket{StartsAt: now.Add(time.Duration(i-23) * time.Hour), Fetch: int64(i), Scan: 1}
	}
	source := &governance{runtime: view.Runtime{History: history, BucketMinutes: 60}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/runtime").Body.String()

	require.Contains(t, body, "1 hour")
	require.Contains(t, body, "UTC")
	// The pair's bars stand side by side, so the axis names the tallest single
	// bar — the last bucket's fetch 23, not its fetch 23 plus scan 1.
	require.Contains(t, body, "tallest bar 23 jobs")
}
