//go:build integration

package queries

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
)

// riverJob is the river_job columns this suite varies; the rest keep defaults.
type riverJob struct {
	State       string
	Queue       string
	Kind        string
	Attempt     int
	MaxAttempts int
	ScheduledAt time.Time
	FinalizedAt *time.Time
	AttemptedAt *time.Time
	// Errors is raw JSON per attempt, River's own shape, oldest first.
	Errors []string
}

// insertRiverJob writes one row straight into river_job, returns its id and
// deletes it on cleanup.
func insertRiverJob(ctx context.Context, t *testing.T, job riverJob) int64 {
	t.Helper()

	args := []any{job.State, job.Queue, job.Kind, job.Attempt, job.MaxAttempts,
		job.ScheduledAt, job.FinalizedAt, job.AttemptedAt}
	errExprs := make([]string, len(job.Errors))
	for i, e := range job.Errors {
		args = append(args, e)
		errExprs[i] = fmt.Sprintf("$%d::jsonb", len(args))
	}
	errorsExpr := "array[]::jsonb[]"
	if len(errExprs) > 0 {
		errorsExpr = "array[" + strings.Join(errExprs, ",") + "]"
	}

	sql := fmt.Sprintf(`
		insert into river_job
			(state, queue, kind, attempt, max_attempts, scheduled_at, finalized_at, attempted_at, args, errors)
		values ($1::river_job_state, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, %s)
		returning id`, errorsExpr)

	var id int64
	require.NoError(t, benchQueue.QueryRow(ctx, sql, args...).Scan(&id))
	t.Cleanup(func() {
		_, err := benchQueue.Exec(context.Background(), "delete from river_job where id = $1", id)
		require.NoError(t, err)
	})
	return id
}

func TestRuntimeCountsEveryRiverStateWithoutCollapsingAnyOfThem(t *testing.T) {
	ctx := t.Context()
	queue := fmt.Sprintf("test-counts-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	terminal := now

	for _, job := range []riverJob{
		{State: "available", Queue: queue, Kind: "fetch", MaxAttempts: 5, ScheduledAt: now},
		{State: "scheduled", Queue: queue, Kind: "fetch", MaxAttempts: 5, ScheduledAt: now.Add(time.Minute)},
		{State: "running", Queue: queue, Kind: "fetch", MaxAttempts: 5, ScheduledAt: now, AttemptedAt: &now},
		{State: "retryable", Queue: queue, Kind: "fetch", Attempt: 1, MaxAttempts: 5, ScheduledAt: now.Add(time.Hour)},
		{State: "completed", Queue: queue, Kind: "fetch", Attempt: 1, MaxAttempts: 5, ScheduledAt: now, FinalizedAt: &terminal},
		{State: "discarded", Queue: queue, Kind: "fetch", Attempt: 5, MaxAttempts: 5, ScheduledAt: now, FinalizedAt: &terminal},
		{State: "cancelled", Queue: queue, Kind: "fetch", MaxAttempts: 5, ScheduledAt: now, FinalizedAt: &terminal},
		// A real River state this hub never assigns: counted on Other.
		{State: "pending", Queue: queue, Kind: "fetch", MaxAttempts: 5, ScheduledAt: now},
	} {
		insertRiverJob(ctx, t, job)
	}

	report, err := Runtime(ctx, benchQueue, now)
	require.NoError(t, err)

	var summary *contract.QueueSummary
	for i := range report.Queues {
		if report.Queues[i].Queue == queue {
			summary = &report.Queues[i]
			break
		}
	}
	require.NotNilf(t, summary, "the scratch queue %q did not appear in the report at all", queue)

	require.EqualValues(t, 1, summary.Counts.Available)
	require.EqualValues(t, 1, summary.Counts.Scheduled)
	require.EqualValues(t, 1, summary.Counts.Running)
	require.EqualValues(t, 1, summary.Counts.Retryable)
	require.EqualValues(t, 1, summary.Counts.Completed)
	require.EqualValues(t, 1, summary.Counts.Discarded)
	require.EqualValues(t, 1, summary.Counts.Cancelled)
	require.EqualValues(t, 1, summary.Counts.Other,
		"a job in a state this vocabulary does not name must still be counted, not dropped")
}

func TestRuntimeAlwaysReportsFetchAndScanEvenAtZero(t *testing.T) {
	report, err := Runtime(t.Context(), benchQueue, time.Now())
	require.NoError(t, err)

	names := map[string]bool{}
	for _, q := range report.Queues {
		names[q.Queue] = true
	}
	require.True(t, names["fetch"])
	require.True(t, names["scan"])
}

func TestRuntimeSeparatesDiscardedFromRetryingAndCarriesRiversRecordedErrors(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	finalized := now.Add(-time.Minute)

	discardedID := insertRiverJob(ctx, t, riverJob{
		State: "discarded", Queue: "scan", Kind: "scan", Attempt: 5, MaxAttempts: 5,
		ScheduledAt: now, FinalizedAt: &finalized,
		Errors: []string{
			`{"at":"2026-09-10T08:00:00Z","attempt":4,"error":"engine timeout"}`,
			`{"at":"2026-09-10T08:05:00Z","attempt":5,"error":"engine timeout"}`,
		},
	})
	retryingID := insertRiverJob(ctx, t, riverJob{
		State: "retryable", Queue: "fetch", Kind: "fetch", Attempt: 2, MaxAttempts: 5,
		ScheduledAt: now.Add(30 * time.Minute),
		Errors:      []string{`{"at":"2026-09-10T09:00:00Z","attempt":2,"error":"connection reset"}`},
	})

	report, err := Runtime(ctx, benchQueue, now)
	require.NoError(t, err)

	var discardedRow, retryingRow *contract.RuntimeJob
	for i := range report.Errors.Discarded {
		if report.Errors.Discarded[i].ID == discardedID {
			discardedRow = &report.Errors.Discarded[i]
		}
	}
	for i := range report.Errors.Retrying {
		if report.Errors.Retrying[i].ID == retryingID {
			retryingRow = &report.Errors.Retrying[i]
		}
	}
	require.NotNil(t, discardedRow, "the discarded job did not appear in Errors.Discarded")
	require.NotNil(t, retryingRow, "the retrying job did not appear in Errors.Retrying")

	for _, row := range report.Errors.Retrying {
		require.NotEqual(t, discardedID, row.ID, "a discarded job appeared in the retrying list")
	}
	for _, row := range report.Errors.Discarded {
		require.NotEqual(t, retryingID, row.ID, "a retrying job appeared in the discarded list")
	}

	require.Len(t, discardedRow.Errors, 2)
	require.Equal(t, "engine timeout", discardedRow.Errors[0].Error)
	require.Equal(t, 4, discardedRow.Errors[0].Attempt)
	require.Equal(t, "engine timeout", discardedRow.Errors[1].Error)
	require.NotNil(t, discardedRow.FinalizedAt)

	require.Len(t, retryingRow.Errors, 1)
	require.Equal(t, "connection reset", retryingRow.Errors[0].Error)
	require.Nil(t, retryingRow.FinalizedAt, "a job still retrying has not been finalized")
}

func TestRuntimeHistoryBucketsByTheMostRecentAttemptHourly(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)

	threeHoursAgo := now.Add(-3 * time.Hour)
	insertRiverJob(ctx, t, riverJob{
		State: "completed", Queue: "fetch", Kind: "fetch", Attempt: 1, MaxAttempts: 5,
		ScheduledAt: threeHoursAgo, FinalizedAt: &threeHoursAgo, AttemptedAt: &threeHoursAgo,
	})
	insertRiverJob(ctx, t, riverJob{
		State: "completed", Queue: "scan", Kind: "scan", Attempt: 1, MaxAttempts: 5,
		ScheduledAt: threeHoursAgo, FinalizedAt: &threeHoursAgo, AttemptedAt: &threeHoursAgo,
	})
	insertRiverJob(ctx, t, riverJob{
		State: "available", Queue: "fetch", Kind: "fetch", MaxAttempts: 5, ScheduledAt: now,
	})

	report, err := Runtime(ctx, benchQueue, now)
	require.NoError(t, err)
	require.Len(t, report.RunHistory, 24, "the window is 24 hourly buckets, always")

	var found, totalFetch, totalScan int64
	targetHour := threeHoursAgo.Truncate(time.Hour)
	for _, bucket := range report.RunHistory {
		if bucket.StartsAt.Equal(targetHour) {
			found++
			require.EqualValues(t, 1, bucket.Fetch)
			require.EqualValues(t, 1, bucket.Scan)
		}
		totalFetch += bucket.Fetch
		totalScan += bucket.Scan
	}
	require.EqualValues(t, 1, found, "the target hour must appear exactly once")
	// The never-attempted job contributes to neither total.
	require.EqualValues(t, 1, totalFetch)
	require.EqualValues(t, 1, totalScan)
}

// A job attempted after `now` was read must be left out, not fail the report.
func TestRuntimeToleratesAJobAttemptedAfterTheWindowsLastBucket(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	nextHour := now.Add(90 * time.Minute)

	insertRiverJob(ctx, t, riverJob{
		State: "running", Queue: "fetch", Kind: "fetch", Attempt: 1, MaxAttempts: 5,
		ScheduledAt: now, AttemptedAt: &nextHour,
	})

	report, err := Runtime(ctx, benchQueue, now)
	require.NoError(t, err, "a job attempted past the last bucket must be left out, not fatal")
	require.Len(t, report.RunHistory, 24)

	var total int64
	for _, bucket := range report.RunHistory {
		total += bucket.Fetch
	}
	require.Zero(t, total, "the job is outside the window, so no bucket may claim it")
}
