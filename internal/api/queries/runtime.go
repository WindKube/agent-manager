package queries

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/outbox"
)

// RuntimeQueue is the read the runtime report needs against River's own
// database, satisfied by *pgxpool.Pool. It is raw SQL, never bun, because the
// application schema must not reference the queue database.
type RuntimeQueue interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// runtimeQueues always get a row, zeroed when empty.
var runtimeQueues = []string{outbox.QueueFetch, outbox.QueueScan}

const (
	// runtimeErrorLimit bounds the discarded and retrying lists.
	runtimeErrorLimit = 25
	// runtimeBuckets and runtimeBucketWidth are the run-history window: the
	// last day, hourly.
	runtimeBuckets     = 24
	runtimeBucketWidth = time.Hour
)

// Runtime answers GET /v1/runtime: job counts per queue and state, discarded
// and retrying jobs with their errors, and an hourly run history.
func Runtime(ctx context.Context, queue RuntimeQueue, now time.Time) (contract.RuntimeReport, error) {
	counts, err := runtimeCounts(ctx, queue)
	if err != nil {
		return contract.RuntimeReport{}, err
	}

	report := contract.RuntimeReport{
		BucketMinutes: int(runtimeBucketWidth / time.Minute),
		Queues:        queueSummaries(counts),
	}

	discarded, err := runtimeJobs(ctx, queue, "discarded", runtimeErrorLimit)
	if err != nil {
		return contract.RuntimeReport{}, err
	}
	retrying, err := runtimeJobs(ctx, queue, "retryable", runtimeErrorLimit)
	if err != nil {
		return contract.RuntimeReport{}, err
	}
	report.Errors = contract.RuntimeErrors{Discarded: discarded, Retrying: retrying}

	history, err := runtimeHistory(ctx, queue, now.UTC())
	if err != nil {
		return contract.RuntimeReport{}, err
	}
	report.RunHistory = history

	return report, nil
}

const runtimeCountsSelect = `
select queue, state::text, count(*)
from river_job
group by queue, state`

// runtimeCounts reads every (queue, state) pair, unfiltered, so a job on an
// unknown queue is still reported.
func runtimeCounts(ctx context.Context, queue RuntimeQueue) (map[string]contract.QueueJobCounts, error) {
	rows, err := queue.Query(ctx, runtimeCountsSelect)
	if err != nil {
		return nil, fmt.Errorf("read job counts by state: %w", err)
	}
	defer rows.Close()

	out := map[string]contract.QueueJobCounts{}
	for rows.Next() {
		var q, state string
		var n int64
		if scanErr := rows.Scan(&q, &state, &n); scanErr != nil {
			return nil, fmt.Errorf("scan a job-count row: %w", scanErr)
		}
		counts := out[q]
		addState(&counts, state, n)
		out[q] = counts
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("read job counts by state: %w", rows.Err())
	}
	return out, nil
}

// queueSummaries reports the registered queues even at zero, then any other
// queue the table holds, sorted.
func queueSummaries(counts map[string]contract.QueueJobCounts) []contract.QueueSummary {
	known := make(map[string]bool, len(runtimeQueues))
	out := make([]contract.QueueSummary, 0, len(counts))
	for _, q := range runtimeQueues {
		known[q] = true
		out = append(out, contract.QueueSummary{Queue: q, Counts: counts[q]})
	}

	var extra []string
	for q := range counts {
		if !known[q] {
			extra = append(extra, q)
		}
	}
	sort.Strings(extra)
	for _, q := range extra {
		out = append(out, contract.QueueSummary{Queue: q, Counts: counts[q]})
	}
	return out
}

// addState folds one state's count onto its field; unknown states go to Other.
func addState(c *contract.QueueJobCounts, state string, n int64) {
	switch state {
	case "available":
		c.Available += n
	case "scheduled":
		c.Scheduled += n
	case "running":
		c.Running += n
	case "retryable":
		c.Retryable += n
	case "completed":
		c.Completed += n
	case "discarded":
		c.Discarded += n
	case "cancelled":
		c.Cancelled += n
	default:
		c.Other += n
	}
}

const runtimeJobsSelect = `
select id, queue, kind, attempt, max_attempts, scheduled_at, finalized_at, errors
from river_job
where state = $1
order by coalesce(finalized_at, scheduled_at) desc, id desc
limit $2`

// runtimeJobs reads the most recent jobs in one state, newest first, with
// every attempt error River recorded on the row.
func runtimeJobs(ctx context.Context, queue RuntimeQueue, state string, limit int) ([]contract.RuntimeJob, error) {
	rows, err := queue.Query(ctx, runtimeJobsSelect, state, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s jobs: %w", state, err)
	}
	defer rows.Close()

	out := []contract.RuntimeJob{}
	for rows.Next() {
		var job contract.RuntimeJob
		var finalizedAt *time.Time
		var rawErrors []json.RawMessage
		if scanErr := rows.Scan(&job.ID, &job.Queue, &job.Kind, &job.Attempt, &job.MaxAttempts,
			&job.ScheduledAt, &finalizedAt, &rawErrors); scanErr != nil {
			return nil, fmt.Errorf("scan a %s job: %w", state, scanErr)
		}
		job.ScheduledAt = job.ScheduledAt.UTC()
		if finalizedAt != nil {
			utc := finalizedAt.UTC()
			job.FinalizedAt = &utc
		}
		job.Errors = attemptErrors(rawErrors)
		out = append(out, job)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("read %s jobs: %w", state, rows.Err())
	}
	return out, nil
}

// attemptErrors decodes River's error shape, keeping undecodable entries as
// raw text so a River format change never hides a job.
func attemptErrors(raw []json.RawMessage) []contract.JobAttemptError {
	out := make([]contract.JobAttemptError, 0, len(raw))
	for _, entry := range raw {
		var decoded struct {
			At      time.Time `json:"at"`
			Attempt int       `json:"attempt"`
			Error   string    `json:"error"`
		}
		if err := json.Unmarshal(entry, &decoded); err != nil {
			out = append(out, contract.JobAttemptError{Error: string(entry)})
			continue
		}
		out = append(out, contract.JobAttemptError{
			At: decoded.At.UTC(), Attempt: decoded.Attempt, Error: decoded.Error,
		})
	}
	return out
}

const runtimeHistorySelect = `
select queue, date_trunc('hour', attempted_at) as bucket, count(*)
from river_job
where attempted_at >= $1 and attempted_at < $2
group by queue, bucket`

// runtimeHistory buckets jobs by latest attempt time over the last
// runtimeBuckets hours, oldest first, including empty buckets.
func runtimeHistory(ctx context.Context, queue RuntimeQueue, now time.Time) ([]contract.RunBucket, error) {
	latest := now.Truncate(runtimeBucketWidth)
	earliest := latest.Add(-(runtimeBuckets - 1) * runtimeBucketWidth)

	buckets := make([]contract.RunBucket, runtimeBuckets)
	index := map[time.Time]int{}
	for i := range buckets {
		start := earliest.Add(time.Duration(i) * runtimeBucketWidth)
		buckets[i] = contract.RunBucket{StartsAt: start}
		index[start] = i
	}

	// The upper bound keeps a job attempted after `now` out of an unopened bucket.
	rows, err := queue.Query(ctx, runtimeHistorySelect, earliest, latest.Add(runtimeBucketWidth))
	if err != nil {
		return nil, fmt.Errorf("read run history: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var q string
		var bucket time.Time
		var n int64
		if scanErr := rows.Scan(&q, &bucket, &n); scanErr != nil {
			return nil, fmt.Errorf("scan a run-history row: %w", scanErr)
		}
		i, ok := index[bucket.UTC()]
		if !ok {
			// Both bounds are in the SQL, so this is a clock mismatch worth surfacing.
			return nil, fmt.Errorf("run history: bucket %s at queue %s is outside the requested window", bucket, q)
		}
		switch q {
		case outbox.QueueFetch:
			buckets[i].Fetch += n
		case outbox.QueueScan:
			buckets[i].Scan += n
		}
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("read run history: %w", rows.Err())
	}
	return buckets, nil
}
