package hub

import (
	"context"
	"fmt"
	"time"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// Runtime reads GET /v1/runtime and returns view.Runtime directly: there is
// exactly one caller, so no separate hub-owned type is worth the indirection.
func (c *Client) Runtime(ctx context.Context) (view.Runtime, error) {
	resp, err := c.api.GetRuntimeWithResponse(ctx)
	if err != nil {
		return view.Runtime{}, fmt.Errorf("read the runtime report: %w", err)
	}
	if resp.JSON200 == nil {
		return view.Runtime{}, fmt.Errorf("read the runtime report: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := view.Runtime{
		Queues:        make([]view.QueueCounts, 0, len(body.Queues)),
		Discarded:     make([]view.JobRow, 0, len(body.Errors.Discarded)),
		Retrying:      make([]view.JobRow, 0, len(body.Errors.Retrying)),
		History:       make([]view.RunBucket, 0, len(body.RunHistory)),
		BucketMinutes: int(body.BucketMinutes),
	}
	for _, q := range body.Queues {
		out.Queues = append(out.Queues, queueCounts(q))
	}
	for _, job := range body.Errors.Discarded {
		out.Discarded = append(out.Discarded, jobRow(job, view.Timestamp(derefTime(job.FinalizedAt))))
	}
	for _, job := range body.Errors.Retrying {
		out.Retrying = append(out.Retrying, jobRow(job, view.Timestamp(job.ScheduledAt)))
	}
	for _, bucket := range body.RunHistory {
		out.History = append(out.History, view.RunBucket{
			StartsAt: bucket.StartsAt, Fetch: bucket.Fetch, Scan: bucket.Scan,
		})
	}
	return out, nil
}

func queueCounts(from apiclient.QueueSummary) view.QueueCounts {
	c := from.Counts
	return view.QueueCounts{
		Queue: string(from.Queue), Available: c.Available, Scheduled: c.Scheduled,
		Running: c.Running, Retryable: c.Retryable, Completed: c.Completed,
		Discarded: c.Discarded, Cancelled: c.Cancelled, Other: c.Other,
	}
}

// derefTime is the zero value for a nil pointer, which view.Timestamp
// already renders as "" rather than as the Unix epoch.
func derefTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func jobRow(from apiclient.RuntimeJob, when string) view.JobRow {
	row := view.JobRow{
		ID: from.Id, Queue: string(from.Queue), Kind: from.Kind,
		Attempt: int(from.Attempt), MaxAttempts: int(from.MaxAttempts), When: when,
		Errors: make([]view.ErrorEntry, 0, len(from.Errors)),
	}
	for _, e := range from.Errors {
		row.Errors = append(row.Errors, view.ErrorEntry{
			At: view.Timestamp(e.At), Attempt: int(e.Attempt), Error: e.Error,
		})
	}
	return row
}
