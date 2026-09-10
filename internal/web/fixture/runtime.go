package fixture

import (
	"context"
	"time"

	"agent-manager/internal/web/view"
)

// Runtime implements web.RuntimeSource for the screen tests: a fetch queue
// working through a small backlog, a scan queue with one job discarded and
// one retrying, and 24 hours of run history with a gap in the middle —
// which is what a quiet stretch on a real hub looks like.
func (c *Catalog) Runtime(context.Context) (view.Runtime, error) {
	now := fixtureNow()

	history := make([]view.RunBucket, 24)
	for i := range history {
		start := now.Truncate(time.Hour).Add(time.Duration(i-23) * time.Hour)
		fetch, scan := int64(4), int64(1)
		if i > 8 && i < 14 {
			// The quiet stretch: nothing ran.
			fetch, scan = 0, 0
		}
		if i == 23 {
			fetch, scan = 6, 3
		}
		history[i] = view.RunBucket{StartsAt: start, Fetch: fetch, Scan: scan}
	}

	return view.Runtime{
		Queues: []view.QueueCounts{
			{Queue: "fetch", Available: 2, Running: 1, Completed: 4180, Retryable: 1},
			{Queue: "scan", Available: 0, Running: 1, Completed: 4102, Discarded: 1, Cancelled: 3},
		},
		Discarded: []view.JobRow{
			{
				ID: 48213, Queue: "scan", Kind: "scan", Attempt: 5, MaxAttempts: 5,
				When: view.Timestamp(now.Add(-3 * time.Hour)),
				Errors: []view.ErrorEntry{
					{At: view.Timestamp(now.Add(-4 * time.Hour)), Attempt: 4,
						Error: "rule pack load failed: signature mismatch for pack 2026.09.10"},
					{At: view.Timestamp(now.Add(-3 * time.Hour)), Attempt: 5,
						Error: "rule pack load failed: signature mismatch for pack 2026.09.10"},
				},
			},
		},
		Retrying: []view.JobRow{
			{
				ID: 48310, Queue: "fetch", Kind: "fetch", Attempt: 2, MaxAttempts: 5,
				When: view.Timestamp(now.Add(15 * time.Minute)),
				Errors: []view.ErrorEntry{
					{At: view.Timestamp(now.Add(-10 * time.Minute)), Attempt: 2,
						Error: "unreachable: dial tcp: connection reset while downloading the archive"},
				},
			},
		},
		History:       history,
		BucketMinutes: 60,
	}, nil
}
