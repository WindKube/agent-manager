package contract

import "time"

// QueueJobCounts is one queue's jobs by River's own state. The names are
// River's vocabulary, not this hub's: available, scheduled and running are
// all "not failed", and collapsing them would hide whether a queue is
// working through a backlog or stalled entirely.
type QueueJobCounts struct {
	Available int64 `json:"available" example:"4"`
	Scheduled int64 `json:"scheduled" example:"0"`
	Running   int64 `json:"running" example:"2"`
	Retryable int64 `json:"retryable" example:"1"`
	Completed int64 `json:"completed" example:"918"`
	Discarded int64 `json:"discarded" example:"3"`
	Cancelled int64 `json:"cancelled" example:"0"`
	// Other is a job in a state this vocabulary does not name — River's
	// `pending`, which this hub never assigns today, or a state a future
	// River adds. Counted rather than dropped, so an unforeseen state is
	// still visible on the total.
	Other int64 `json:"other" example:"0"`
}

// QueueSummary is one River queue: one per worker role.
type QueueSummary struct {
	Queue  string         `json:"queue" enum:"fetch,scan"`
	Counts QueueJobCounts `json:"counts"`
}

// JobAttemptError is one attempt River recorded on a job row, oldest first.
type JobAttemptError struct {
	At      time.Time `json:"at"`
	Attempt int       `json:"attempt" example:"2"`
	Error   string    `json:"error" doc:"The stringified error, or panic value, River recorded for this attempt."`
}

// RuntimeJob is one job carrying at least one recorded error.
type RuntimeJob struct {
	ID          int64  `json:"id" example:"48213"`
	Queue       string `json:"queue" enum:"fetch,scan"`
	Kind        string `json:"kind" example:"fetch"`
	Attempt     int    `json:"attempt" example:"3"`
	MaxAttempts int    `json:"maxAttempts" example:"5"`
	// ScheduledAt is River's own column: the next attempt for a job still
	// retrying, frozen at its last computed value for a discarded one.
	ScheduledAt time.Time `json:"scheduledAt"`
	// FinalizedAt is when a discarded job stopped retrying. Absent for a
	// job still retrying.
	FinalizedAt *time.Time `json:"finalizedAt,omitempty"`
	// Errors is every attempt error River recorded on this row, oldest first.
	Errors []JobAttemptError `json:"errors"`
}

// RuntimeErrors separates the one case that needs a person from the one
// that does not: retries exhausted versus still retrying on its own. A
// discarded job mixed into the same list as one still retrying is the
// exact ambiguity this screen exists to remove.
type RuntimeErrors struct {
	// Discarded is retries exhausted: River will not run these again
	// without manual intervention.
	Discarded []RuntimeJob `json:"discarded"`
	// Retrying failed at least once and is still scheduled to run again.
	Retrying []RuntimeJob `json:"retrying"`
}

// RunBucket is one interval of the run-history chart.
type RunBucket struct {
	StartsAt time.Time `json:"startsAt"`
	Fetch    int64     `json:"fetch"`
	Scan     int64     `json:"scan"`
}

// RuntimeReport answers GET /v1/runtime.
type RuntimeReport struct {
	Queues []QueueSummary `json:"queues" doc:"Job counts by River's own state, one entry per queue."`
	Errors RuntimeErrors  `json:"errors"`
	// RunHistory buckets jobs by their most recent attempt time, oldest
	// bucket first. A job counts once, in the bucket of its LAST attempt —
	// a job retried three times appears once, not three times, and a job
	// River's own retention already reaped does not appear at all.
	RunHistory []RunBucket `json:"runHistory"`
	// BucketMinutes is the width of one RunHistory interval, in minutes —
	// what makes the chart's axis readable rather than a row of unlabelled bars.
	BucketMinutes int `json:"bucketMinutes" example:"60"`
}
