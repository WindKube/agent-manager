package outbox

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"

	"agent-manager/internal/metrics"
)

// QueueSampleInterval is how often a worker counts its own queues' jobs.
const QueueSampleInterval = 15 * time.Second

// sampledStates are the states worth a gauge. completed is left out: River
// prunes it on its own schedule, so its count says nothing about health.
var sampledStates = []rivertype.JobState{
	rivertype.JobStateAvailable,
	rivertype.JobStateScheduled,
	rivertype.JobStateRetryable,
	rivertype.JobStateRunning,
	rivertype.JobStateDiscarded,
}

// SampleQueues sets the depth gauges for this role's own queues, so each
// queue is reported by the role that drains it rather than by every process
// holding the queue pool.
func SampleQueues(pool *pgxpool.Pool, queues []string, log zerolog.Logger) func(context.Context) {
	states := make([]string, len(sampledStates))
	for i, s := range sampledStates {
		states[i] = string(s)
	}

	return func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		rows, err := pool.Query(ctx, `select queue, state::text, count(*)
			from river_job
			where queue = any($1) and state = any($2::river_job_state[])
			group by queue, state`, queues, states)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn().Err(err).Msg("sample queue depth")
			}
			return
		}
		defer rows.Close()

		counts := make(map[[2]string]float64)
		for rows.Next() {
			var queue, state string
			var n int64
			if err := rows.Scan(&queue, &state, &n); err != nil {
				log.Warn().Err(err).Msg("sample queue depth")
				return
			}
			counts[[2]string{queue, state}] = float64(n)
		}
		if rows.Err() != nil {
			log.Warn().Err(rows.Err()).Msg("sample queue depth")
			return
		}

		for _, queue := range queues {
			for _, state := range states {
				metrics.QueueJobs.WithLabelValues(queue, state).Set(counts[[2]string{queue, state}])
			}
		}
	}
}
