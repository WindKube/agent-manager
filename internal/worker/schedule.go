package worker

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
)

// inserter is the slice of a River client the scheduler needs.
type inserter interface {
	Insert(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// schedule inserts each periodic job every Interval until ctx ends. Unique by
// period, so replicas of one role insert it once per interval between them.
func schedule(ctx context.Context, client inserter, jobs []PeriodicJob, log zerolog.Logger) {
	for _, job := range jobs {
		go func() {
			insert := func() {
				opts := &river.InsertOpts{UniqueOpts: river.UniqueOpts{ByPeriod: job.Interval}}
				if _, err := client.Insert(ctx, job.Args, opts); err != nil && ctx.Err() == nil {
					log.Error().Err(err).Str("kind", job.Args.Kind()).Msg("schedule a periodic job")
				}
			}
			if job.RunOnStart {
				insert()
			}
			ticker := time.NewTicker(job.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					insert()
				}
			}
		}()
	}
}

var _ inserter = (*river.Client[pgx.Tx])(nil)
