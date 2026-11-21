package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/riverqueue/rivercontrib/otelriver"
)

// The queue database is River's alone: nothing here may ever be pointed at
// AGENT_MANAGER_DATABASE_URL.

// MigrateQueue idempotently applies River's migrations in process and returns
// the versions applied. Deployments use River's CLI instead; this path is for tests.
func MigrateQueue(ctx context.Context, queueURL string, log *slog.Logger) ([]int, error) {
	if queueURL == "" {
		return nil, errors.New("queue database url is empty")
	}

	pool, err := pgxpool.New(ctx, queueURL)
	if err != nil {
		return nil, fmt.Errorf("open queue pool: %w", err)
	}
	defer pool.Close()

	if pingErr := pool.Ping(ctx); pingErr != nil {
		return nil, fmt.Errorf("ping queue database: %w", pingErr)
	}

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Logger: log})
	if err != nil {
		return nil, fmt.Errorf("build the river migrator: %w", err)
	}

	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return nil, fmt.Errorf("migrate the queue database: %w", err)
	}

	applied := make([]int, 0, len(res.Versions))
	for _, v := range res.Versions {
		applied = append(applied, v.Version)
	}
	return applied, nil
}

// NewInsertClient builds the insert-only River client the relay drains into;
// it declares no queues or workers, so it never works a job.
func NewInsertClient(pool *pgxpool.Pool, log *slog.Logger) (*river.Client[pgx.Tx], error) {
	if pool == nil {
		return nil, errors.New("queue pool is nil")
	}

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger:     log,
		Middleware: []rivertype.Middleware{TraceMiddleware()},
	})
	if err != nil {
		return nil, fmt.Errorf("build the insert-only river client: %w", err)
	}
	return client, nil
}

// RiverInserter adapts a River client to the narrow seam the relay holds.
func RiverInserter(client *river.Client[pgx.Tx]) Inserter { return riverInserter{client: client} }

type riverInserter struct {
	client *river.Client[pgx.Tx]
}

func (i riverInserter) InsertJob(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) error {
	if _, err := i.client.Insert(ctx, args, opts); err != nil {
		return fmt.Errorf("insert %s into the queue: %w", args.Kind(), err)
	}
	return nil
}

// TraceMiddleware propagates the inserting span's context through job metadata
// and opens a per-job span linked (not parented) to it, since jobs may run long after the request.
func TraceMiddleware() rivertype.Middleware {
	return otelriver.NewMiddleware(&otelriver.MiddlewareConfig{
		EnableTracePropagation:      true,
		EnableWorkSpanJobKindSuffix: true,
	})
}
