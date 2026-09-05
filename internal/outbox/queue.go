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
)

// The queue database is River's alone. Atlas describes the application
// schema and River migrates its own with its own tool, so nothing in this
// file may ever be pointed at AGENT_MANAGER_DATABASE_URL.

// MigrateQueue applies River's own migrations to the queue database and returns
// the versions it applied, newest last. It is idempotent: a second run applies
// nothing.
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

// NewInsertClient builds the insert-only River client the relay drains
// into. It declares no queues and no workers, so it can insert but will
// never work a job — the relay hands jobs over, the worker roles run them.
func NewInsertClient(pool *pgxpool.Pool, log *slog.Logger) (*river.Client[pgx.Tx], error) {
	if pool == nil {
		return nil, errors.New("queue pool is nil")
	}

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Logger: log})
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
