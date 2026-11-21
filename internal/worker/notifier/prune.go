package notifier

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/uptrace/bun"

	"agent-manager/internal/outbox"
)

const pruneInterval = time.Hour

// Prune is the periodic job that trims the delivery log.
type Prune struct{}

func (Prune) Kind() string { return "webhook-prune" }

func (Prune) InsertOpts() river.InsertOpts { return river.InsertOpts{Queue: outbox.QueueNotify} }

// Pruner works the `webhook-prune` job.
type Pruner struct {
	river.WorkerDefaults[Prune]

	db        bun.IDB
	retention time.Duration
}

func (p *Pruner) Work(ctx context.Context, _ *river.Job[Prune]) error {
	if _, err := PruneDeliveries(ctx, p.db, p.retention); err != nil {
		return err
	}
	// Twice the lookback, so a mark always outlives the window that reads it.
	if _, err := p.db.ExecContext(ctx, `delete from webhook_dispatch where dispatched_at < now() - make_interval(secs => ?)`,
		(2 * Lookback).Seconds()); err != nil {
		return fmt.Errorf("prune webhook dispatch marks: %w", err)
	}
	return nil
}

// PruneDeliveries deletes delivery attempts older than retention.
func PruneDeliveries(ctx context.Context, db bun.IDB, retention time.Duration) (int64, error) {
	res, err := db.ExecContext(ctx,
		`delete from webhook_delivery where occurred_at < now() - make_interval(secs => ?)`, retention.Seconds())
	if err != nil {
		return 0, fmt.Errorf("prune webhook deliveries: %w", err)
	}
	return res.RowsAffected()
}
