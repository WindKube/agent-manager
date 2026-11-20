package notifier

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/notify"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/models"
)

// Lookback is how far back the dispatcher looks for audit rows it has not
// fanned out yet. It bounds both how long a transaction may stay open before
// its audit row commits and how long the notifier may be down without losing
// events; webhook_dispatch rows are kept for twice as long.
const Lookback = 24 * time.Hour

const dispatchBatch = 500

// Dispatch is the periodic job that fans new audit rows out to subscriptions.
type Dispatch struct{}

func (Dispatch) Kind() string { return "webhook-dispatch" }

func (Dispatch) InsertOpts() river.InsertOpts { return river.InsertOpts{Queue: outbox.QueueNotify} }

// Dispatcher works the `webhook-dispatch` job.
type Dispatcher struct {
	river.WorkerDefaults[Dispatch]

	db      bun.IDB
	enqueue outbox.Enqueuer
}

func (d *Dispatcher) Work(ctx context.Context, _ *river.Job[Dispatch]) error {
	_, err := DispatchEvents(ctx, d.db, d.enqueue)
	return err
}

type subscriptionFilter struct {
	ID         uuid.UUID `bun:"id"`
	EventTypes []string  `bun:"event_types,array"`
	Namespaces []string  `bun:"namespaces,array"`
	CreatedAt  time.Time `bun:"created_at"`
}

type pendingEvent struct {
	ID          uuid.UUID `bun:"id"`
	OccurredAt  time.Time `bun:"occurred_at"`
	Kind        string    `bun:"kind"`
	Action      string    `bun:"action"`
	SubjectKind string    `bun:"subject_kind"`
	Namespace   string    `bun:"namespace"`
}

// DispatchEvents enqueues one notify job per (subscription, event) for every
// audit row not yet dispatched, and returns how many it enqueued.
//
// Exactly once: an audit row is claimed by inserting its webhook_dispatch
// row, and its jobs are written to the outbox in the same transaction. A
// concurrent dispatcher's insert of the same key waits for this one to
// commit and then claims nothing, and a rollback releases the claim and the
// jobs together. Scanning a time window rather than following an id cursor
// is what catches a row whose transaction commits after a later one's.
func DispatchEvents(ctx context.Context, db bun.IDB, enqueue outbox.Enqueuer) (int, error) {
	total := 0
	for {
		claimed, enqueued, err := dispatchBatchOnce(ctx, db, enqueue)
		if err != nil {
			return total, err
		}
		total += enqueued
		if claimed < dispatchBatch {
			return total, nil
		}
	}
}

func dispatchBatchOnce(ctx context.Context, db bun.IDB, enqueue outbox.Enqueuer) (claimed, enqueued int, err error) {
	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var events []pendingEvent
		if claimErr := tx.NewRaw(`with claimed as (
				insert into webhook_dispatch (audit_event_id)
				select aud.id from audit_event as aud
				where aud.occurred_at > now() - make_interval(secs => ?)
				  and aud.kind::text = any(?)
				  and not exists (select 1 from webhook_dispatch as d where d.audit_event_id = aud.id)
				order by aud.occurred_at, aud.id
				limit ?
				on conflict do nothing
				returning audit_event_id)
			select aud.id, aud.occurred_at, aud.kind::text as kind, coalesce(aud.data ->> 'action', '') as action,
			       coalesce(aud.subject_kind::text, '') as subject_kind, coalesce(aud.namespace, '') as namespace
			from audit_event as aud join claimed on claimed.audit_event_id = aud.id
			order by aud.occurred_at, aud.id`,
			Lookback.Seconds(), pgdialect.Array(notify.AuditKinds()), dispatchBatch).Scan(ctx, &events); claimErr != nil {
			return fmt.Errorf("claim audit rows for webhooks: %w", claimErr)
		}
		claimed = len(events)
		if claimed == 0 {
			return nil
		}

		var subs []subscriptionFilter
		if subErr := tx.NewSelect().Model((*models.WebhookSubscription)(nil)).
			Column("id", "event_types", "namespaces", "created_at").
			Where("enabled").Scan(ctx, &subs); subErr != nil {
			return fmt.Errorf("read webhook subscriptions: %w", subErr)
		}

		var jobs []outbox.Job
		for _, ev := range events {
			t, ok := notify.FromAudit(ev.Kind, ev.Action, ev.SubjectKind)
			if !ok {
				continue
			}
			for _, sub := range subs {
				if sub.CreatedAt.After(ev.OccurredAt) || !notify.Matches(sub.EventTypes, sub.Namespaces, t, ev.Namespace) {
					continue
				}
				jobs = append(jobs, NewDeliveryJob(sub.ID, ev.ID))
			}
		}
		if _, enqErr := enqueue.Enqueue(ctx, tx, jobs...); enqErr != nil {
			return enqErr
		}
		enqueued = len(jobs)
		return nil
	})
	return claimed, enqueued, err
}
