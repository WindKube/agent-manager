package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"
)

// DefaultSweepInterval is the periodic drain. LISTEN/NOTIFY carries the latency,
// but a notification is fire-and-forget: it is lost if the listener connection is
// down at that instant, and Postgres never redelivers it. The sweep is what turns
// a lost notification into a few seconds of delay instead of a job that never
// runs, so it is not an optimisation to be tuned away (R5).
const DefaultSweepInterval = 10 * time.Second

const (
	// DefaultPruneInterval is how often delivered rows are swept out. It is far
	// shorter than the retention window on purpose: the prune is cheap and a missed
	// run must not let the table grow.
	DefaultPruneInterval = time.Hour

	// DefaultRetention is data-model.md's "delivered rows pruned after 24 h".
	DefaultRetention = 24 * time.Hour

	// DefaultBatch is how many rows one claim takes. The claim holds row locks
	// across the River insert, so the batch stays small enough that a slow queue
	// cannot block a mutation for long.
	DefaultBatch = 50

	listenerRetryDelay = time.Second
)

// Inserter is all the relay needs from River: hand one job over, or fail.
//
// It is deliberately narrower than *river.Client and lets no River result type
// cross the seam, so the relay is testable without a queue database and cannot
// reach for the rest of the client's surface. RiverInserter adapts the real
// client.
type Inserter interface {
	InsertJob(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) error
}

// RelayConfig configures the relay. It is hosted in the api role (R5), next to
// the transactions that feed it.
type RelayConfig struct {
	// AppDatabaseURL is the application database. The relay opens ONE dedicated
	// connection to it for LISTEN: a pooled connection cannot hold a subscription,
	// because the pool would hand it to somebody else's query. Empty disables the
	// listener and leaves the sweep as the only delivery path — degraded, not
	// broken, which is the property the sweep exists to provide.
	AppDatabaseURL string

	Batch         int
	SweepInterval time.Duration
	PruneInterval time.Duration
	Retention     time.Duration
}

func (c RelayConfig) withDefaults() RelayConfig {
	if c.Batch <= 0 {
		c.Batch = DefaultBatch
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = DefaultSweepInterval
	}
	if c.PruneInterval <= 0 {
		c.PruneInterval = DefaultPruneInterval
	}
	if c.Retention <= 0 {
		c.Retention = DefaultRetention
	}
	return c
}

// RelayStats is what the relay did. Notifications and Sweeps are separate so a
// test can prove which of the two delivered a row.
type RelayStats struct {
	Notifications int64
	Sweeps        int64
	Delivered     int64
	Pruned        int64
	ListenerDrops int64
}

// Relay moves committed outbox rows into River.
type Relay struct {
	db    bun.IDB
	queue Inserter
	cfg   RelayConfig
	log   zerolog.Logger

	notifications atomic.Int64
	sweeps        atomic.Int64
	delivered     atomic.Int64
	pruned        atomic.Int64
	listenerDrops atomic.Int64
}

func NewRelay(db bun.IDB, queue Inserter, cfg RelayConfig, log zerolog.Logger) (*Relay, error) {
	if db == nil {
		return nil, errors.New("relay: application database handle is nil")
	}
	if queue == nil {
		return nil, errors.New("relay: queue inserter is nil")
	}
	return &Relay{db: db, queue: queue, cfg: cfg.withDefaults(), log: log}, nil
}

func (r *Relay) Stats() RelayStats {
	return RelayStats{
		Notifications: r.notifications.Load(),
		Sweeps:        r.sweeps.Load(),
		Delivered:     r.delivered.Load(),
		Pruned:        r.pruned.Load(),
		ListenerDrops: r.listenerDrops.Load(),
	}
}

// Run drains the outbox until ctx is cancelled.
//
// Two independent triggers, and that redundancy is the point: LISTEN for latency,
// a periodic sweep so a notification lost to a dropped connection costs seconds
// rather than forever.
func (r *Relay) Run(ctx context.Context) error {
	wake := make(chan struct{}, 1)
	if r.cfg.AppDatabaseURL != "" {
		go r.listen(ctx, wake)
	} else {
		r.log.Warn().Msg("outbox relay has no listen connection; delivery is on the sweep only")
	}

	sweep := time.NewTicker(r.cfg.SweepInterval)
	defer sweep.Stop()
	prune := time.NewTicker(r.cfg.PruneInterval)
	defer prune.Stop()

	// A restart must not wait for the first tick: rows committed while the process
	// was down are already pending and their notifications are long gone.
	r.drainLogged(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			r.drainLogged(ctx)
		case <-sweep.C:
			r.sweeps.Add(1)
			r.drainLogged(ctx)
		case <-prune.C:
			if _, err := r.Prune(ctx); err != nil && ctx.Err() == nil {
				r.log.Error().Err(err).Msg("outbox prune failed")
			}
		}
	}
}

func (r *Relay) drainLogged(ctx context.Context) {
	if err := r.Drain(ctx); err != nil && ctx.Err() == nil {
		r.log.Error().Err(err).Msg("outbox drain failed")
	}
}

// Drain delivers every pending row, one claimed batch at a time.
func (r *Relay) Drain(ctx context.Context) error {
	for {
		n, err := r.deliverBatch(ctx)
		if err != nil {
			return err
		}
		if n < r.cfg.Batch {
			return nil
		}
	}
}

type pendingRow struct {
	id      uuid.UUID
	kind    string
	payload json.RawMessage
}

// deliverBatch claims a batch, inserts it into River and marks it delivered, all
// in one transaction.
//
// The claim uses `for update skip locked` so several api replicas can drain
// concurrently without one waiting on another's locks. The River inserts happen
// inside that transaction — before the mark commits — which is the at-least-once
// trade: a crash here redelivers, and every handler is idempotent (principle IX).
// Marking first would silently drop the job instead, and nothing would ever
// notice.
func (r *Relay) deliverBatch(ctx context.Context) (int, error) {
	var claimed int

	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		rows, err := claim(ctx, tx, r.cfg.Batch)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		claimed = len(rows)

		ids := make([]uuid.UUID, 0, len(rows))
		for _, row := range rows {
			args := queuedJob{kind: row.kind, payload: row.payload}
			opts := &river.InsertOpts{Queue: Queue(Kind(row.kind))}
			if err := r.queue.InsertJob(ctx, args, opts); err != nil {
				return fmt.Errorf("insert %s job %s into the queue: %w", row.kind, row.id, err)
			}
			ids = append(ids, row.id)
		}

		if _, err := tx.NewRaw(
			`update outbox set state = 'delivered', delivered_at = now() where id in (?)`,
			bun.List(ids),
		).Exec(ctx); err != nil {
			return fmt.Errorf("mark outbox rows delivered: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	r.delivered.Add(int64(claimed))
	return claimed, nil
}

func claim(ctx context.Context, tx bun.Tx, batch int) ([]pendingRow, error) {
	// Ordering by the primary key is ordering by time: the id is a uuid v7. The
	// placeholder is bun's `?` — bun formats raw SQL itself rather than binding
	// through the driver.
	sqlRows, err := tx.QueryContext(ctx, `select id, job_kind, payload
		from outbox
		where state = 'pending'
		order by id
		for update skip locked
		limit ?`, batch)
	if err != nil {
		return nil, fmt.Errorf("claim outbox rows: %w", err)
	}
	defer func() { _ = sqlRows.Close() }()

	var out []pendingRow
	for sqlRows.Next() {
		var row pendingRow
		if err := sqlRows.Scan(&row.id, &row.kind, &row.payload); err != nil {
			return nil, fmt.Errorf("scan outbox row: %w", err)
		}
		out = append(out, row)
	}
	if err := sqlRows.Err(); err != nil {
		return nil, fmt.Errorf("read claimed outbox rows: %w", err)
	}
	return out, nil
}

// Prune removes delivered rows past the retention window. `DELETE` on `outbox` is
// the only delete grant am_api holds (data-model.md), so this is the only
// statement in the system that may run it.
func (r *Relay) Prune(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`delete from outbox
		 where state = 'delivered' and delivered_at < now() - make_interval(secs => ?)`,
		r.cfg.Retention.Seconds())
	if err != nil {
		return 0, fmt.Errorf("prune outbox: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune outbox: %w", err)
	}
	if n > 0 {
		r.pruned.Add(n)
	}
	return n, nil
}

// listen holds the LISTEN subscription, reconnecting for as long as ctx lives. A
// drop is logged at warn rather than fatal: the sweep keeps delivering.
func (r *Relay) listen(ctx context.Context, wake chan<- struct{}) {
	for ctx.Err() == nil {
		if err := r.listenOnce(ctx, wake); err != nil && ctx.Err() == nil {
			r.listenerDrops.Add(1)
			r.log.Warn().Err(err).
				Dur("sweep_interval", r.cfg.SweepInterval).
				Msg("outbox listener dropped; the sweep keeps delivery going")

			select {
			case <-ctx.Done():
				return
			case <-time.After(listenerRetryDelay):
			}
		}
	}
}

func (r *Relay) listenOnce(ctx context.Context, wake chan<- struct{}) error {
	conn, err := pgx.Connect(ctx, r.cfg.AppDatabaseURL)
	if err != nil {
		return fmt.Errorf("connect the outbox listener: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	// The channel name is a constant, so this concatenation carries no user input;
	// LISTEN takes no bind parameters.
	if _, err := conn.Exec(ctx, "listen "+NotifyChannel); err != nil {
		return fmt.Errorf("listen %s: %w", NotifyChannel, err)
	}

	// A row may have been committed between the last drain and this subscription,
	// and its notification went nowhere.
	r.signal(wake)

	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			return fmt.Errorf("wait for %s: %w", NotifyChannel, err)
		}
		r.notifications.Add(1)
		r.signal(wake)
	}
}

// signal is non-blocking: the channel has room for one pending wake-up, and a
// second is redundant because a drain empties the table.
func (r *Relay) signal(wake chan<- struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

// queuedJob carries an outbox row into River unchanged.
//
// Kind is the row's job_kind, so the outbox kind and the queue kind are one
// string and a worker registers against a single name. MarshalJSON hands River the
// stored payload verbatim rather than re-encoding a Go value, which is what lets
// the relay stay ignorant of every job type.
type queuedJob struct {
	kind    string
	payload json.RawMessage
}

func (j queuedJob) Kind() string { return j.kind }

func (j queuedJob) MarshalJSON() ([]byte, error) {
	if len(j.payload) == 0 {
		return []byte("{}"), nil
	}
	return j.payload, nil
}
