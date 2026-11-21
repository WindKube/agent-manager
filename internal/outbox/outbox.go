// Package outbox is the only door to the job queue, which lives in its own
// database. Writer inserts rows in the caller's transaction and Relay moves
// committed rows into River, so a commit publishes its state and jobs or neither.
//
// Delivery is at-least-once: the relay inserts into River before marking the
// row delivered, so a crash duplicates a job rather than losing it; the
// idempotency key therefore lives on the job's target row. Never call
// River directly from a request handler.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/propagation"

	"agent-manager/internal/store/models"
)

// NotifyChannel is the LISTEN channel the relay wakes on. It is raised inside
// the caller's transaction, so it cannot outrun the row it refers to.
const NotifyChannel = "outbox_new"

// Kind is an outbox row's job_kind.
type Kind string

const (
	KindFetch       Kind = "fetch"
	KindScan        Kind = "scan"
	KindRescanSweep Kind = "rescan-sweep"
	KindNotify      Kind = "notify"
)

func (k Kind) Valid() bool {
	switch k {
	case KindFetch, KindScan, KindRescanSweep, KindNotify:
		return true
	default:
		return false
	}
}

// Queue names, one per worker role. No kind may use river.QueueDefault, since
// workers register only their own queue.
const (
	QueueFetch  = "fetch"
	QueueScan   = "scan"
	QueueNotify = "notify"
)

var queueByKind = map[Kind]string{
	KindFetch:       QueueFetch,
	KindScan:        QueueScan,
	KindRescanSweep: QueueScan,
	KindNotify:      QueueNotify,
}

// Queue is the River queue a kind is delivered to.
func Queue(k Kind) string {
	return queueByKind[k]
}

// MaxJobAttempts caps retries; River's default of 25 is just noise for a
// persistently failing fetch or scan.
const MaxJobAttempts = 3

// MaxNotifyAttempts is larger so a receiver down for an afternoon still gets
// the event; backoff spreads it over about 17 hours.
const MaxNotifyAttempts = 10

// MaxAttempts is the retry budget a kind is inserted with.
func MaxAttempts(k Kind) int {
	if k == KindNotify {
		return MaxNotifyAttempts
	}
	return MaxJobAttempts
}

// Job is one queued unit of work as the caller describes it.
type Job struct {
	Kind Kind

	// SubjectID and SubjectVersion complete the idempotency key: the version
	// for a fetch, plus the rule-pack version for a scan.
	SubjectID      uuid.UUID
	SubjectVersion string

	// Payload is marshalled to jsonb; a json.RawMessage passes through unchanged.
	Payload any
}

// IdempotencyKey is job_kind:subject_id:subject_version.
func (j Job) IdempotencyKey() string {
	subject := ""
	if j.SubjectID != uuid.Nil {
		subject = j.SubjectID.String()
	}
	return string(j.Kind) + ":" + subject + ":" + j.SubjectVersion
}

// Validate rejects a job the relay could not deliver before it reaches the
// caller's transaction.
func (j Job) Validate() error {
	if !j.Kind.Valid() {
		return fmt.Errorf("unknown job kind %q", j.Kind)
	}
	if _, err := j.encodePayload(); err != nil {
		return err
	}
	return nil
}

func (j Job) encodePayload() (json.RawMessage, error) {
	switch payload := j.Payload.(type) {
	case nil:
		return json.RawMessage("{}"), nil
	case json.RawMessage:
		if len(payload) == 0 {
			return json.RawMessage("{}"), nil
		}
		if !json.Valid(payload) {
			return nil, fmt.Errorf("payload for %s is not valid json", j.Kind)
		}
		return payload, nil
	default:
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode payload for %s: %w", j.Kind, err)
		}
		return encoded, nil
	}
}

// Enqueuer is the seam a command depends on, so a handler test needs no database.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx bun.IDB, jobs ...Job) ([]uuid.UUID, error)
}

// Writer inserts outbox rows. It holds no database handle, so it can only
// enqueue inside the caller's transaction.
type Writer struct{}

func NewWriter() Writer { return Writer{} }

var _ Enqueuer = Writer{}

// Enqueue writes one row per job and raises NotifyChannel, all inside tx.
func (Writer) Enqueue(ctx context.Context, tx bun.IDB, jobs ...Job) ([]uuid.UUID, error) {
	if tx == nil {
		return nil, errors.New("enqueue: no transaction: outbox rows are written inside the caller's transaction")
	}
	if len(jobs) == 0 {
		return nil, nil
	}

	trace := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, trace)

	rows := make([]models.Outbox, 0, len(jobs))
	ids := make([]uuid.UUID, 0, len(jobs))
	for _, job := range jobs {
		if err := job.Validate(); err != nil {
			return nil, fmt.Errorf("enqueue: %w", err)
		}
		payload, err := job.encodePayload()
		if err != nil {
			return nil, err
		}

		id := models.NewID()
		ids = append(ids, id)
		rows = append(rows, models.Outbox{
			ID:             id,
			JobKind:        string(job.Kind),
			Payload:        payload,
			IdempotencyKey: job.IdempotencyKey(),
			State:          models.OutboxStatePending,
			TraceParent:    trace.Get("traceparent"),
		})
	}

	// am_fetcher and am_scanner hold INSERT-only on outbox, so suppress bun's
	// automatic RETURNING for `default:` columns.
	if _, err := tx.NewInsert().Model(&rows).Returning("NULL").Exec(ctx); err != nil {
		return nil, fmt.Errorf("insert outbox rows: %w", err)
	}

	// One notification per transaction is enough; the relay drains all pending.
	// bun formats raw SQL itself, so the placeholder is `?`, not `$1`.
	if _, err := tx.ExecContext(ctx, "select pg_notify(?, '')", NotifyChannel); err != nil {
		return nil, fmt.Errorf("notify %s: %w", NotifyChannel, err)
	}

	return ids, nil
}
