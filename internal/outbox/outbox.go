// Package outbox is the only door to the job queue. The queue lives in its
// own PostgreSQL database, so a mutation cannot enqueue inside its own
// transaction: Writer inserts a row inside the caller's transaction instead,
// and Relay moves committed rows into River, so a commit publishes both the
// state change and its jobs, or neither.
//
// Delivery is at-least-once, deliberately: the relay inserts into River
// before it marks the outbox row delivered, since the other order loses the
// job outright if the process dies in between, while this order only
// duplicates it. The idempotency key lives on the job's target row — never
// in the queue — so a redelivery is answered by the data rather than by the
// queue remembering.
//
// No code path may enqueue by calling River from a request handler. It goes
// through Writer, or it is a defect.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
)

// NotifyChannel is the LISTEN channel the relay wakes on. Writer raises it inside
// the caller's transaction, so Postgres delivers it on commit and discards it on
// rollback — the notification cannot outrun the row it refers to.
const NotifyChannel = "outbox_new"

// Kind is an outbox row's job_kind.
type Kind string

const (
	KindFetch       Kind = "fetch"
	KindScan        Kind = "scan"
	KindRescanSweep Kind = "rescan-sweep"
)

func (k Kind) Valid() bool {
	switch k {
	case KindFetch, KindScan, KindRescanSweep:
		return true
	default:
		return false
	}
}

// Queue names, one per worker role. A kind rides the queue its worker actually
// registers — no kind may share river.QueueDefault, or a worker that never
// registers that queue's job kind starves on jobs it cannot run.
const (
	QueueFetch = "fetch"
	QueueScan  = "scan"
)

// queueByKind names the River queue a kind is delivered to. The outbox row carries
// no queue column, so the mapping lives here.
var queueByKind = map[Kind]string{
	KindFetch:       QueueFetch,
	KindScan:        QueueScan,
	KindRescanSweep: QueueScan,
}

// Queue is the River queue a kind is delivered to.
func Queue(k Kind) string {
	return queueByKind[k]
}

// Job is one queued unit of work as the caller describes it.
type Job struct {
	Kind Kind

	// SubjectID and SubjectVersion complete the idempotency key. They name the
	// row whose state answers "has this already happened?" — the version for
	// a fetch, the version plus rule-pack version for a scan. A sweep has no
	// subject.
	SubjectID      uuid.UUID
	SubjectVersion string

	// Payload is marshalled to jsonb and handed to River verbatim. A
	// json.RawMessage passes through unchanged.
	Payload any
}

// IdempotencyKey is (job_kind, subject_id, subject_version), the key the
// handler uses to recognise a redelivery.
func (j Job) IdempotencyKey() string {
	subject := ""
	if j.SubjectID != uuid.Nil {
		subject = j.SubjectID.String()
	}
	return string(j.Kind) + ":" + subject + ":" + j.SubjectVersion
}

// Validate rejects a job the relay could not deliver, before it reaches the
// caller's transaction: an unknown kind has no worker registered against it and a
// payload that will not encode would abort the mutation at the insert.
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

// Writer inserts outbox rows. It deliberately holds no database handle:
// every call takes the caller's transaction, so "enqueue outside a
// transaction" is not expressible.
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
		})
	}

	// am_fetcher and am_scanner hold INSERT-only on outbox — no SELECT — and bun
	// appends RETURNING for every `default:`-tagged column unless told not to,
	// which that grant refuses. am_api, the other caller, never reads the
	// returned columns either, so suppressing it costs nothing there.
	if _, err := tx.NewInsert().Model(&rows).Returning("NULL").Exec(ctx); err != nil {
		return nil, fmt.Errorf("insert outbox rows: %w", err)
	}

	// One notification per transaction is enough: the relay drains everything
	// pending when it wakes. The placeholder is bun's `?`, not Postgres's
	// `$1`: bun formats raw SQL itself and passes no arguments to the driver.
	if _, err := tx.ExecContext(ctx, "select pg_notify(?, '')", NotifyChannel); err != nil {
		return nil, fmt.Errorf("notify %s: %w", NotifyChannel, err)
	}

	return ids, nil
}
