package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Outbox is the only door to the queue: a row is written inside the mutation's
// own transaction, and a relay drains it with `for update skip locked`. Enqueuing
// after commit instead would lose jobs on a crash.
type Outbox struct {
	bun.BaseModel `bun:"table:outbox,alias:obx"`

	ID      uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	JobKind string          `bun:"job_kind,type:text,notnull"`
	Payload json.RawMessage `bun:"payload,type:jsonb,notnull"`
	// IdempotencyKey is (job_kind, subject_id, subject_version); delivery is
	// at-least-once, so the handler must recognize a redelivery.
	IdempotencyKey string      `bun:"idempotency_key,type:text,notnull"`
	State          OutboxState `bun:"state,type:outbox_state,notnull"`
	CreatedAt      time.Time   `bun:"created_at,type:timestamptz,notnull,default:now()"`
	DeliveredAt    *time.Time  `bun:"delivered_at,type:timestamptz,nullzero"`
}
