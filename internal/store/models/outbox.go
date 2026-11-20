package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Outbox is the only door to the queue: a row is written inside the
// mutation's own transaction, so enqueuing after commit instead would lose
// jobs on a crash.
type Outbox struct {
	bun.BaseModel `bun:"table:outbox,alias:obx"`

	ID             uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	JobKind        string          `bun:"job_kind,type:text,notnull"`
	Payload        json.RawMessage `bun:"payload,type:jsonb,notnull"`
	IdempotencyKey string          `bun:"idempotency_key,type:text,notnull"`
	State          OutboxState     `bun:"state,type:outbox_state,notnull"`
	CreatedAt      time.Time       `bun:"created_at,type:timestamptz,notnull,default:now()"`
	DeliveredAt    *time.Time      `bun:"delivered_at,type:timestamptz,nullzero"`
	// TraceParent is the W3C traceparent of the span that enqueued the job, so
	// the job's own spans can link back to the request that caused it.
	TraceParent string `bun:"traceparent,type:text,nullzero"`
}
