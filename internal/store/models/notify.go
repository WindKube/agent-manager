package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// WebhookSubscription is one outbound webhook. Secret is the HMAC key: am_api
// may write it but cannot SELECT it; only the notifier reads it back.
type WebhookSubscription struct {
	bun.BaseModel `bun:"table:webhook_subscription,alias:whs"`

	ID   uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	Name string    `bun:"name,type:text,notnull"`
	URL  string    `bun:"url,type:text,notnull"`
	// EventTypes is a list of notify event types, or the single entry "*".
	EventTypes []string `bun:"event_types,array,type:text[],notnull"`
	// Namespaces empty means every namespace.
	Namespaces          []string  `bun:"namespaces,array,type:text[],notnull,default:'{}'"`
	Secret              []byte    `bun:"secret,type:bytea,notnull"`
	Enabled             bool      `bun:"enabled,type:boolean,notnull,default:true"`
	DisabledReason      string    `bun:"disabled_reason,type:text,nullzero"`
	CreatedByIdentityID uuid.UUID `bun:"created_by_identity_id,type:uuid,notnull"`
	CreatedAt           time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt           time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`
	// Last attempt's outcome, denormalised so listing needs no join.
	LastDeliveryAt     *time.Time `bun:"last_delivery_at,type:timestamptz,nullzero"`
	LastDeliveryStatus *int32     `bun:"last_delivery_status,type:integer,nullzero"`
	LastDeliveryError  string     `bun:"last_delivery_error,type:text,nullzero"`

	CreatedBy *Identity `bun:"rel:belongs-to,join:created_by_identity_id=id"`
}

// WebhookDispatch marks an audit row the notifier has fanned out to its
// subscriptions; its primary key is what makes the fan-out happen once.
type WebhookDispatch struct {
	bun.BaseModel `bun:"table:webhook_dispatch,alias:whx"`

	AuditEventID uuid.UUID `bun:"audit_event_id,pk,type:uuid,notnull"`
	DispatchedAt time.Time `bun:"dispatched_at,type:timestamptz,notnull,default:now()"`
}

// WebhookDelivery is one delivery attempt, kept for 30 days and deleted with
// its subscription.
type WebhookDelivery struct {
	bun.BaseModel `bun:"table:webhook_delivery,alias:whd"`

	ID             uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	SubscriptionID uuid.UUID `bun:"subscription_id,type:uuid,notnull"`
	// EventID is the audit_event id, also the Webhook-Id receivers dedupe on.
	EventID   uuid.UUID `bun:"event_id,type:uuid,notnull"`
	EventType string    `bun:"event_type,type:text,notnull"`
	Attempt   int32     `bun:"attempt,type:integer,notnull"`
	// StatusCode is null when no response arrived.
	StatusCode *int32 `bun:"status_code,type:integer,nullzero"`
	Error      string `bun:"error,type:text,nullzero"`
	// ResponseBody is the first KiB of the receiver's answer.
	ResponseBody string    `bun:"response_body,type:text,nullzero"`
	DurationMs   int32     `bun:"duration_ms,type:integer,notnull"`
	OccurredAt   time.Time `bun:"occurred_at,type:timestamptz,notnull,default:now()"`

	Subscription *WebhookSubscription `bun:"rel:belongs-to,join:subscription_id=id"`
}
