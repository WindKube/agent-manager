package contract

import "time"

// CreateWebhookRequest asks for a new webhook subscription.
type CreateWebhookRequest struct {
	Name       string   `json:"name" minLength:"1" maxLength:"100" doc:"What the webhook is for." example:"security channel"`
	URL        string   `json:"url" minLength:"1" maxLength:"2048" doc:"https only, with no credentials in it and not a private or loopback address." example:"https://hooks.example.com/agent-manager"`
	EventTypes []string `json:"eventTypes" minItems:"1" maxItems:"50" enum:"*,package.version.registered,package.version.stored,package.version.fetch-failed,package.version.deleted,package.deleted,scan.completed,finding.accepted,finding.rejected,waiver.expiring,waiver.expired,profile.revision.published,policy.changed,service-token.created,service-token.revoked,machine.forgotten" doc:"The event types to deliver, or the single entry * for every one." example:"[\"scan.completed\",\"waiver.expiring\"]"`
	Namespaces []string `json:"namespaces,omitempty" maxItems:"50" doc:"Only events about packages in these namespaces. Absent or empty delivers every namespace, and events with no namespace." example:"[\"platform\"]"`
}

// UpdateWebhookRequest changes what is given and leaves the rest.
type UpdateWebhookRequest struct {
	Name       *string  `json:"name,omitempty" minLength:"1" maxLength:"100"`
	URL        *string  `json:"url,omitempty" minLength:"1" maxLength:"2048"`
	EventTypes []string `json:"eventTypes,omitempty" maxItems:"50" enum:"*,package.version.registered,package.version.stored,package.version.fetch-failed,package.version.deleted,package.deleted,scan.completed,finding.accepted,finding.rejected,waiver.expiring,waiver.expired,profile.revision.published,policy.changed,service-token.created,service-token.revoked,machine.forgotten"`
	// Namespaces is a pointer so an explicit empty list can clear the filter.
	Namespaces *[]string `json:"namespaces,omitempty" maxItems:"50"`
	Enabled    *bool     `json:"enabled,omitempty" doc:"Re-enabling clears the reason a webhook was disabled."`
}

// Webhook is one subscription as listed. It never carries the secret.
type Webhook struct {
	ID                 string     `json:"id" format:"uuid"`
	Name               string     `json:"name" example:"security channel"`
	URL                string     `json:"url" example:"https://hooks.example.com/agent-manager"`
	EventTypes         []string   `json:"eventTypes" example:"[\"scan.completed\"]"`
	Namespaces         []string   `json:"namespaces" doc:"Empty means every namespace."`
	Enabled            bool       `json:"enabled"`
	DisabledReason     string     `json:"disabledReason,omitempty" doc:"Why the hub disabled it, when it did; absent when a person did." example:"the receiver answered 410 Gone"`
	CreatedBy          string     `json:"createdBy" doc:"The email or subject of the person who created it." example:"kwiatrzyk@example.com"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
	LastDeliveryAt     *time.Time `json:"lastDeliveryAt,omitempty"`
	LastDeliveryStatus *int       `json:"lastDeliveryStatus,omitempty" doc:"The HTTP status of the last attempt; absent when it got no response."`
	LastDeliveryError  string     `json:"lastDeliveryError,omitempty"`
}

// WebhookCreated is one of the two responses that carry a secret.
type WebhookCreated struct {
	Webhook Webhook `json:"webhook"`
	Secret  string  `json:"secret" doc:"The signing secret, whsec_ and base64. Returned once." example:"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"`
}

// WebhookSecret is a rotated secret, returned once.
type WebhookSecret struct {
	Secret string `json:"secret" doc:"The new signing secret, whsec_ and base64. The previous one stops signing immediately." example:"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"`
}

// WebhookList is every subscription, and the event types one may filter on.
type WebhookList struct {
	Webhooks   []Webhook `json:"webhooks" doc:"Most recently created first."`
	EventTypes []string  `json:"eventTypes" doc:"Every event type a subscription can select."`
}

// WebhookDelivery is one delivery attempt.
type WebhookDelivery struct {
	ID           string    `json:"id" format:"uuid"`
	EventID      string    `json:"eventId" format:"uuid" doc:"The audit event delivered, and the Webhook-Id header the receiver saw."`
	EventType    string    `json:"eventType" example:"scan.completed"`
	Attempt      int       `json:"attempt" example:"1"`
	StatusCode   *int      `json:"statusCode,omitempty" doc:"Absent when no response arrived."`
	Error        string    `json:"error,omitempty"`
	ResponseBody string    `json:"responseBody,omitempty" doc:"The first KiB of the receiver's answer."`
	DurationMs   int       `json:"durationMs"`
	OccurredAt   time.Time `json:"occurredAt"`
}

// WebhookDeliveryList is a subscription's most recent attempts.
type WebhookDeliveryList struct {
	Deliveries []WebhookDelivery `json:"deliveries" doc:"Newest first, at most 100, kept for 30 days."`
}
