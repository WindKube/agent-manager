package view

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// Webhook is one subscription as the Webhooks screen lists it.
type Webhook struct {
	ID                 string
	Name               string
	URL                string
	EventTypes         []string
	Namespaces         []string
	Enabled            bool
	DisabledReason     string
	CreatedBy          string
	CreatedAt          time.Time
	LastDeliveryAt     *time.Time
	LastDeliveryStatus *int64
	LastDeliveryError  string
}

// EventList is the subscribed event types joined for a table cell.
func (w Webhook) EventList() string {
	if slices.Equal(w.EventTypes, []string{"*"}) {
		return "every event"
	}
	return strings.Join(w.EventTypes, ", ")
}

// NamespaceList is the namespace filter, or what its absence means.
func (w Webhook) NamespaceList() string {
	if len(w.Namespaces) == 0 {
		return "every namespace"
	}
	return strings.Join(w.Namespaces, ", ")
}

// State is enabled, or disabled with the reason when the hub did it.
func (w Webhook) State() string {
	switch {
	case w.Enabled:
		return "enabled"
	case w.DisabledReason != "":
		return "disabled: " + w.DisabledReason
	default:
		return "disabled"
	}
}

// LastDelivery is the last attempt's outcome, or "never".
func (w Webhook) LastDelivery() string {
	if w.LastDeliveryAt == nil {
		return "never delivered"
	}
	return "last " + deliveryOutcome(w.LastDeliveryStatus, w.LastDeliveryError) + " at " + Timestamp(*w.LastDeliveryAt)
}

// Href is a path under this webhook's own routes.
func (w Webhook) Href(action string) string { return "/webhooks/" + w.ID + "/" + action }

// DeliveriesHref opens this webhook's recent deliveries.
func (w Webhook) DeliveriesHref() string { return "/webhooks?webhook=" + w.ID + "#webhook-deliveries" }

// WebhookDelivery is one attempt to deliver one event.
type WebhookDelivery struct {
	EventID      string
	EventType    string
	Attempt      int64
	StatusCode   *int64
	Error        string
	ResponseBody string
	DurationMs   int64
	OccurredAt   time.Time
}

// Outcome is the status code, or the error when nothing answered.
func (d WebhookDelivery) Outcome() string { return deliveryOutcome(d.StatusCode, d.Error) }

// Delivered reports a 2xx answer.
func (d WebhookDelivery) Delivered() bool {
	return d.StatusCode != nil && *d.StatusCode >= 200 && *d.StatusCode < 300
}

// Duration is how long the attempt took.
func (d WebhookDelivery) Duration() string { return strconv.FormatInt(d.DurationMs, 10) + " ms" }

func deliveryOutcome(status *int64, err string) string {
	switch {
	case status != nil:
		return "HTTP " + strconv.FormatInt(*status, 10)
	case err != "":
		return "failed: " + err
	default:
		return "failed"
	}
}

// WebhookSecret is the only response that carries a signing secret; the
// screen shows it once and never again.
type WebhookSecret struct {
	Name   string
	Secret string
}

// WebhookForm is the create form's values, echoed back after a refusal.
type WebhookForm struct {
	Name       string
	URL        string
	EventTypes []string
	Namespaces string
}

// Selected reports whether an event type was ticked.
func (f WebhookForm) Selected(eventType string) bool { return slices.Contains(f.EventTypes, eventType) }

// NamespaceList splits the namespaces field on commas and whitespace.
func (f WebhookForm) NamespaceList() []string {
	return strings.FieldsFunc(f.Namespaces, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}

// Webhooks is the Webhooks screen.
type Webhooks struct {
	Webhooks []Webhook
	// EventTypes is the api's vocabulary, "*" first.
	EventTypes []string
	Form       WebhookForm
	Secret     *WebhookSecret

	// Open is the webhook whose deliveries are shown, if any.
	Open                  *Webhook
	Deliveries            []WebhookDelivery
	DeliveriesUnavailable bool

	Notice *Notice
	GovernanceState
}
