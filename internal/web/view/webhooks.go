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

func (w Webhook) EventList() string {
	if slices.Equal(w.EventTypes, []string{"*"}) {
		return "every event"
	}
	return strings.Join(w.EventTypes, ", ")
}

func (w Webhook) NamespaceList() string {
	if len(w.Namespaces) == 0 {
		return "every namespace"
	}
	return strings.Join(w.Namespaces, ", ")
}

// State includes the reason when the hub disabled the webhook itself.
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

func (w Webhook) LastDelivery() string {
	if w.LastDeliveryAt == nil {
		return "never delivered"
	}
	return "last " + deliveryOutcome(w.LastDeliveryStatus, w.LastDeliveryError) + " at " + Timestamp(*w.LastDeliveryAt)
}

func (w Webhook) Href(action string) string { return "/webhooks/" + w.ID + "/" + action }

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

func (d WebhookDelivery) Outcome() string { return deliveryOutcome(d.StatusCode, d.Error) }

func (d WebhookDelivery) Delivered() bool {
	return d.StatusCode != nil && *d.StatusCode >= 200 && *d.StatusCode < 300
}

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

// WebhookSecret is the only response that carries a signing secret; it is shown once.
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

func (f WebhookForm) Selected(eventType string) bool { return slices.Contains(f.EventTypes, eventType) }

func (f WebhookForm) NamespaceList() []string {
	return strings.FieldsFunc(f.Namespaces, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}

type Webhooks struct {
	Webhooks []Webhook
	// EventTypes is the api's vocabulary, "*" first.
	EventTypes []string
	Form       WebhookForm
	Secret     *WebhookSecret

	Open                  *Webhook
	Deliveries            []WebhookDelivery
	DeliveriesUnavailable bool

	Notice *Notice
	GovernanceState
}
