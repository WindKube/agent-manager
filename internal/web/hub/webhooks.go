package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The Webhooks screen's door to the api.

// ErrWebhookNotFound is a webhook id the api does not know.
var ErrWebhookNotFound = errors.New("no such webhook")

// WebhookRefusedError is a 422 whose problem detail the screen shows as-is.
type WebhookRefusedError struct{ Detail string }

func (e *WebhookRefusedError) Error() string { return e.Detail }

// Webhooks reads GET /v1/webhooks: the subscriptions and the event vocabulary.
func (c *Client) Webhooks(ctx context.Context) ([]view.Webhook, []string, error) {
	resp, err := c.api.ListWebhooksWithResponse(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list webhooks: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, nil, fmt.Errorf("list webhooks: %w", webhookError(resp.HTTPResponse, resp.Body))
	}
	out := make([]view.Webhook, 0, len(resp.JSON200.Webhooks))
	for i := range resp.JSON200.Webhooks {
		out = append(out, webhookView(&resp.JSON200.Webhooks[i]))
	}
	return out, resp.JSON200.EventTypes, nil
}

// CreateWebhook posts POST /v1/webhooks and returns the signing secret,
// which nothing on this side stores.
func (c *Client) CreateWebhook(ctx context.Context, name, url string, eventTypes, namespaces []string) (view.WebhookSecret, error) {
	types := make([]apiclient.CreateWebhookRequestEventTypes, 0, len(eventTypes))
	for _, t := range eventTypes {
		types = append(types, apiclient.CreateWebhookRequestEventTypes(t))
	}
	resp, err := c.api.CreateWebhookWithResponse(ctx, apiclient.CreateWebhookRequest{
		Name: name, Url: url, EventTypes: types, Namespaces: &namespaces,
	})
	if err != nil {
		return view.WebhookSecret{}, fmt.Errorf("create webhook: %w", err)
	}
	if resp.JSON201 == nil {
		return view.WebhookSecret{}, webhookError(resp.HTTPResponse, resp.Body)
	}
	return view.WebhookSecret{Name: resp.JSON201.Webhook.Name, Secret: resp.JSON201.Secret}, nil
}

// SetWebhookEnabled patches PATCH /v1/webhooks/{id}.
func (c *Client) SetWebhookEnabled(ctx context.Context, id string, enabled bool) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ErrWebhookNotFound
	}
	resp, err := c.api.UpdateWebhookWithResponse(ctx, parsed, apiclient.UpdateWebhookRequest{Enabled: &enabled})
	if err != nil {
		return fmt.Errorf("update webhook: %w", err)
	}
	if resp.JSON200 != nil {
		return nil
	}
	return webhookError(resp.HTTPResponse, resp.Body)
}

// RotateWebhookSecret posts POST /v1/webhooks/{id}/secret; the old secret
// stops signing at once.
func (c *Client) RotateWebhookSecret(ctx context.Context, id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return "", ErrWebhookNotFound
	}
	resp, err := c.api.RotateWebhookSecretWithResponse(ctx, parsed)
	if err != nil {
		return "", fmt.Errorf("rotate webhook secret: %w", err)
	}
	if resp.JSON200 == nil {
		return "", webhookError(resp.HTTPResponse, resp.Body)
	}
	return resp.JSON200.Secret, nil
}

// DeleteWebhook deletes DELETE /v1/webhooks/{id}.
func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ErrWebhookNotFound
	}
	resp, err := c.api.DeleteWebhookWithResponse(ctx, parsed)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if resp.StatusCode() == http.StatusNoContent {
		return nil
	}
	return webhookError(resp.HTTPResponse, resp.Body)
}

// WebhookDeliveries reads GET /v1/webhooks/{id}/deliveries, newest first.
func (c *Client) WebhookDeliveries(ctx context.Context, id string) ([]view.WebhookDelivery, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrWebhookNotFound
	}
	resp, err := c.api.ListWebhookDeliveriesWithResponse(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, webhookError(resp.HTTPResponse, resp.Body)
	}
	out := make([]view.WebhookDelivery, 0, len(resp.JSON200.Deliveries))
	for i := range resp.JSON200.Deliveries {
		d := &resp.JSON200.Deliveries[i]
		out = append(out, view.WebhookDelivery{
			EventID: d.EventId.String(), EventType: d.EventType, Attempt: d.Attempt, StatusCode: d.StatusCode,
			Error: deref(d.Error), ResponseBody: deref(d.ResponseBody), DurationMs: d.DurationMs, OccurredAt: d.OccurredAt,
		})
	}
	return out, nil
}

func webhookView(w *apiclient.Webhook) view.Webhook {
	return view.Webhook{
		ID: w.Id.String(), Name: w.Name, URL: w.Url,
		EventTypes: append([]string{}, w.EventTypes...), Namespaces: append([]string{}, w.Namespaces...),
		Enabled: w.Enabled, DisabledReason: deref(w.DisabledReason), CreatedBy: w.CreatedBy, CreatedAt: w.CreatedAt,
		LastDeliveryAt: w.LastDeliveryAt, LastDeliveryStatus: w.LastDeliveryStatus, LastDeliveryError: deref(w.LastDeliveryError),
	}
}

func webhookError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return ErrWebhookNotFound
		case http.StatusForbidden:
			return ErrForbidden
		case http.StatusUnprocessableEntity:
			detail := http.StatusText(resp.StatusCode)
			var problem apiclient.Error
			if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
				detail = *problem.Detail
			}
			return &WebhookRefusedError{Detail: detail}
		}
	}
	return statusError(resp, body)
}
