package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/notify"
	"agent-manager/internal/store/models"
)

// ErrWebhookNotFound is a subscription id that names nothing.
var ErrWebhookNotFound = errors.New("no such webhook")

const maxWebhookDeliveries = 100

// Webhooks lists every subscription, never with its secret: am_api holds no
// SELECT on that column, so selecting it would be refused.
func Webhooks(ctx context.Context, db bun.IDB) (contract.WebhookList, error) {
	var rows []models.WebhookSubscription
	if err := db.NewSelect().Model(&rows).ExcludeColumn("secret").Relation("CreatedBy").
		OrderExpr("whs.created_at desc").Scan(ctx); err != nil {
		return contract.WebhookList{}, fmt.Errorf("list webhooks: %w", err)
	}
	out := contract.WebhookList{Webhooks: make([]contract.Webhook, 0, len(rows)), EventTypes: []string{}}
	for i := range rows {
		out.Webhooks = append(out.Webhooks, webhookWire(&rows[i]))
	}
	for _, t := range notify.EventTypes() {
		out.EventTypes = append(out.EventTypes, string(t))
	}
	return out, nil
}

// Webhook is one subscription.
func Webhook(ctx context.Context, db bun.IDB, id uuid.UUID) (contract.Webhook, error) {
	var row models.WebhookSubscription
	err := db.NewSelect().Model(&row).ExcludeColumn("secret").Relation("CreatedBy").
		Where("whs.id = ?", id).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.Webhook{}, ErrWebhookNotFound
	case err != nil:
		return contract.Webhook{}, fmt.Errorf("read webhook %s: %w", id, err)
	}
	return webhookWire(&row), nil
}

// WebhookDeliveries is a subscription's most recent attempts.
func WebhookDeliveries(ctx context.Context, db bun.IDB, id uuid.UUID) (contract.WebhookDeliveryList, error) {
	if _, err := Webhook(ctx, db, id); err != nil {
		return contract.WebhookDeliveryList{}, err
	}
	var rows []models.WebhookDelivery
	if err := db.NewSelect().Model(&rows).Where("subscription_id = ?", id).
		OrderExpr("occurred_at desc, id desc").Limit(maxWebhookDeliveries).Scan(ctx); err != nil {
		return contract.WebhookDeliveryList{}, fmt.Errorf("list deliveries of webhook %s: %w", id, err)
	}
	out := contract.WebhookDeliveryList{Deliveries: make([]contract.WebhookDelivery, 0, len(rows))}
	for i := range rows {
		row := &rows[i]
		out.Deliveries = append(out.Deliveries, contract.WebhookDelivery{
			ID: row.ID.String(), EventID: row.EventID.String(), EventType: row.EventType,
			Attempt: int(row.Attempt), StatusCode: intPtr(row.StatusCode), Error: row.Error,
			ResponseBody: row.ResponseBody, DurationMs: int(row.DurationMs), OccurredAt: row.OccurredAt,
		})
	}
	return out, nil
}

func webhookWire(row *models.WebhookSubscription) contract.Webhook {
	createdBy := ""
	if row.CreatedBy != nil {
		createdBy = row.CreatedBy.Email
		if createdBy == "" {
			createdBy = row.CreatedBy.Subject
		}
	}
	namespaces := append([]string{}, row.Namespaces...)
	return contract.Webhook{
		ID: row.ID.String(), Name: row.Name, URL: row.URL,
		EventTypes: append([]string{}, row.EventTypes...), Namespaces: namespaces,
		Enabled: row.Enabled, DisabledReason: row.DisabledReason, CreatedBy: createdBy,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, LastDeliveryAt: row.LastDeliveryAt,
		LastDeliveryStatus: intPtr(row.LastDeliveryStatus), LastDeliveryError: row.LastDeliveryError,
	}
}

func intPtr(v *int32) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}
