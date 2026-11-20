package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/notify"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// ErrWebhookNotFound is a subscription id that names nothing.
var ErrWebhookNotFound = queries.ErrWebhookNotFound

const maxWebhookNameLength = 100

// WebhookInput is a creation, or an update's full resulting state.
type WebhookInput struct {
	Name       string
	URL        string
	EventTypes []string
	Namespaces []string
}

// WebhookPatch carries an update; nil leaves a field as it is.
type WebhookPatch struct {
	Name       *string
	URL        *string
	EventTypes []string
	Namespaces *[]string
	Enabled    *bool
}

func (in WebhookInput) normalise() (WebhookInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > maxWebhookNameLength {
		return in, fmt.Errorf("%w: a webhook needs a name of 1 to %d characters", ErrValidation, maxWebhookNameLength)
	}
	in.URL = strings.TrimSpace(in.URL)
	if _, err := notify.ValidateURL(in.URL); err != nil {
		return in, fmt.Errorf("%w: %w", ErrValidation, err)
	}

	types := dedupe(in.EventTypes)
	switch {
	case len(types) == 0:
		return in, fmt.Errorf("%w: a webhook needs at least one event type, or *", ErrValidation)
	case slices.Contains(types, notify.AllEvents) && len(types) > 1:
		return in, fmt.Errorf("%w: * already selects every event type; list nothing else beside it", ErrValidation)
	}
	for _, t := range types {
		if t != notify.AllEvents && !notify.EventType(t).Valid() {
			return in, fmt.Errorf("%w: %q is not an event type", ErrValidation, t)
		}
	}
	in.EventTypes = types

	in.Namespaces = dedupe(in.Namespaces)
	for _, ns := range in.Namespaces {
		if len(ns) > 100 || strings.ContainsAny(ns, " \t\n/") {
			return in, fmt.Errorf("%w: %q is not a namespace", ErrValidation, ns)
		}
	}
	return in, nil
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// CreatedWebhook carries the only copy of the secret there will ever be.
type CreatedWebhook struct {
	ID     uuid.UUID
	Secret string
}

// CreateWebhook stores a subscription with a fresh secret.
func CreateWebhook(ctx context.Context, db bun.IDB, p auth.Principal, in WebhookInput) (CreatedWebhook, error) {
	if p.IdentityID == uuid.Nil {
		return CreatedWebhook{}, ErrServiceTokenNeedsAPerson
	}
	in, err := in.normalise()
	if err != nil {
		return CreatedWebhook{}, err
	}
	key, err := notify.NewSecret()
	if err != nil {
		return CreatedWebhook{}, err
	}

	sub := models.WebhookSubscription{
		ID: models.NewID(), Name: in.Name, URL: in.URL, EventTypes: in.EventTypes, Namespaces: in.Namespaces,
		Secret: key, Enabled: true, CreatedByIdentityID: p.IdentityID,
	}
	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// am_api may not read the secret back, so nothing is returned.
		if _, insertErr := tx.NewInsert().Model(&sub).Returning("NULL").Exec(ctx); insertErr != nil {
			return fmt.Errorf("insert webhook: %w", insertErr)
		}
		entry := identityAudit(p, models.AuditKindWebhook, "created",
			fmt.Sprintf("created webhook %s to %s for %s", sub.Name, notify.RedactedHost(sub.URL),
				strings.Join(sub.EventTypes, ", ")),
			audit.Webhook(sub.ID, sub.Name))
		entry.Data = webhookAuditData(in)
		return writeAudit(ctx, tx, entry)
	})
	if err != nil {
		return CreatedWebhook{}, err
	}
	return CreatedWebhook{ID: sub.ID, Secret: notify.EncodeSecret(key)}, nil
}

// UpdateWebhook applies a patch. Re-enabling clears the disabled reason.
func UpdateWebhook(ctx context.Context, db bun.IDB, p auth.Principal, id uuid.UUID, patch WebhookPatch) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		current, err := lockWebhook(ctx, tx, id)
		if err != nil {
			return err
		}
		next := WebhookInput{Name: current.Name, URL: current.URL, EventTypes: current.EventTypes, Namespaces: current.Namespaces}
		if patch.Name != nil {
			next.Name = *patch.Name
		}
		if patch.URL != nil {
			next.URL = *patch.URL
		}
		if patch.EventTypes != nil {
			next.EventTypes = patch.EventTypes
		}
		if patch.Namespaces != nil {
			next.Namespaces = *patch.Namespaces
		}
		if next, err = next.normalise(); err != nil {
			return err
		}
		enabled := current.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}

		q := tx.NewUpdate().Model((*models.WebhookSubscription)(nil)).
			Set("name = ?", next.Name).
			Set("url = ?", next.URL).
			Set("event_types = ?", pgdialect.Array(next.EventTypes)).
			Set("namespaces = ?", pgdialect.Array(next.Namespaces)).
			Set("enabled = ?", enabled).
			Set("updated_at = now()").
			Where("id = ?", id)
		if enabled {
			q = q.Set("disabled_reason = NULL")
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("update webhook %s: %w", id, err)
		}

		action, text := "updated", "updated webhook "+next.Name
		switch {
		case enabled && !current.Enabled:
			action, text = "enabled", "enabled webhook "+next.Name
		case !enabled && current.Enabled:
			action, text = "disabled", "disabled webhook "+next.Name
		}
		entry := identityAudit(p, models.AuditKindWebhook, action, text, audit.Webhook(id, next.Name))
		entry.Data = webhookAuditData(next)
		return writeAudit(ctx, tx, entry)
	})
}

// RotateWebhookSecret replaces the secret and returns the new one, once.
func RotateWebhookSecret(ctx context.Context, db bun.IDB, p auth.Principal, id uuid.UUID) (string, error) {
	key, err := notify.NewSecret()
	if err != nil {
		return "", err
	}
	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		current, lockErr := lockWebhook(ctx, tx, id)
		if lockErr != nil {
			return lockErr
		}
		if _, updErr := tx.NewUpdate().Model((*models.WebhookSubscription)(nil)).
			Set("secret = ?", key).Set("updated_at = now()").
			Where("id = ?", id).Exec(ctx); updErr != nil {
			return fmt.Errorf("rotate the secret of webhook %s: %w", id, updErr)
		}
		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindWebhook, "secret-rotated",
			"rotated the secret of webhook "+current.Name, audit.Webhook(id, current.Name)))
	})
	if err != nil {
		return "", err
	}
	return notify.EncodeSecret(key), nil
}

// DeleteWebhook removes a subscription and its delivery log.
func DeleteWebhook(ctx context.Context, db bun.IDB, p auth.Principal, id uuid.UUID) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		current, err := lockWebhook(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*models.WebhookDelivery)(nil)).Where("subscription_id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("delete the deliveries of webhook %s: %w", id, err)
		}
		if _, err := tx.NewDelete().Model((*models.WebhookSubscription)(nil)).Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("delete webhook %s: %w", id, err)
		}
		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindWebhook, "deleted",
			"deleted webhook "+current.Name, audit.Webhook(id, current.Name)))
	})
}

// lockWebhook reads the row without its secret, which am_api cannot select.
func lockWebhook(ctx context.Context, tx bun.IDB, id uuid.UUID) (models.WebhookSubscription, error) {
	var sub models.WebhookSubscription
	err := tx.NewSelect().Model(&sub).ExcludeColumn("secret").Where("id = ?", id).For("update").Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return sub, ErrWebhookNotFound
	case err != nil:
		return sub, fmt.Errorf("load webhook %s: %w", id, err)
	}
	return sub, nil
}

func webhookAuditData(in WebhookInput) map[string]any {
	return map[string]any{"host": notify.RedactedHost(in.URL), "eventTypes": in.EventTypes, "namespaces": in.Namespaces}
}
