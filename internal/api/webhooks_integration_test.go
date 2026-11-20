//go:build integration

package api_test

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/notify"
	"agent-manager/internal/store/models"
	"agent-manager/internal/store/storetest"
)

func webhookAuditActions(t *testing.T, id string) []string {
	t.Helper()
	var actions []string
	require.NoError(t, db.NewSelect().Model((*models.AuditEvent)(nil)).ColumnExpr("data ->> 'action'").
		Where("subject_kind = 'webhook' and subject_id = ?", id).OrderExpr("occurred_at, id").
		Scan(context.Background(), &actions))
	return actions
}

func storedSecret(t *testing.T, id string) []byte {
	t.Helper()
	var key []byte
	require.NoError(t, db.NewSelect().Model((*models.WebhookSubscription)(nil)).Column("secret").
		Where("id = ?", id).Scan(context.Background(), &key))
	return key
}

func TestACatalogAdminManagesAWebhookAndEveryChangeIsAudited(t *testing.T) {
	created := sendJSON[contract.WebhookCreated](t, kw, http.MethodPost, "/v1/webhooks",
		`{"name":"siem","url":"https://hooks.example.com/services/T0/B0/very-secret","eventTypes":["scan.completed","waiver.expiring"],"namespaces":["platform"]}`,
		http.StatusCreated)
	hook := created.Webhook
	require.True(t, strings.HasPrefix(created.Secret, "whsec_"))
	key, err := notify.DecodeSecret(created.Secret)
	require.NoError(t, err)
	require.Equal(t, key, storedSecret(t, hook.ID))
	require.Equal(t, []string{"scan.completed", "waiver.expiring"}, hook.EventTypes)
	require.Equal(t, []string{"platform"}, hook.Namespaces)
	require.True(t, hook.Enabled)
	require.Equal(t, "kwiatrzyk@example.com", hook.CreatedBy)

	listed := sendJSON[contract.WebhookList](t, kw, http.MethodGet, "/v1/webhooks", "", http.StatusOK)
	require.NotEmpty(t, listed.EventTypes)
	require.Contains(t, listed.EventTypes, "waiver.expired")
	require.True(t, func() bool {
		for _, w := range listed.Webhooks {
			if w.ID == hook.ID {
				return true
			}
		}
		return false
	}())
	require.NotContains(t, string(send(t, kw, http.MethodGet, "/v1/webhooks", "", http.StatusOK)), created.Secret)

	path := "/v1/webhooks/" + hook.ID
	disabled := sendJSON[contract.Webhook](t, kw, http.MethodPatch, path, `{"enabled":false,"namespaces":[]}`, http.StatusOK)
	require.False(t, disabled.Enabled)
	require.Empty(t, disabled.Namespaces)
	require.Equal(t, hook.EventTypes, disabled.EventTypes, "an absent field is left as it was")

	renamed := sendJSON[contract.Webhook](t, kw, http.MethodPatch, path, `{"name":"siem-2","enabled":true,"eventTypes":["*"]}`, http.StatusOK)
	require.Equal(t, "siem-2", renamed.Name)
	require.True(t, renamed.Enabled)
	require.Equal(t, []string{"*"}, renamed.EventTypes)

	rotated := sendJSON[contract.WebhookSecret](t, kw, http.MethodPost, path+"/secret", "", http.StatusOK)
	require.NotEqual(t, created.Secret, rotated.Secret)
	rotatedKey, err := notify.DecodeSecret(rotated.Secret)
	require.NoError(t, err)
	require.Equal(t, rotatedKey, storedSecret(t, hook.ID))

	deliveries := sendJSON[contract.WebhookDeliveryList](t, kw, http.MethodGet, path+"/deliveries", "", http.StatusOK)
	require.Empty(t, deliveries.Deliveries)

	send(t, kw, http.MethodDelete, path, "", http.StatusNoContent)
	send(t, kw, http.MethodDelete, path, "", http.StatusNotFound)
	send(t, kw, http.MethodGet, path+"/deliveries", "", http.StatusNotFound)

	require.Equal(t, []string{"created", "disabled", "enabled", "secret-rotated", "deleted"}, webhookAuditActions(t, hook.ID))
	var leaked int
	require.NoError(t, db.NewSelect().Model((*models.AuditEvent)(nil)).ColumnExpr("count(*)").
		Where("subject_kind = 'webhook' and subject_id = ?", hook.ID).
		Where("(text || data::text) like '%very-secret%' or (text || data::text) like '%whsec_%'").
		Scan(context.Background(), &leaked))
	require.Zero(t, leaked, "neither the URL's path nor a secret may reach the audit log")
}

func TestOnlyACatalogAdminMayTouchWebhooks(t *testing.T) {
	body := `{"name":"x","url":"https://hooks.example.com/x","eventTypes":["*"]}`
	for _, who := range []actor{an, contractor} {
		send(t, who, http.MethodGet, "/v1/webhooks", "", http.StatusForbidden)
		send(t, who, http.MethodPost, "/v1/webhooks", body, http.StatusForbidden)
		send(t, who, http.MethodDelete, "/v1/webhooks/"+uuid.NewString(), "", http.StatusForbidden)
	}

	token := createServiceToken(t, kw, "ci-webhooks", "read:catalog")
	rec := request(t, liveHandler(t), http.MethodGet, "/v1/webhooks", token.Secret, "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

func TestAWebhookURLMustBePublicHTTPSAndItsEventTypesKnown(t *testing.T) {
	for _, body := range []string{
		`{"name":"x","url":"http://hooks.example.com/x","eventTypes":["*"]}`,
		`{"name":"x","url":"https://10.0.0.5/x","eventTypes":["*"]}`,
		`{"name":"x","url":"https://169.254.169.254/latest/meta-data","eventTypes":["*"]}`,
		`{"name":"x","url":"https://u:p@hooks.example.com/x","eventTypes":["*"]}`,
		`{"name":"x","url":"https://localhost/x","eventTypes":["*"]}`,
		`{"name":"x","url":"https://hooks.example.com/x","eventTypes":["no.such.event"]}`,
		`{"name":"x","url":"https://hooks.example.com/x","eventTypes":["*","scan.completed"]}`,
		`{"name":"x","url":"https://hooks.example.com/x","eventTypes":[]}`,
	} {
		send(t, kw, http.MethodPost, "/v1/webhooks", body, http.StatusUnprocessableEntity)
	}
}

func TestTheAPIRoleManagesWebhooksWithoutEverReadingASecret(t *testing.T) {
	ctx := context.Background()
	// The suite connects as a superuser, which would hide a missing column grant.
	asAPI, closeAPI, err := storetest.RoleDB(ctx, appURL, "am_api")
	require.NoError(t, err)
	t.Cleanup(closeAPI)
	p := principalFor(t, kw)

	created, err := commands.CreateWebhook(ctx, asAPI, p, commands.WebhookInput{
		Name: "as-api", URL: "https://hooks.example.com/as-api", EventTypes: []string{"policy.changed"},
	})
	require.NoError(t, err)

	off := false
	require.NoError(t, commands.UpdateWebhook(ctx, asAPI, p, created.ID, commands.WebhookPatch{Enabled: &off}))
	_, err = commands.RotateWebhookSecret(ctx, asAPI, p, created.ID)
	require.NoError(t, err)

	hook, err := queries.Webhook(ctx, asAPI, created.ID)
	require.NoError(t, err)
	require.False(t, hook.Enabled)
	_, err = queries.Webhooks(ctx, asAPI)
	require.NoError(t, err)
	_, err = queries.WebhookDeliveries(ctx, asAPI, created.ID)
	require.NoError(t, err)

	_, err = db.NewInsert().Model(&models.WebhookDelivery{
		ID: models.NewID(), SubscriptionID: created.ID, EventID: models.NewID(), EventType: "policy.changed",
		Attempt: 1, DurationMs: 3,
	}).Exec(ctx)
	require.NoError(t, err)
	require.NoError(t, commands.DeleteWebhook(ctx, asAPI, p, created.ID))

	var secret []byte
	err = asAPI.NewSelect().Model((*models.WebhookSubscription)(nil)).Column("secret").Limit(1).Scan(ctx, &secret)
	require.Error(t, err)
	require.NotErrorIs(t, err, sql.ErrNoRows)
	require.ErrorContains(t, err, "permission denied")
}
