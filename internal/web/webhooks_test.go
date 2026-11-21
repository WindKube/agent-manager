package web_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

const seededWebhook = "0193f2a0-0000-7000-8000-0000000000e1"

func TestWebhooksScreenListsWebhooksAndOffersEveryEventType(t *testing.T) {
	api, h := newServer(t)
	rec := get(t, h, "/webhooks")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	body := rec.Body.String()
	require.Contains(t, body, "security channel")
	require.Contains(t, body, "https://hooks.example.com/agent-manager")
	require.Contains(t, body, "last HTTP 200 at")
	require.Contains(t, body, `action="/webhooks/`+seededWebhook+`/enabled"`)
	require.Contains(t, body, `action="/webhooks/`+seededWebhook+`/secret"`)
	require.Contains(t, body, `action="/webhooks/`+seededWebhook+`/delete"`)
	for _, eventType := range api.Data.WebhookEventTypes {
		require.Contains(t, body, `name="eventType" value="`+eventType+`"`)
	}
	require.NotContains(t, body, "webhooks-secret")
	require.NotContains(t, body, `id="webhook-deliveries"`, "no delivery log until one is opened")
}

func TestOpeningAWebhookShowsItsRecentDeliveries(t *testing.T) {
	api, h := newServer(t)
	body := get(t, h, "/webhooks?webhook="+seededWebhook).Body.String()
	require.Contains(t, body, `id="webhook-deliveries"`)
	require.Contains(t, body, "HTTP 503")
	require.Contains(t, body, "upstream busy")
	require.Len(t, api.Calls("listWebhookDeliveries"), 1)

	body = get(t, h, "/webhooks?webhook=0193f2a0-0000-7000-8000-00000000dead").Body.String()
	require.NotContains(t, body, `id="webhook-deliveries"`)
	require.Len(t, api.Calls("listWebhookDeliveries"), 1, "an unlisted id is never asked for")
}

func TestCreatingAWebhookShowsTheSecretOnceWithoutARedirect(t *testing.T) {
	api, h := newServer(t)
	rec := post(t, h, "/webhooks", url.Values{
		"name": {"pager"}, "url": {"https://hooks.example.com/pager"},
		"eventType": {"waiver.expired", "scan.completed"}, "namespaces": {"platform, security"},
	})
	require.Equal(t, http.StatusOK, rec.Code, "a redirect would have to carry the secret")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Contains(t, rec.Body.String(), `id="webhooks-secret"`)
	require.Contains(t, rec.Body.String(), "whsec_fake-")

	calls := api.Calls("createWebhook")
	require.Len(t, calls, 1)
	var sent apiclient.CreateWebhookRequest
	calls[0].Decode(t, &sent)
	require.Equal(t, "pager", sent.Name)
	require.Equal(t, "https://hooks.example.com/pager", sent.Url)
	require.Equal(t, []apiclient.CreateWebhookRequestEventTypes{"waiver.expired", "scan.completed"}, sent.EventTypes)
	require.Equal(t, []string{"platform", "security"}, *sent.Namespaces)

	again := get(t, h, "/webhooks").Body.String()
	require.Contains(t, again, "pager")
	require.NotContains(t, again, "whsec_fake-", "the secret is never shown twice")
}

func TestAWebhookWithNoEventTypeIsRefusedBeforeTheAPI(t *testing.T) {
	api, h := newServer(t)
	rec := post(t, h, "/webhooks", url.Values{"name": {"x"}, "url": {"https://hooks.example.com/x"}})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "at least one event type")
	require.Empty(t, api.Calls("createWebhook"))
}

func TestTheAPIsWebhookRefusalIsShownWithTheFormKept(t *testing.T) {
	api, h := newServer(t)
	api.Fail("createWebhook", http.StatusUnprocessableEntity, "the URL must be https")

	rec := post(t, h, "/webhooks", url.Values{
		"name": {"kept name"}, "url": {"http://hooks.example.com"}, "eventType": {"*"},
	})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "the URL must be https")
	require.Contains(t, body, `value="kept name"`)
	require.Contains(t, body, `value="*" checked`)
	require.NotContains(t, body, "webhooks-secret")
}

func TestRotatingAWebhookSecretShowsTheNewOneOnce(t *testing.T) {
	api, h := newServer(t)
	rec := post(t, h, "/webhooks/"+seededWebhook+"/secret", url.Values{})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Contains(t, rec.Body.String(), "Signing secret for security channel")
	require.Contains(t, rec.Body.String(), "whsec_rotated-")
	require.Equal(t, "/v1/webhooks/"+seededWebhook+"/secret", api.Calls("rotateWebhookSecret")[0].Path)

	rec = post(t, h, "/webhooks/not-a-uuid/secret", url.Values{})
	require.Equal(t, "/webhooks?outcome=missing", rec.Header().Get("Location"))
}

func TestDisablingEnablingAndDeletingRedirectWithAnOutcome(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/webhooks/"+seededWebhook+"/enabled", url.Values{"enabled": {"0"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/webhooks?outcome=disabled", rec.Header().Get("Location"))
	var sent apiclient.UpdateWebhookRequest
	api.Calls("updateWebhook")[0].Decode(t, &sent)
	require.False(t, *sent.Enabled)
	require.Nil(t, sent.Name, "toggling sends nothing but enabled")

	body := get(t, h, "/webhooks?outcome=disabled").Body.String()
	require.Contains(t, body, "Disabled.")
	require.Contains(t, body, ">Enable</button>")

	rec = post(t, h, "/webhooks/"+seededWebhook+"/enabled", url.Values{"enabled": {"1"}})
	require.Equal(t, "/webhooks?outcome=enabled", rec.Header().Get("Location"))

	rec = post(t, h, "/webhooks/"+seededWebhook+"/delete", url.Values{})
	require.Equal(t, "/webhooks?outcome=deleted", rec.Header().Get("Location"))
	require.Equal(t, "/v1/webhooks/"+seededWebhook, api.Calls("deleteWebhook")[0].Path)
	require.NotContains(t, get(t, h, "/webhooks").Body.String(), `id="webhook-`+seededWebhook+`"`)

	rec = post(t, h, "/webhooks/"+seededWebhook+"/delete", url.Values{})
	require.Equal(t, "/webhooks?outcome=missing", rec.Header().Get("Location"))
}

func TestAWebhookDisabledByTheHubSaysWhy(t *testing.T) {
	api, h := newServer(t)
	api.Data.Webhooks[0].Enabled = false
	api.Data.Webhooks[0].DisabledReason = ptrTo("the receiver answered 410 Gone")
	require.Contains(t, get(t, h, "/webhooks").Body.String(), "disabled: the receiver answered 410 Gone")
}

func TestWebhooksScreenRefusesARoleThatMayNotManageThem(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listWebhooks", http.StatusForbidden)
	rec := get(t, h, "/webhooks")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), `id="webhooks-refused"`)
	require.NotContains(t, rec.Body.String(), "Create webhook")
}

func TestWebhooksScreenSaysSoWhenTheAPIIsDown(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listWebhooks", http.StatusInternalServerError)
	rec := get(t, h, "/webhooks")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="webhooks-unavailable"`)
}
