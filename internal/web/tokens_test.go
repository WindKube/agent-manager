package web_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

func TestTokensScreenListsTokensAndOffersReadableProfiles(t *testing.T) {
	api, h := newServer(t)
	rec := get(t, h, "/tokens")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	body := rec.Body.String()
	require.Contains(t, body, "release pipeline")
	require.Contains(t, body, "sync:profile/example/platform-engineer")
	require.Contains(t, body, `action="/tokens/0193f2a0-0000-7000-8000-00000000c1c1/revoke"`)
	for _, p := range api.Data.Profiles {
		require.Contains(t, body, `value="`+p.Slug+`"`, "every readable profile is a scope choice")
	}
	require.Contains(t, body, `name="readCatalog"`)
	require.Contains(t, body, `value="`+time.Now().UTC().Add(90*24*time.Hour).Format(time.DateOnly)+`"`,
		"the expiry defaults to 90 days")
	require.NotContains(t, body, "tokens-secret")
}

func TestCreatingATokenShowsTheSecretOnceWithoutARedirect(t *testing.T) {
	api, h := newServer(t)
	slug := api.Data.Profiles[0].Slug
	expires := time.Now().UTC().AddDate(0, 1, 0).Format(time.DateOnly)

	rec := post(t, h, "/tokens", url.Values{
		"name": {"nightly image"}, "profile": {slug}, "readCatalog": {"1"}, "expires": {expires},
	})
	require.Equal(t, http.StatusOK, rec.Code, "a redirect would have to carry the secret")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Contains(t, rec.Body.String(), `id="tokens-secret"`)
	require.Contains(t, rec.Body.String(), "amst_fake-")

	calls := api.Calls("createServiceToken")
	require.Len(t, calls, 1)
	var sent apiclient.CreateServiceTokenRequest
	calls[0].Decode(t, &sent)
	require.Equal(t, "nightly image", sent.Name)
	require.Equal(t, []string{"sync:profile/" + slug, "read:catalog"}, sent.Scopes)
	require.Equal(t, expires, sent.ExpiresAt.UTC().Format(time.DateOnly))

	again := get(t, h, "/tokens").Body.String()
	require.Contains(t, again, "nightly image")
	require.NotContains(t, again, "amst_fake-", "the secret is never shown twice")
}

func TestATokenWithNoScopeIsRefusedBeforeTheAPI(t *testing.T) {
	api, h := newServer(t)
	rec := post(t, h, "/tokens", url.Values{"name": {"x"}, "expires": {"2030-01-01"}})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "at least one")
	require.Empty(t, api.Calls("createServiceToken"))
}

func TestTheAPIsRefusalIsShownWithTheFormKept(t *testing.T) {
	api, h := newServer(t)
	api.Fail("createServiceToken", http.StatusUnprocessableEntity, `no profile "secret" that this identity can sync`)

	rec := post(t, h, "/tokens", url.Values{
		"name": {"kept name"}, "readCatalog": {"1"}, "expires": {"2030-01-01"},
	})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "that this identity can sync")
	require.Contains(t, body, `value="kept name"`)
	require.NotContains(t, body, "tokens-secret")
}

func TestRevokingRedirectsWithAnOutcome(t *testing.T) {
	api, h := newServer(t)
	id := api.Data.ServiceTokens[0].Id.String()

	rec := post(t, h, "/tokens/"+id+"/revoke", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/tokens?outcome=revoked", rec.Header().Get("Location"))
	require.Equal(t, "/v1/service-tokens/"+id, api.Calls("revokeServiceToken")[0].Path)

	body := get(t, h, "/tokens?outcome=revoked").Body.String()
	require.Contains(t, body, "Revoked.")
	require.NotContains(t, body, `action="/tokens/`+id+`/revoke"`, "a revoked token offers no revoke")

	rec = post(t, h, "/tokens/not-a-uuid/revoke", url.Values{})
	require.Equal(t, "/tokens?outcome=missing", rec.Header().Get("Location"))
}

func TestTokensScreenSaysSoWhenTheAPIIsDown(t *testing.T) {
	api, h := newServer(t)
	api.Fail("listServiceTokens", http.StatusInternalServerError)
	rec := get(t, h, "/tokens")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="tokens-unavailable"`)
}
