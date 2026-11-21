package web_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web"
	"agent-manager/internal/web/fakeapi"
)

func cliServer(t *testing.T) (*fakeapi.API, http.Handler) {
	t.Helper()
	return newServerWith(t, web.Options{HubURL: "http://localhost:8082"})
}

func pendingDevice(api *fakeapi.API, host string, expiresIn time.Duration) {
	api.Data.Devices["HKQ2-9FTL"] = apiclient.PendingDeviceAuthorization{
		RequestingHost: host, ExpiresIn: int64(expiresIn.Seconds()),
	}
}

func TestCLIScreenWithNoCodePrintsTheRealCommandAndHubAddress(t *testing.T) {
	_, h := cliServer(t)
	body := get(t, h, "/cli").Body.String()
	require.Contains(t, body, "amctl login --hub http://localhost:8082")
	require.Contains(t, body, "http://localhost:8082")
	require.NotContains(t, body, "cli-pending")
}

func TestCLIScreenWithNoHubURLConfiguredSaysSoRatherThanPrintingABrokenCommand(t *testing.T) {
	_, h := newServer(t)

	body := get(t, h, "/cli").Body.String()
	require.NotContains(t, body, "amctl login")
	require.Contains(t, body, "deployment fault")
}

func TestCLIScreenShowsTheHostAndCountdownBeforeConfirmation(t *testing.T) {
	api, h := cliServer(t)
	pendingDevice(api, "dev-laptop-01", 9*time.Minute)
	rec := get(t, h, "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	require.Contains(t, body, "dev-laptop-01")
	require.Contains(t, body, `id="cli-pending"`)
	require.Contains(t, body, `action="/cli/confirm"`)
	require.Contains(t, body, `value="HKQ2-9FTL"`)
}

func TestCLIScreenEscapesAMachineSuppliedHost(t *testing.T) {
	api, h := cliServer(t)
	pendingDevice(api, `<script>alert(1)</script>`, time.Minute)
	body := get(t, h, "/cli?user_code=HKQ2-9FTL").Body.String()
	require.NotContains(t, body, "<script>")
	require.Contains(t, body, "&lt;script&gt;")
}

func TestCLIScreenDistinguishesTheThreeRefusals(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		id     string
	}{
		{"unknown", http.StatusNotFound, "cli-unknown"},
		{"expired", http.StatusGone, "cli-expired"},
		{"already decided", http.StatusConflict, "cli-decided"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api, h := cliServer(t)
			api.Fail("lookupDeviceCode", tt.status)
			rec := get(t, h, "/cli?user_code=ZZZZ-ZZZZ")
			require.Equal(t, tt.status, rec.Code)
			require.Contains(t, rec.Body.String(), `id="`+tt.id+`"`)
		})
	}

	// The four screens above are pairwise distinct ids.
	ids := map[string]bool{"cli-unknown": true, "cli-expired": true, "cli-decided": true, "cli-pending": true}
	require.Len(t, ids, 4)
}

func TestCLIScreenWhenTheLookupFailsIsUnavailableRatherThanEmpty(t *testing.T) {
	api, h := cliServer(t)
	api.Fail("lookupDeviceCode", http.StatusServiceUnavailable)

	rec := get(t, h, "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="cli-unavailable"`)
}

func TestCLIScreenSignedOutMidLookupGoesToSignIn(t *testing.T) {
	api, h := cliServer(t)
	api.Fail("lookupDeviceCode", http.StatusUnauthorized)
	rec := get(t, h, "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/auth/signin")
}

func TestConfirmDeviceCodeIsPostRedirectGet(t *testing.T) {
	api, h := cliServer(t)
	pendingDevice(api, "dev-laptop-01", 9*time.Minute)
	rec := post(t, h, "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	calls := api.Calls("approveDeviceCode")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/device/authorizations/HKQ2-9FTL/approve", calls[0].Path)

	location := rec.Header().Get("Location")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.NotContains(t, location, "HKQ2-9FTL", "the user code must not travel in a redirect URL")
	require.Contains(t, location, "outcome=approved")

	body := get(t, h, location).Body.String()
	require.Contains(t, body, "dev-laptop-01")
}

func TestConfirmDeviceCodeRefusalsReachTheirOwnNotice(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		want   string
	}{
		{"unknown", http.StatusNotFound, "outcome=unknown"},
		{"expired", http.StatusGone, "outcome=expired"},
		{"already decided", http.StatusConflict, "outcome=decided"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api, h := cliServer(t)
			api.Fail("approveDeviceCode", tt.status)
			rec := post(t, h, "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
			require.Equal(t, http.StatusSeeOther, rec.Code)
			require.Contains(t, rec.Header().Get("Location"), tt.want)
		})
	}
}

func TestConfirmDeviceCodeSignedOutGoesToSignIn(t *testing.T) {
	api, h := cliServer(t)
	api.Fail("approveDeviceCode", http.StatusUnauthorized)
	rec := post(t, h, "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/auth/signin")
}

func TestConfirmDeviceCodeWhenTheApiFailsSaysUnavailable(t *testing.T) {
	api, h := cliServer(t)
	api.Fail("approveDeviceCode", http.StatusServiceUnavailable)

	rec := post(t, h, "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "outcome=unavailable")
}
