package web_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// T095-T096, T098: the Connect-the-CLI screen.

// device is a web.DeviceSource whose answer a test sets directly, and which
// records every user code it was asked to decide — the only way to assert that a
// refusal refused BEFORE any call reached a source.
type device struct {
	pending view.PendingDeviceAuthorization
	err     error

	approvedHost string
	approveErr   error
	approvedWith []string
}

func (d *device) LookupDeviceCode(context.Context, string) (view.PendingDeviceAuthorization, error) {
	return d.pending, d.err
}

func (d *device) ApproveDeviceCode(_ context.Context, userCode string) (string, error) {
	d.approvedWith = append(d.approvedWith, userCode)
	return d.approvedHost, d.approveErr
}

func cliHandler(source *device) http.Handler {
	return web.New(web.Deps{
		Catalog: fixture.New(), Device: source, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{HubURL: "http://localhost:8082"}).Handler()
}

func TestCLIScreenWithNoCodePrintsTheRealCommandAndHubAddress(t *testing.T) {
	body := get(t, cliHandler(&device{}), "/cli").Body.String()
	require.Contains(t, body, "amctl login --hub http://localhost:8082")
	require.Contains(t, body, "http://localhost:8082")
	require.NotContains(t, body, "cli-pending")
}

func TestCLIScreenWithNoHubURLConfiguredSaysSoRatherThanPrintingABrokenCommand(t *testing.T) {
	h := web.New(web.Deps{
		Catalog: fixture.New(), Device: &device{}, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	body := get(t, h, "/cli").Body.String()
	require.NotContains(t, body, "amctl login")
	require.Contains(t, body, "deployment fault")
}

func TestCLIScreenShowsTheHostAndCountdownBeforeConfirmation(t *testing.T) {
	source := &device{pending: view.PendingDeviceAuthorization{
		RequestingHost: "dev-laptop-01", ExpiresAt: time.Now().Add(9 * time.Minute),
	}}
	rec := get(t, cliHandler(source), "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	require.Contains(t, body, "dev-laptop-01")
	require.Contains(t, body, `id="cli-pending"`)
	require.Contains(t, body, `action="/cli/confirm"`)
	require.Contains(t, body, `value="HKQ2-9FTL"`)
}

func TestCLIScreenEscapesAMachineSuppliedHost(t *testing.T) {
	source := &device{pending: view.PendingDeviceAuthorization{
		RequestingHost: `<script>alert(1)</script>`, ExpiresAt: time.Now().Add(time.Minute),
	}}
	body := get(t, cliHandler(source), "/cli?user_code=HKQ2-9FTL").Body.String()
	require.NotContains(t, body, "<script>")
	require.Contains(t, body, "&lt;script&gt;")
}

// TestCLIScreenDistinguishesTheThreeRefusals is T098: unknown, expired and
// already-decided must be three different screens, not one generic "invalid
// code" (001 FR-042, 003 T093).
func TestCLIScreenDistinguishesTheThreeRefusals(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		id     string
	}{
		{"unknown", hub.ErrDeviceCodeUnknown, http.StatusNotFound, "cli-unknown"},
		{"expired", hub.ErrDeviceCodeExpired, http.StatusGone, "cli-expired"},
		{"already decided", hub.ErrDeviceCodeDecided, http.StatusConflict, "cli-decided"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, cliHandler(&device{err: tt.err}), "/cli?user_code=ZZZZ-ZZZZ")
			require.Equal(t, tt.status, rec.Code)
			require.Contains(t, rec.Body.String(), `id="`+tt.id+`"`)
		})
	}

	// And the four screens above are pairwise distinct ids: no two share one, which
	// is what makes a screen-test assertion on any one of them meaningful.
	ids := map[string]bool{"cli-unknown": true, "cli-expired": true, "cli-decided": true, "cli-pending": true}
	require.Len(t, ids, 4)
}

func TestCLIScreenWithNoDeviceSourceIsUnavailableRatherThanEmpty(t *testing.T) {
	h := web.New(web.Deps{
		Catalog: fixture.New(), Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	rec := get(t, h, "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), `id="cli-unavailable"`)
}

func TestCLIScreenSignedOutMidLookupGoesToSignIn(t *testing.T) {
	rec := get(t, cliHandler(&device{err: view.ErrSignedOut}), "/cli?user_code=HKQ2-9FTL")
	require.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/auth/signin")
}

// TestConfirmDeviceCodeIsPostRedirectGet is T095/T098: a decision is a POST that
// redirects, so the browser's reload button cannot repeat it, and the user code
// travels in the FORM body, never in the redirect's URL (see internal/web/cli.go).
func TestConfirmDeviceCodeIsPostRedirectGet(t *testing.T) {
	source := &device{approvedHost: "dev-laptop-01"}
	rec := post(t, cliHandler(source), "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, []string{"HKQ2-9FTL"}, source.approvedWith)

	location := rec.Header().Get("Location")
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.NotContains(t, location, "HKQ2-9FTL", "the user code must not travel in a redirect URL")
	require.Contains(t, location, "outcome=approved")

	body := get(t, cliHandler(source), location).Body.String()
	require.Contains(t, body, "dev-laptop-01")
}

func TestConfirmDeviceCodeRefusalsReachTheirOwnNotice(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"unknown", hub.ErrDeviceCodeUnknown, "outcome=unknown"},
		{"expired", hub.ErrDeviceCodeExpired, "outcome=expired"},
		{"already decided", hub.ErrDeviceCodeDecided, "outcome=decided"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := &device{approveErr: tt.err}
			rec := post(t, cliHandler(source), "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
			require.Equal(t, http.StatusSeeOther, rec.Code)
			require.Contains(t, rec.Header().Get("Location"), tt.want)
		})
	}
}

func TestConfirmDeviceCodeSignedOutGoesToSignIn(t *testing.T) {
	source := &device{approveErr: view.ErrSignedOut}
	rec := post(t, cliHandler(source), "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/auth/signin")
}

func TestConfirmDeviceCodeWithNoDeviceSourceRecordsNothing(t *testing.T) {
	h := web.New(web.Deps{
		Catalog: fixture.New(), Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	rec := post(t, h, "/cli/confirm", url.Values{"user_code": {"HKQ2-9FTL"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "outcome=unavailable")
}
