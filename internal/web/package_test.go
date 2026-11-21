package web_test

import (
	"html"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

// TestPackageDeleteControlsAreDisabledWithoutTheCatalogAdminRoleAndNeverHidden:
// missing controls would read as a hub with no delete feature at all.
func TestPackageDeleteControlsAreDisabledWithoutTheCatalogAdminRoleAndNeverHidden(t *testing.T) {
	api, h := newServer(t)
	api.Data.As(apiclient.ViewerRoleReadOnly)
	body := html.UnescapeString(get(t, h, "/packages/example/platform-toolkit").Body.String())

	require.Contains(t, body, "Delete package")
	require.Contains(t, body, "Delete version")
	require.Contains(t, body, "may not delete a package or a version")
	require.Contains(t, body, "disabled")
	require.Contains(t, body, `aria-disabled="true"`)
}

func TestPackageDeleteControlsAreEnabledForTheCatalogAdminRole(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, `action="/packages/example/platform-toolkit/delete"`)
	require.NotContains(t, html.UnescapeString(body), "may not delete a package or a version")
}

// TestADeleteFromAnIdentityWithoutTheRoleReachesNoApi: a post from a stale page or
// crafted request must not reach the api. The api's own refusal is tested in
// internal/api; this is the screen's half.
func TestADeleteFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	api, h := newServer(t)
	api.Data.As(apiclient.ViewerRoleReadOnly)

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
	require.Empty(t, api.Calls("deleteVersion"))

	rec = post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
	require.Empty(t, api.Calls("deletePackage"))
}

func TestDeletingAVersionReachesTheApiAndRedirectsWithAnAcknowledgement(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "/packages/example/platform-toolkit")
	require.Contains(t, location, "notice=version-deleted")
	require.Contains(t, location, "version=1.3.0")
	calls := api.Calls("deleteVersion")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/packages/example/platform-toolkit/versions/1.3.0", calls[0].Path)

	body := html.UnescapeString(get(t, h, location).Body.String())
	require.Contains(t, body, "1.3.0")
	require.Contains(t, body, "withdrawn from the catalog")
	require.Contains(t, body, "still resolves it")
}

// TestDeletingAPackageReachesTheApiAndRedirectsToTheCatalog: the package page
// 404s once its latest_version_id clears, so the acknowledgement lives on the catalog.
func TestDeletingAPackageReachesTheApiAndRedirectsToTheCatalog(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "/catalog")
	require.Contains(t, location, "notice=package-deleted")
	require.Contains(t, location, "id=example%2Fplatform-toolkit")
	calls := api.Calls("deletePackage")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/packages/example/platform-toolkit", calls[0].Path)

	body := get(t, h, location).Body.String()
	require.Contains(t, body, "example/platform-toolkit")
	require.Contains(t, body, "deleted from the catalog")
}

func TestAPackageDeleteConflictFromTheApiIsShownAsARefusalNotASilentSuccess(t *testing.T) {
	api, h := newServer(t)
	api.Fail("deleteVersion", http.StatusConflict, "version 1.0.0 is already withdrawn")

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "notice=failed")

	body := get(t, h, location).Body.String()
	require.Contains(t, body, "already withdrawn")
}

func TestAForbiddenDeleteFromTheApiIsShownAsARefusal(t *testing.T) {
	api, h := newServer(t)
	api.Fail("deletePackage", http.StatusForbidden)

	rec := post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
}

func TestThePackagePageStatesWhereThePackageComesFrom(t *testing.T) {
	api, h := newServer(t)
	detail := api.Data.Details["example/adr-writer"]
	commit := *detail.Versions[0].SourceCommit
	body := html.UnescapeString(get(t, h, "/packages/example/adr-writer").Body.String())

	require.Contains(t, body, "from github.com/example/architecture-skills @ v3.1.0")
	require.Contains(t, body, `href="https://github.com/example/architecture-skills/commit/`+commit+`"`)
	require.Contains(t, body, ">"+commit[:7]+"</a>")
	require.Contains(t, body, ", subdirectory adr-writer/")
	require.Contains(t, body, `commit <a href="https://github.com/example/architecture-skills/commit/`+commit+`" rel="noopener noreferrer">`+commit[:7]+"</a> · v3.1.0")

	body = html.UnescapeString(get(t, h, "/packages/community/release-toolkit").Body.String())
	require.Contains(t, body, "from releases.octoflow.dev/release-toolkit-1.2.7.tar.gz")
	require.NotContains(t, body, "/commit/")
}

func TestTheTrackUpstreamControlIsOfferedForAGitPackageOnly(t *testing.T) {
	_, h := newServer(t)
	body := html.UnescapeString(get(t, h, "/packages/example/platform-toolkit").Body.String())
	require.Contains(t, body, `id="package-tracking"`)
	require.Contains(t, body, `action="/packages/tracking"`)
	require.Contains(t, body, `name="track" value="on" checked`)
	require.Contains(t, body, `name="pattern" value="v*"`)
	require.Contains(t, body, "last checked 40 minutes ago")

	body = get(t, h, "/packages/community/release-toolkit").Body.String()
	require.NotContains(t, body, `id="package-tracking"`)
}

func TestSavingUpstreamTrackingReachesTheApiAndRedirectsWithANotice(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/packages/tracking", url.Values{
		"id": {"example/adr-writer"}, "track": {"on"}, "pattern": {"release-*"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=tracking-changed")

	calls := api.Calls("setPackageTracking")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/packages/example/adr-writer/tracking", calls[0].Path)
	require.JSONEq(t, `{"trackUpstream":true,"tagPattern":"release-*"}`, string(calls[0].Body))

	body := html.UnescapeString(get(t, h, "/packages/example/adr-writer?notice=tracking-changed").Body.String())
	require.Contains(t, body, "Upstream tracking saved.")
	require.Contains(t, body, `name="pattern" value="release-*"`)
}
