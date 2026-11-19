package web_test

import (
	"html"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
)

// TestPackageDeleteControlsAreDisabledWithoutTheCatalogAdminRoleAndNeverHidden
// is FR-126's own rule, applied to catalog delete: a viewer who may not
// delete anything sees both buttons, disabled, with the reason on them —
// never a page with the controls missing, which would look like a hub with
// no delete feature at all rather than one this identity may not use.
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

// TestPackageDeleteControlsAreEnabledForTheCatalogAdminRole is the other
// half: the same viewer.HasRole && role check, the other way.
func TestPackageDeleteControlsAreEnabledForTheCatalogAdminRole(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, `action="/packages/example/platform-toolkit/delete"`)
	require.NotContains(t, html.UnescapeString(body), "may not delete a package or a version")
}

// TestADeleteFromAnIdentityWithoutTheRoleReachesNoApi proves the web role's
// own guard, mirroring TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi:
// a post that arrives anyway, from a stale page or a crafted request, must
// never reach the api. The api's OWN refusal of the same identity is
// proven independently by internal/api's integration test — this is the
// screen's half of the same guarantee, not a substitute for it.
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

// TestDeletingAVersionReachesTheApiAndRedirectsWithAnAcknowledgement proves
// the happy path: an admin's post reaches the api with the exact
// namespace/name/version the URL named, and the redirect carries a notice a
// reader cannot mistake for the delete having done nothing.
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

// TestDeletingAPackageReachesTheApiAndRedirectsToTheCatalog proves a package
// delete lands on the catalog rather than the package's own page: that page
// 404s the instant its latest_version_id clears, so the acknowledgement has
// to live somewhere else.
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

// TestAPackageDeleteConflictFromTheApiIsShownAsARefusalNotASilentSuccess
// proves the api's own refusal (already withdrawn, say) reaches the screen
// as its own reason rather than a redirect that reads like success.
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

// TestAForbiddenDeleteFromTheApiIsShownAsARefusal proves the same mapping
// governance_test.go's own screens use: the api's 403 becomes the screen's
// refusal notice, not a 500 or a silent no-op.
func TestAForbiddenDeleteFromTheApiIsShownAsARefusal(t *testing.T) {
	api, h := newServer(t)
	api.Fail("deletePackage", http.StatusForbidden)

	rec := post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
}

// TestThePackagePageStatesWhereThePackageComesFrom is the provenance line:
// repository, ref, the shown version's commit linked on its forge, and the
// subdirectory.
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
