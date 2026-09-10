package web_test

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// packageCurator is a PackageCurator test double, this file's counterpart to
// org_test.go's organization type: it records every call so a test can prove
// the api was, or was not, reached.
type packageCurator struct {
	versionResult view.VersionDeleted
	versionErr    error
	versionCalls  [][3]string // namespace, name, version

	packageResult view.PackageDeleted
	packageErr    error
	packageCalls  [][2]string // namespace, name

	visibilityResult view.Package
	visibilityErr    error
	visibilityCalls  [][3]string // namespace, name, visibility
}

// SetVisibility is unexercised by this file's tests, but PackageCurator is
// one interface: a stub missing it stops satisfying web.PackageCurator, and
// Go's structural satisfaction means the failure lands wherever the stub is
// passed rather than here.
func (c *packageCurator) SetVisibility(_ context.Context, namespace, name, visibility string) (view.Package, error) {
	c.visibilityCalls = append(c.visibilityCalls, [3]string{namespace, name, visibility})
	return c.visibilityResult, c.visibilityErr
}

func (c *packageCurator) DeleteVersion(_ context.Context, namespace, name, version string) (view.VersionDeleted, error) {
	c.versionCalls = append(c.versionCalls, [3]string{namespace, name, version})
	return c.versionResult, c.versionErr
}

func (c *packageCurator) DeletePackage(_ context.Context, namespace, name string) (view.PackageDeleted, error) {
	c.packageCalls = append(c.packageCalls, [2]string{namespace, name})
	return c.packageResult, c.packageErr
}

// packageDeleteHandler wires the catalog source too: a package delete's own
// redirect lands on /catalog (its own detail page 404s the instant the
// delete clears latest_version_id), so a test following that redirect needs
// somewhere for it to land.
func packageDeleteHandler(curator web.PackageCurator, viewers web.ViewerSource) http.Handler {
	source := fixture.New()
	return web.New(web.Deps{
		Catalog: source, Packages: source, PackageCurator: curator, Viewers: viewers, Log: zerolog.Nop(),
	}, web.Options{}).Handler()
}

// TestPackageDeleteControlsAreDisabledWithoutTheCatalogAdminRoleAndNeverHidden
// is FR-126's own rule, applied to catalog delete: a viewer who may not
// delete anything sees both buttons, disabled, with the reason on them —
// never a page with the controls missing, which would look like a hub with
// no delete feature at all rather than one this identity may not use.
func TestPackageDeleteControlsAreDisabledWithoutTheCatalogAdminRoleAndNeverHidden(t *testing.T) {
	h := packageDeleteHandler(&packageCurator{}, readOnlyViewers())
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
	h := packageDeleteHandler(&packageCurator{}, fixture.SignedInViewers())
	body := get(t, h, "/packages/example/platform-toolkit").Body.String()

	require.Contains(t, body, `action="/packages/example/platform-toolkit/delete"`)
	require.NotContains(t, body, `disabled aria-disabled="true" title="Your role`)
}

// TestADeleteFromAnIdentityWithoutTheRoleReachesNoApi proves the web role's
// own guard, mirroring TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi:
// a post that arrives anyway, from a stale page or a crafted request, must
// never reach the curator. The api's OWN refusal of the same identity is
// proven independently by internal/api's integration test — this is the
// screen's half of the same guarantee, not a substitute for it.
func TestADeleteFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	curator := &packageCurator{}
	h := packageDeleteHandler(curator, readOnlyViewers())

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
	require.Empty(t, curator.versionCalls)

	rec = post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
	require.Empty(t, curator.packageCalls)
}

// TestDeletingAVersionReachesTheApiAndRedirectsWithAnAcknowledgement proves
// the happy path: an admin's post reaches the curator with the exact
// namespace/name/version the URL named, and the redirect carries a notice a
// reader cannot mistake for the delete having done nothing.
func TestDeletingAVersionReachesTheApiAndRedirectsWithAnAcknowledgement(t *testing.T) {
	curator := &packageCurator{versionResult: view.VersionDeleted{PinnedByProfiles: 2}}
	h := packageDeleteHandler(curator, fixture.SignedInViewers())

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "/packages/example/platform-toolkit")
	require.Contains(t, location, "notice=version-deleted")
	require.Contains(t, location, "version=1.3.0")
	require.Equal(t, [][3]string{{"example", "platform-toolkit", "1.3.0"}}, curator.versionCalls)

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
	curator := &packageCurator{packageResult: view.PackageDeleted{VersionsArchived: 3}}
	h := packageDeleteHandler(curator, fixture.SignedInViewers())

	rec := post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "/catalog")
	require.Contains(t, location, "notice=package-deleted")
	require.Contains(t, location, "id=example%2Fplatform-toolkit")
	require.Equal(t, [][2]string{{"example", "platform-toolkit"}}, curator.packageCalls)

	body := get(t, h, location).Body.String()
	require.Contains(t, body, "example/platform-toolkit")
	require.Contains(t, body, "deleted from the catalog")
}

// TestAPackageDeleteConflictFromTheApiIsShownAsARefusalNotASilentSuccess
// proves the api's own refusal (already withdrawn, say) reaches the screen
// as its own reason rather than a redirect that reads like success.
func TestAPackageDeleteConflictFromTheApiIsShownAsARefusalNotASilentSuccess(t *testing.T) {
	curator := &packageCurator{versionErr: errors.New("version 1.0.0 is already withdrawn")}
	h := packageDeleteHandler(curator, fixture.SignedInViewers())

	rec := post(t, h, "/packages/example/platform-toolkit/versions/1.3.0/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	require.Contains(t, location, "notice=failed")

	body := get(t, h, location).Body.String()
	require.Contains(t, body, "already withdrawn")
}

// TestAForbiddenDeleteFromTheApiIsShownAsARefusal proves the same mapping
// governance_test.go's own screens use: hub.ErrForbidden becomes the
// screen's refusal notice, not a 500 or a silent no-op.
func TestAForbiddenDeleteFromTheApiIsShownAsARefusal(t *testing.T) {
	curator := &packageCurator{packageErr: hub.ErrForbidden}
	h := packageDeleteHandler(curator, fixture.SignedInViewers())

	rec := post(t, h, "/packages/example/platform-toolkit/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "notice=refused")
}
