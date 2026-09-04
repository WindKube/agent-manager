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

// organization is an OrganizationSource test double, the Organization-screen
// counterpart of governance_test.go's governance type.
type organization struct {
	data view.Organization
	err  error

	tested   view.IdentityConnectionTest
	testErr  error
	testedAt int

	policy    view.OrganizationPolicy
	policyErr error

	mappingCalls []struct{ group, role string }
	mappingErr   error

	categoryCalls  []string
	categoryErr    error
	renameCalls    []struct{ id, name string }
	renameErr      error
	deleteMapping  []string
	deleteCategory []string
}

func (o *organization) Organization(context.Context) (view.Organization, error) { return o.data, o.err }

func (o *organization) TestIdentityConnection(context.Context) (view.IdentityConnectionTest, error) {
	o.testedAt++
	return o.tested, o.testErr
}

func (o *organization) UpdatePolicy(_ context.Context, in view.OrganizationPolicy) (view.OrganizationPolicy, error) {
	o.policy = in
	return in, o.policyErr
}

func (o *organization) CreateMapping(_ context.Context, groupName, role string) (view.GroupRoleMapping, error) {
	o.mappingCalls = append(o.mappingCalls, struct{ group, role string }{groupName, role})
	return view.GroupRoleMapping{GroupName: groupName, Role: role}, o.mappingErr
}

func (o *organization) DeleteMapping(_ context.Context, groupName string) error {
	o.deleteMapping = append(o.deleteMapping, groupName)
	return errors.New("am_api holds no DELETE grant on group_role_map")
}

func (o *organization) CreateCategory(_ context.Context, name string) (view.OrganizationCategory, error) {
	o.categoryCalls = append(o.categoryCalls, name)
	return view.OrganizationCategory{Name: name}, o.categoryErr
}

func (o *organization) UpdateCategory(_ context.Context, id, name string) (view.OrganizationCategory, error) {
	o.renameCalls = append(o.renameCalls, struct{ id, name string }{id, name})
	return view.OrganizationCategory{ID: id, Name: name}, o.renameErr
}

func (o *organization) DeleteCategory(_ context.Context, id string) error {
	o.deleteCategory = append(o.deleteCategory, id)
	return errors.New("am_api holds no DELETE grant on category")
}

func orgHandler(source *organization, viewers web.ViewerSource) http.Handler {
	return web.New(web.Deps{
		Organization: source, Viewers: viewers, Log: zerolog.Nop(),
	}, web.Options{}).Handler()
}

func sampleOrg() view.Organization {
	return view.Organization{
		Provider: view.OrganizationProvider{
			Issuer: "https://idp.example.invalid", ClientID: "am-hub", Scopes: []string{"openid", "profile"},
			DeviceAuthorizationEndpoint: "https://idp.example.invalid/device",
		},
		Policy: view.OrganizationPolicy{ScanGate: "approval", RequireSignedBundles: true},
		Mappings: []view.GroupRoleMapping{
			{GroupName: "eng-platform", Role: "catalog-admin"},
		},
		Categories: []view.OrganizationCategory{
			{ID: "11111111-1111-1111-1111-111111111111", Name: "Infrastructure", Slug: "infrastructure", Count: 3},
		},
	}
}

func TestTheOrganizationScreenRendersTheProviderPolicyMappingsAndCategories(t *testing.T) {
	body := get(t, orgHandler(&organization{data: sampleOrg()}, fixture.SignedInViewers()), "/org").Body.String()

	require.Contains(t, body, "https://idp.example.invalid")
	require.Contains(t, body, "am-hub")
	require.Contains(t, body, "eng-platform")
	require.Contains(t, body, "Infrastructure")
	require.Contains(t, body, "infrastructure")
}

// TestTheOrganizationScreenNeverRendersTheClientSecret proves view.Organization
// carries no field a secret value could ever reach, so the only two places
// "secret" appears at all are the fixed button label and the fixed explanation
// of why rotation is unavailable — never inside a form value.
func TestTheOrganizationScreenNeverRendersTheClientSecret(t *testing.T) {
	rec := get(t, orgHandler(&organization{data: sampleOrg()}, fixture.SignedInViewers()), "/org")
	body := rec.Body.String()
	require.NotRegexp(t, `(?i)value="[^"]*secret[^"]*"`, body)
	require.Contains(t, body, "Rotate secret")
	require.Contains(t, html.UnescapeString(body), view.SecretRotationReason)
}

// TestARoleThatMayNotAdministerTheOrganizationSeesADistinguishableRefusal
// proves a non-admin role's read is refused by the api (requireOrgAdmin, mapped
// to hub.ErrForbidden here the same way the two governance screens' own
// refusal is), and that refusal is a screen a reader cannot mistake for an
// empty organisation.
func TestARoleThatMayNotAdministerTheOrganizationSeesADistinguishableRefusal(t *testing.T) {
	rec := get(t, orgHandler(&organization{err: hub.ErrForbidden}, readOnlyViewers()), "/org")
	require.Equal(t, http.StatusForbidden, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `id="org-refused"`)
	require.NotContains(t, body, "https://idp.example.invalid")
	require.NotContains(t, body, "eng-platform")
}

func TestTheOrganizationScreenTellsSignedOutRefusedAndUnavailableApart(t *testing.T) {
	for _, state := range []struct {
		name   string
		source *organization
		id     string
		status int
	}{
		{"signed out", &organization{err: view.ErrSignedOut}, `id="org-signed-out"`, http.StatusOK},
		{"refused", &organization{err: hub.ErrForbidden}, `id="org-refused"`, http.StatusForbidden},
		{"unavailable", &organization{err: errBoom}, `id="org-unavailable"`, http.StatusBadGateway},
	} {
		t.Run(state.name, func(t *testing.T) {
			rec := get(t, orgHandler(state.source, fixture.SignedInViewers()), "/org")
			require.Equal(t, state.status, rec.Code)
			require.Contains(t, rec.Body.String(), state.id)
		})
	}
}

// TestTheOrganizationScreenEscapesAttackerSuppliedNames proves a group or
// category name reaches the page only through templ's escaping.
func TestTheOrganizationScreenEscapesAttackerSuppliedNames(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	data := sampleOrg()
	data.Mappings = []view.GroupRoleMapping{{GroupName: "group " + payload, Role: "catalog-admin"}}
	data.Categories = []view.OrganizationCategory{{ID: "1", Name: "cat " + payload, Slug: "cat"}}

	body := get(t, orgHandler(&organization{data: data}, fixture.SignedInViewers()), "/org").Body.String()

	require.NotContains(t, body, payload, "the organization screen rendered attacker-supplied markup unescaped")
	require.Contains(t, body, "&lt;img src=x onerror=")
}

// TestTheRotateSecretActionIsAlwaysDisabledAndExplainsWhy proves the screen
// never offers a working rotation, because rotating is genuinely impossible.
func TestTheRotateSecretActionIsAlwaysDisabledAndExplainsWhy(t *testing.T) {
	body := html.UnescapeString(get(t, orgHandler(&organization{data: sampleOrg()}, fixture.SignedInViewers()), "/org").Body.String())
	require.Contains(t, body, "Rotate secret")
	require.Contains(t, body, view.SecretRotationReason)
	require.Contains(t, body, `disabled`)
}

// TestDeleteActionsAreAlwaysDisabledAndExplainWhy proves no DELETE grant on
// group_role_map or category means the screen never offers a working delete.
func TestDeleteActionsAreAlwaysDisabledAndExplainWhy(t *testing.T) {
	body := html.UnescapeString(get(t, orgHandler(&organization{data: sampleOrg()}, fixture.SignedInViewers()), "/org").Body.String())
	require.Contains(t, body, view.DeleteMappingReason)
	require.Contains(t, body, view.DeleteCategoryReason)
}

// TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi proves a
// post that arrives anyway from an old page must not reach the api.
func TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	source := &organization{data: sampleOrg()}
	h := orgHandler(source, readOnlyViewers())

	rec := post(t, h, "/org/policy", url.Values{"scanGate": {"block"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=refused")
	require.Empty(t, source.mappingCalls)
	require.Equal(t, view.OrganizationPolicy{}, source.policy, "the api was asked to save a policy this role may not change")
}

func TestSavingThePolicyReachesTheApiWithTheSubmittedFields(t *testing.T) {
	source := &organization{data: sampleOrg()}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/policy", url.Values{
		"scanGate": {"block"}, "requireSignedBundles": {"on"}, "communityNeedsReview": {"on"},
	})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=policy-saved")
	require.Equal(t, "block", source.policy.ScanGate)
	require.True(t, source.policy.RequireSignedBundles)
	require.True(t, source.policy.CommunityNeedsReview)
	require.False(t, source.policy.RescanOnNewVersion)
}

func TestCreatingAMappingReachesTheApi(t *testing.T) {
	source := &organization{data: sampleOrg()}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/mappings", url.Values{"groupName": {"eng-security"}, "role": {"scanner-reviewer"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=mapping-saved")
	require.Len(t, source.mappingCalls, 1)
	require.Equal(t, "eng-security", source.mappingCalls[0].group)
	require.Equal(t, "scanner-reviewer", source.mappingCalls[0].role)
}

// TestDeletingAMappingOrCategoryAlwaysRefusesWithoutCallingTheApi mirrors
// rotateSecret: the screen already explained the action is disabled, so a
// hand-crafted post is answered the same way, not by asking the api a question
// whose answer is already known.
func TestDeletingAMappingOrCategoryAlwaysRefusesWithoutCallingTheApi(t *testing.T) {
	source := &organization{data: sampleOrg()}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/mappings/eng-platform/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")
	require.Empty(t, source.deleteMapping, "the delete handler must not call the api's DeleteMapping")

	rec = post(t, h, "/org/categories/11111111-1111-1111-1111-111111111111/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")
	require.Empty(t, source.deleteCategory, "the delete handler must not call the api's DeleteCategory")
}

func TestRotatingTheSecretAlwaysRefusesWithoutCallingTheApi(t *testing.T) {
	source := &organization{data: sampleOrg()}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/identity/secret", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")
}

func TestTestingTheConnectionRedirectsAndTheScreenRunsItLive(t *testing.T) {
	source := &organization{data: sampleOrg(), tested: view.IdentityConnectionTest{OK: true}}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/identity/test", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "tested=1")
	require.Zero(t, source.testedAt, "the test action itself must not call the api; only the redirected GET does")

	body := get(t, h, "/org?tested=1").Body.String()
	require.Equal(t, 1, source.testedAt)
	require.Contains(t, body, `id="org-connection-ok"`)
}

func TestCreatingACategoryWithADuplicateNameRendersTheApisReason(t *testing.T) {
	source := &organization{data: sampleOrg(), categoryErr: errors.New("a category with that name already exists")}
	h := orgHandler(source, fixture.SignedInViewers())

	rec := post(t, h, "/org/categories", url.Values{"name": {"Infrastructure"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")

	body := get(t, h, rec.Header().Get("Location")).Body.String()
	require.Contains(t, body, "already exists")
}
