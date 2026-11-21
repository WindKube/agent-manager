package web_test

import (
	"html"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/view"
)

const infrastructureID = "11111111-1111-1111-1111-111111111111"

// orgServer answers the organisation read with sampleOrg rather than the seed.
func orgServer(t *testing.T) (*fakeapi.API, http.Handler) {
	t.Helper()
	api, h := newServer(t)
	api.Data.Organization = sampleOrg()
	return api, h
}

func sampleOrg() apiclient.Organization {
	endpoint := "https://idp.example.invalid/device"
	return apiclient.Organization{
		Provider: apiclient.OrganizationProvider{
			Issuer: "https://idp.example.invalid", ClientId: "am-hub", Scopes: []string{"openid", "profile"},
			DeviceAuthorizationEndpoint: &endpoint,
		},
		Policy: apiclient.OrganizationPolicy{ScanGate: apiclient.OrganizationPolicyScanGateApproval, RequireSignedBundles: true},
		Mappings: []apiclient.GroupRoleMapping{
			{GroupName: "eng-platform", Role: apiclient.GroupRoleMappingRoleCatalogAdmin},
		},
		Categories: []apiclient.OrganizationCategory{
			{Id: uuid.MustParse(infrastructureID), Name: "Infrastructure", Slug: "infrastructure", Count: 3},
		},
	}
}

func TestTheOrganizationScreenRendersTheProviderPolicyMappingsAndCategories(t *testing.T) {
	_, h := orgServer(t)
	body := get(t, h, "/org").Body.String()

	require.Contains(t, body, "https://idp.example.invalid")
	require.Contains(t, body, "am-hub")
	require.Contains(t, body, "eng-platform")
	require.Contains(t, body, "Infrastructure")
	require.Contains(t, body, "infrastructure")
}

// TestTheOrganizationScreenNeverRendersTheClientSecret: "secret" may appear only
// in fixed labels, never inside a form value.
func TestTheOrganizationScreenNeverRendersTheClientSecret(t *testing.T) {
	_, h := orgServer(t)
	rec := get(t, h, "/org")
	body := rec.Body.String()
	require.NotRegexp(t, `(?i)value="[^"]*secret[^"]*"`, body)
	require.Contains(t, body, "Rotate secret")
	require.Contains(t, html.UnescapeString(body), view.SecretRotationReason)
}

// TestARoleThatMayNotAdministerTheOrganizationSeesADistinguishableRefusal: the
// api's refusal must not read as an empty organisation.
func TestARoleThatMayNotAdministerTheOrganizationSeesADistinguishableRefusal(t *testing.T) {
	api, h := orgServer(t)
	api.Data.As(apiclient.ViewerRoleReadOnly)
	api.Fail("getOrganization", http.StatusForbidden)
	rec := get(t, h, "/org")
	require.Equal(t, http.StatusForbidden, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `id="org-refused"`)
	require.NotContains(t, body, "https://idp.example.invalid")
	require.NotContains(t, body, "eng-platform")
}

func TestTheOrganizationScreenTellsSignedOutRefusedAndUnavailableApart(t *testing.T) {
	for _, state := range []struct {
		name    string
		apiCode int
		id      string
		status  int
	}{
		{"signed out", http.StatusUnauthorized, `id="org-signed-out"`, http.StatusOK},
		{"refused", http.StatusForbidden, `id="org-refused"`, http.StatusForbidden},
		{"unavailable", http.StatusServiceUnavailable, `id="org-unavailable"`, http.StatusBadGateway},
	} {
		t.Run(state.name, func(t *testing.T) {
			api, h := orgServer(t)
			api.Fail("getOrganization", state.apiCode)
			rec := get(t, h, "/org")
			require.Equal(t, state.status, rec.Code)
			require.Contains(t, rec.Body.String(), state.id)
		})
	}
}

func TestTheOrganizationScreenEscapesAttackerSuppliedNames(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	api, h := orgServer(t)
	api.Data.Organization.Mappings = []apiclient.GroupRoleMapping{
		{GroupName: "group " + payload, Role: apiclient.GroupRoleMappingRoleCatalogAdmin},
	}
	api.Data.Organization.Categories = []apiclient.OrganizationCategory{{Id: uuid.New(), Name: "cat " + payload, Slug: "cat"}}

	body := get(t, h, "/org").Body.String()

	require.NotContains(t, body, payload, "the organization screen rendered attacker-supplied markup unescaped")
	require.Contains(t, body, "&lt;img src=x onerror=")
}

// TestTheRotateSecretActionIsAlwaysDisabledAndExplainsWhy: rotating is genuinely
// impossible here, so the control never works.
func TestTheRotateSecretActionIsAlwaysDisabledAndExplainsWhy(t *testing.T) {
	_, h := orgServer(t)
	body := html.UnescapeString(get(t, h, "/org").Body.String())
	require.Contains(t, body, "Rotate secret")
	require.Contains(t, body, view.SecretRotationReason)
	require.Contains(t, body, `disabled`)
}

// TestDeleteActionsAreEnabledUnlessACategoryIsInUse: an in-use category is the one
// refusal the screen can know about before submitting.
func TestDeleteActionsAreEnabledUnlessACategoryIsInUse(t *testing.T) {
	api, h := orgServer(t)
	api.Data.Organization.Categories = append(api.Data.Organization.Categories, apiclient.OrganizationCategory{
		Id: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Name: "Unused", Slug: "unused", Count: 0,
	})
	body := get(t, h, "/org").Body.String()

	require.Contains(t, body, `action="/org/mappings/eng-platform/delete"`)
	require.Contains(t, body, `action="/org/categories/22222222-2222-2222-2222-222222222222/delete"`)
	require.Contains(t, body, "still assigned to a package cannot be deleted")
}

// TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi: a post from an
// old page must not reach the api.
func TestAnOrganizationChangeFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	api, h := orgServer(t)
	api.Data.As(apiclient.ViewerRoleReadOnly)

	rec := post(t, h, "/org/policy", url.Values{"scanGate": {"block"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=refused")
	require.Empty(t, api.Calls("createGroupRoleMapping"))
	require.Empty(t, api.Calls("updatePolicy"), "the api was asked to save a policy this role may not change")
}

func TestSavingThePolicyReachesTheApiWithTheSubmittedFields(t *testing.T) {
	api, h := orgServer(t)

	rec := post(t, h, "/org/policy", url.Values{
		"scanGate": {"block"}, "requireSignedBundles": {"on"}, "communityNeedsReview": {"on"},
	})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=policy-saved")
	calls := api.Calls("updatePolicy")
	require.Len(t, calls, 1)
	var policy apiclient.UpdatePolicyRequest
	calls[0].Decode(t, &policy)
	require.Equal(t, apiclient.UpdatePolicyRequestScanGate("block"), policy.ScanGate)
	require.True(t, policy.RequireSignedBundles)
	require.True(t, policy.CommunityNeedsReview)
	require.False(t, policy.RescanOnNewVersion)
}

func TestCreatingAMappingReachesTheApi(t *testing.T) {
	api, h := orgServer(t)

	rec := post(t, h, "/org/mappings", url.Values{"groupName": {"eng-security"}, "role": {"scanner-reviewer"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=mapping-saved")
	calls := api.Calls("createGroupRoleMapping")
	require.Len(t, calls, 1)
	var mapping apiclient.CreateMappingRequest
	calls[0].Decode(t, &mapping)
	require.Equal(t, "eng-security", mapping.GroupName)
	require.Equal(t, apiclient.CreateMappingRequestRoleScannerReviewer, mapping.Role)
}

func TestDeletingAMappingOrCategoryReachesTheApi(t *testing.T) {
	api, h := orgServer(t)

	rec := post(t, h, "/org/mappings/eng-platform/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=mapping-deleted")
	calls := api.Calls("deleteGroupRoleMapping")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/organization/mappings/eng-platform", calls[0].Path)

	rec = post(t, h, "/org/categories/"+infrastructureID+"/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=category-deleted")
	calls = api.Calls("deleteCategory")
	require.Len(t, calls, 1)
	require.Equal(t, "/v1/organization/categories/"+infrastructureID, calls[0].Path)
}

func TestDeletingACategoryStillInUseIsRefused(t *testing.T) {
	api, h := orgServer(t)
	api.Fail("deleteCategory", http.StatusConflict, "category is still assigned to at least one package")

	rec := post(t, h, "/org/categories/"+infrastructureID+"/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "detail=category")
}

func TestRotatingTheSecretAlwaysRefusesWithoutCallingTheApi(t *testing.T) {
	api, h := orgServer(t)

	rec := post(t, h, "/org/identity/secret", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")
	for _, call := range api.Calls("") {
		require.Equal(t, "getViewer", call.Operation, "rotating the secret reached the api")
	}
}

func TestTestingTheConnectionRedirectsAndTheScreenRunsItLive(t *testing.T) {
	api, h := orgServer(t)

	rec := post(t, h, "/org/identity/test", url.Values{})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "tested=1")
	require.Empty(t, api.Calls("testIdentityConnection"),
		"the test action itself must not call the api; only the redirected GET does")

	body := get(t, h, "/org?tested=1").Body.String()
	require.Len(t, api.Calls("testIdentityConnection"), 1)
	require.Contains(t, body, `id="org-connection-ok"`)
}

func TestCreatingACategoryWithADuplicateNameRendersTheApisReason(t *testing.T) {
	api, h := orgServer(t)
	api.Fail("createCategory", http.StatusConflict, "a category with that name already exists")

	rec := post(t, h, "/org/categories", url.Values{"name": {"Infrastructure"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "saved=conflict")

	body := get(t, h, rec.Header().Get("Location")).Body.String()
	require.Contains(t, body, "already exists")
}
