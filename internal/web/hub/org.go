package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The Organization screen's door to the api.
//
// Returns view types directly, the way hub/package.go does: this screen holds
// almost no rendering decisions of its own — a role name and a scan gate are
// canonical vocabulary either way — so a second, hub-owned copy of the same
// fields would only be a struct a handler then copies out of.

// Organization reads GET /v1/organization.
func (c *Client) Organization(ctx context.Context) (view.Organization, error) {
	resp, err := c.api.GetOrganizationWithResponse(ctx)
	if err != nil {
		return view.Organization{}, fmt.Errorf("read the organisation's settings: %w", err)
	}
	if resp.JSON200 == nil {
		return view.Organization{}, fmt.Errorf("read the organisation's settings: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return organizationOf(resp.JSON200), nil
}

func organizationOf(body *apiclient.Organization) view.Organization {
	out := view.Organization{
		Provider: view.OrganizationProvider{
			Issuer:                      body.Provider.Issuer,
			ClientID:                    body.Provider.ClientId,
			Scopes:                      body.Provider.Scopes,
			DeviceAuthorizationEndpoint: deref(body.Provider.DeviceAuthorizationEndpoint),
		},
		Policy: policyOf(&body.Policy),
	}
	for _, mapping := range body.Mappings {
		out.Mappings = append(out.Mappings, view.GroupRoleMapping{
			GroupName: mapping.GroupName, Role: string(mapping.Role),
		})
	}
	for _, category := range body.Categories {
		out.Categories = append(out.Categories, view.OrganizationCategory{
			ID: category.Id.String(), Name: category.Name, Slug: category.Slug,
			Count: int(category.Count),
		})
	}
	return out
}

func policyOf(body *apiclient.OrganizationPolicy) view.OrganizationPolicy {
	return view.OrganizationPolicy{
		ScanGate:              string(body.ScanGate),
		RequireSignedBundles:  body.RequireSignedBundles,
		CommunityNeedsReview:  body.CommunityNeedsReview,
		RescanOnNewVersion:    body.RescanOnNewVersion,
		AllowPersonalProfiles: body.AllowPersonalProfiles,
	}
}

// TestIdentityConnection posts POST /v1/organization/identity/test.
func (c *Client) TestIdentityConnection(ctx context.Context) (view.IdentityConnectionTest, error) {
	resp, err := c.api.TestIdentityConnectionWithResponse(ctx)
	if err != nil {
		return view.IdentityConnectionTest{}, fmt.Errorf("test the identity connection: %w", err)
	}
	if resp.JSON200 == nil {
		return view.IdentityConnectionTest{}, fmt.Errorf("test the identity connection: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return view.IdentityConnectionTest{OK: resp.JSON200.Ok, Detail: deref(resp.JSON200.Detail)}, nil
}

// UpdatePolicy puts PUT /v1/organization/policy.
func (c *Client) UpdatePolicy(ctx context.Context, in view.OrganizationPolicy) (view.OrganizationPolicy, error) {
	resp, err := c.api.UpdatePolicyWithResponse(ctx, apiclient.UpdatePolicyRequest{
		ScanGate:              apiclient.UpdatePolicyRequestScanGate(in.ScanGate),
		RequireSignedBundles:  in.RequireSignedBundles,
		CommunityNeedsReview:  in.CommunityNeedsReview,
		RescanOnNewVersion:    in.RescanOnNewVersion,
		AllowPersonalProfiles: in.AllowPersonalProfiles,
	})
	if err != nil {
		return view.OrganizationPolicy{}, fmt.Errorf("update the organisation policy: %w", err)
	}
	if resp.JSON200 == nil {
		return view.OrganizationPolicy{}, fmt.Errorf("update the organisation policy: %w",
			orgError(resp.HTTPResponse, resp.Body))
	}
	return policyOf(resp.JSON200), nil
}

// CreateMapping posts POST /v1/organization/mappings.
func (c *Client) CreateMapping(ctx context.Context, groupName, role string) (view.GroupRoleMapping, error) {
	resp, err := c.api.CreateGroupRoleMappingWithResponse(ctx, apiclient.CreateMappingRequest{
		GroupName: groupName, Role: apiclient.CreateMappingRequestRole(role),
	})
	if err != nil {
		return view.GroupRoleMapping{}, fmt.Errorf("map group %q: %w", groupName, err)
	}
	if resp.JSON200 == nil {
		return view.GroupRoleMapping{}, fmt.Errorf("map group %q: %w", groupName,
			orgError(resp.HTTPResponse, resp.Body))
	}
	return view.GroupRoleMapping{GroupName: resp.JSON200.GroupName, Role: string(resp.JSON200.Role)}, nil
}

// DeleteMapping deletes DELETE /v1/organization/mappings/{id}.
func (c *Client) DeleteMapping(ctx context.Context, groupName string) error {
	resp, err := c.api.DeleteGroupRoleMappingWithResponse(ctx, groupName)
	if err != nil {
		return fmt.Errorf("remove mapping %q: %w", groupName, err)
	}
	return orgError(resp.HTTPResponse, resp.Body)
}

// CreateCategory posts POST /v1/organization/categories.
func (c *Client) CreateCategory(ctx context.Context, name string) (view.OrganizationCategory, error) {
	resp, err := c.api.CreateCategoryWithResponse(ctx, apiclient.CreateCategoryRequest{Name: name})
	if err != nil {
		return view.OrganizationCategory{}, fmt.Errorf("add category %q: %w", name, err)
	}
	if resp.JSON200 == nil {
		return view.OrganizationCategory{}, fmt.Errorf("add category %q: %w", name,
			orgError(resp.HTTPResponse, resp.Body))
	}
	return view.OrganizationCategory{
		ID: resp.JSON200.Id.String(), Name: resp.JSON200.Name, Slug: resp.JSON200.Slug,
	}, nil
}

// UpdateCategory patches PATCH /v1/organization/categories/{id}.
func (c *Client) UpdateCategory(ctx context.Context, id, name string) (view.OrganizationCategory, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.OrganizationCategory{}, view.ErrNotFound
	}

	resp, err := c.api.UpdateCategoryWithResponse(ctx, parsed, apiclient.UpdateCategoryRequest{Name: name})
	if err != nil {
		return view.OrganizationCategory{}, fmt.Errorf("rename category %s: %w", id, err)
	}
	if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound {
		return view.OrganizationCategory{}, view.ErrNotFound
	}
	if resp.JSON200 == nil {
		return view.OrganizationCategory{}, fmt.Errorf("rename category %s: %w", id,
			orgError(resp.HTTPResponse, resp.Body))
	}
	return view.OrganizationCategory{
		ID: resp.JSON200.Id.String(), Name: resp.JSON200.Name, Slug: resp.JSON200.Slug,
	}, nil
}

// DeleteCategory deletes DELETE /v1/organization/categories/{id}. Refuses with
// a 409 when a package still carries the category.
func (c *Client) DeleteCategory(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.ErrNotFound
	}
	resp, err := c.api.DeleteCategoryWithResponse(ctx, parsed)
	if err != nil {
		return fmt.Errorf("delete category %s: %w", id, err)
	}
	return orgError(resp.HTTPResponse, resp.Body)
}

// orgError adds this screen's validation and conflict cases to governanceError,
// with the api's own detail text — the reason a role check fails is fixed
// vocabulary, but the reason a policy save or a mapping is refused is specific
// to what was submitted, and the screen has to say which.
func orgError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnprocessableEntity, http.StatusConflict, http.StatusNotFound:
			var problem apiclient.Error
			if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
				return errors.New(*problem.Detail)
			}
		}
	}
	return governanceError(resp, body)
}
