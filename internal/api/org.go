package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The Organization screen's operations.
//
// Every operation here needs the admin role: this screen changes what every
// other identity in the organisation may do, and a screen that hides an
// action is not the same as a request that is refused when it arrives anyway.
var orgAdminRoles = []models.OrgRole{models.OrgRoleCatalogAdmin}

func (s *Server) requireOrgAdmin(ctx context.Context, action string) error {
	principal, _ := PrincipalFrom(ctx)
	return requireRole(principal.Role, action, orgAdminRoles...)
}

// ---- GET /v1/organization ------------------------------------------------------

type getOrganizationOutput struct {
	Body contract.Organization
}

func (s *Server) getOrganization(ctx context.Context, _ *struct{}) (*getOrganizationOutput, error) {
	if err := s.requireOrgAdmin(ctx, "read the organisation's settings"); err != nil {
		return nil, err
	}

	out := contract.Organization{
		Provider: contract.OrganizationProvider{
			Issuer:                      s.deps.Identity.Issuer,
			ClientID:                    s.deps.Identity.ClientID,
			Scopes:                      s.deps.Identity.Scopes,
			DeviceAuthorizationEndpoint: commands.DeviceAuthorizationEndpoint(ctx, s.deps.Identity),
		},
	}
	if out.Provider.Scopes == nil {
		out.Provider.Scopes = []string{}
	}

	policy, err := queries.Policy(ctx, s.deps.DB)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	out.Policy = policy

	if out.Mappings, err = queries.GroupRoleMappings(ctx, s.deps.DB); err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	if out.Categories, err = queries.Categories(ctx, s.deps.DB); err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &getOrganizationOutput{Body: out}, nil
}

// ---- POST /v1/organization/identity/test ---------------------------------------

type testIdentityConnectionOutput struct {
	Body contract.IdentityConnectionTest
}

func (s *Server) testIdentityConnection(ctx context.Context, _ *struct{}) (*testIdentityConnectionOutput, error) {
	if err := s.requireOrgAdmin(ctx, "test the identity provider connection"); err != nil {
		return nil, err
	}
	return &testIdentityConnectionOutput{Body: commands.TestIdentityConnection(ctx, s.deps.Identity)}, nil
}

// ---- POST /v1/organization/identity/secret --------------------------------------

func (s *Server) rotateClientSecret(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := s.requireOrgAdmin(ctx, "rotate the identity provider's client secret"); err != nil {
		return nil, err
	}
	if err := commands.RotateClientSecret(ctx); err != nil {
		return nil, huma.Error409Conflict(err.Error())
	}
	return &struct{}{}, nil
}

// ---- PUT /v1/organization/policy -------------------------------------------------

type updatePolicyInput struct {
	Body contract.UpdatePolicyRequest
}

type updatePolicyOutput struct {
	Body contract.OrganizationPolicy
}

func (s *Server) updatePolicy(ctx context.Context, in *updatePolicyInput) (*updatePolicyOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "change the organisation policy", orgAdminRoles...); err != nil {
		return nil, err
	}

	policy, err := commands.UpdatePolicy(ctx, s.deps.DB, principal, in.Body)
	if err != nil {
		return nil, orgFailure(ctx, err)
	}
	return &updatePolicyOutput{Body: policy}, nil
}

// ---- /v1/organization/mappings[/{id}] --------------------------------------------

type listMappingsOutput struct {
	Body []contract.GroupRoleMapping
}

func (s *Server) listGroupRoleMappings(ctx context.Context, _ *struct{}) (*listMappingsOutput, error) {
	if err := s.requireOrgAdmin(ctx, "read the group-to-role mappings"); err != nil {
		return nil, err
	}
	mappings, err := queries.GroupRoleMappings(ctx, s.deps.DB)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listMappingsOutput{Body: mappings}, nil
}

type createMappingInput struct {
	Body contract.CreateMappingRequest
}

type createMappingOutput struct {
	Body contract.GroupRoleMapping
}

func (s *Server) createGroupRoleMapping(ctx context.Context, in *createMappingInput) (*createMappingOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "map a group to a role", orgAdminRoles...); err != nil {
		return nil, err
	}
	mapping, err := commands.CreateMapping(ctx, s.deps.DB, principal, in.Body)
	if err != nil {
		return nil, orgFailure(ctx, err)
	}
	return &createMappingOutput{Body: mapping}, nil
}

type deleteMappingInput struct {
	GroupName string `path:"id" doc:"The mapped group's name."`
}

func (s *Server) deleteGroupRoleMapping(ctx context.Context, in *deleteMappingInput) (*struct{}, error) {
	if err := s.requireOrgAdmin(ctx, "remove a group-to-role mapping"); err != nil {
		return nil, err
	}
	if err := commands.DeleteMapping(ctx, in.GroupName); err != nil {
		return nil, huma.Error409Conflict(err.Error())
	}
	return &struct{}{}, nil
}

// ---- /v1/organization/categories[/{id}] ------------------------------------------

type listCategoriesOutput struct {
	Body []contract.OrganizationCategory
}

func (s *Server) listCategories(ctx context.Context, _ *struct{}) (*listCategoriesOutput, error) {
	if err := s.requireOrgAdmin(ctx, "read the category vocabulary"); err != nil {
		return nil, err
	}
	categories, err := queries.Categories(ctx, s.deps.DB)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &listCategoriesOutput{Body: categories}, nil
}

type createCategoryInput struct {
	Body contract.CreateCategoryRequest
}

type categoryOutput struct {
	Body contract.OrganizationCategory
}

func (s *Server) createCategory(ctx context.Context, in *createCategoryInput) (*categoryOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "add a category", orgAdminRoles...); err != nil {
		return nil, err
	}
	category, err := commands.CreateCategory(ctx, s.deps.DB, principal, in.Body)
	if err != nil {
		return nil, orgFailure(ctx, err)
	}
	return &categoryOutput{Body: category}, nil
}

type updateCategoryInput struct {
	ID   string `path:"id" format:"uuid"`
	Body contract.UpdateCategoryRequest
}

func (s *Server) updateCategory(ctx context.Context, in *updateCategoryInput) (*categoryOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "rename a category", orgAdminRoles...); err != nil {
		return nil, err
	}
	category, err := commands.UpdateCategory(ctx, s.deps.DB, principal, in.ID, in.Body)
	if err != nil {
		return nil, orgFailure(ctx, err)
	}
	return &categoryOutput{Body: category}, nil
}

type deleteCategoryInput struct {
	ID string `path:"id" format:"uuid"`
}

func (s *Server) deleteCategory(ctx context.Context, in *deleteCategoryInput) (*struct{}, error) {
	if err := s.requireOrgAdmin(ctx, "delete a category"); err != nil {
		return nil, err
	}
	if err := commands.DeleteCategory(ctx, in.ID); err != nil {
		return nil, huma.Error409Conflict(err.Error())
	}
	return &struct{}{}, nil
}

// orgFailure maps this screen's domain errors onto the wire. A validation
// failure is a 422; a name collision is a 409, the same reading
// registerPackage's immutability conflict and findings' rejected-finding
// conflict already use for "well formed, permitted, and refused by the
// resource's own state".
func orgFailure(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, commands.ErrInvalidGate),
		errors.Is(err, commands.ErrInvalidRole),
		errors.Is(err, commands.ErrValidation):
		return huma.Error422UnprocessableEntity(err.Error())
	case errors.Is(err, commands.ErrCategoryExists):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, commands.ErrCategoryNotFound):
		return huma.Error404NotFound(err.Error())
	default:
		return fail(logging.From(ctx), err)
	}
}
