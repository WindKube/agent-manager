package fixture

import (
	"context"

	"agent-manager/internal/web/view"
)

// The Organization screen's stand-in. It implements web.OrganizationSource
// read-only, the same way governance.go's fixture implements no web.Reviewer:
// a screen test exercises the mutation forms against a source that genuinely
// cannot perform one.

// Organization implements the read half of web.OrganizationSource.
func (c *Catalog) Organization(context.Context) (view.Organization, error) {
	return view.Organization{
		Provider: view.OrganizationProvider{
			Issuer:                      "https://idp.fixture.invalid",
			ClientID:                    "am-hub-fixture",
			Scopes:                      []string{"openid", "profile", "email", "groups"},
			DeviceAuthorizationEndpoint: "https://idp.fixture.invalid/device",
		},
		Policy: view.OrganizationPolicy{
			ScanGate: "approval", RequireSignedBundles: true, CommunityNeedsReview: true,
		},
		Mappings: []view.GroupRoleMapping{
			{GroupName: "eng-platform", Role: "catalog-admin"},
			{GroupName: "eng-security", Role: "scanner-reviewer"},
		},
		Categories: []view.OrganizationCategory{
			{ID: "d290f1ee-6c54-4b01-90e6-d701748f0851", Name: "Infrastructure", Slug: "infrastructure", Count: 4},
			{ID: "e290f1ee-6c54-4b01-90e6-d701748f0852", Name: "Documentation", Slug: "documentation", Count: 1},
		},
	}, nil
}

var errFixtureReadOnly = errFixture("this fixture answers no organisation write; see this file's comment")

type errFixture string

func (e errFixture) Error() string { return string(e) }

func (c *Catalog) TestIdentityConnection(context.Context) (view.IdentityConnectionTest, error) {
	return view.IdentityConnectionTest{OK: true}, nil
}

func (c *Catalog) UpdatePolicy(context.Context, view.OrganizationPolicy) (view.OrganizationPolicy, error) {
	return view.OrganizationPolicy{}, errFixtureReadOnly
}

func (c *Catalog) CreateMapping(context.Context, string, string) (view.GroupRoleMapping, error) {
	return view.GroupRoleMapping{}, errFixtureReadOnly
}

func (c *Catalog) DeleteMapping(context.Context, string) error { return errFixtureReadOnly }

func (c *Catalog) CreateCategory(context.Context, string) (view.OrganizationCategory, error) {
	return view.OrganizationCategory{}, errFixtureReadOnly
}

func (c *Catalog) UpdateCategory(context.Context, string, string) (view.OrganizationCategory, error) {
	return view.OrganizationCategory{}, errFixtureReadOnly
}

func (c *Catalog) DeleteCategory(context.Context, string) error { return errFixtureReadOnly }
