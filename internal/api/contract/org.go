package contract

// The Organization screen's surface.
//
// getOrganization never carries the client secret, not even a masked or
// length-revealing stand-in: the provider section below has no field a secret
// could occupy.

// OrganizationProvider is the identity provider settings panel. It is read
// from the api's own OIDC configuration and, for the device endpoint, from
// that provider's discovery document — never stored.
type OrganizationProvider struct {
	Issuer   string   `json:"issuer" doc:"The trust anchor every ID token is checked against." example:"http://dex:5556/dex"`
	ClientID string   `json:"clientId" example:"agent-manager-web"`
	Scopes   []string `json:"scopes" doc:"Requested at every sign-in." example:"openid,profile,email,groups"`
	// DeviceAuthorizationEndpoint is read from the provider's discovery document
	// at request time, not cached at boot: an operator who repoints the issuer
	// sees the new provider's endpoint on the next load rather than a stale one.
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint,omitempty" doc:"Absent when discovery could not be completed." example:"http://dex:5556/dex/device/code"`
}

// OrganizationPolicy is org_policy's mutable half, and every toggle here
// changes downstream behaviour, not merely its own row.
type OrganizationPolicy struct {
	ScanGate              string `json:"scanGate" enum:"block,approval,warn-with-override" doc:"What a flagged verdict does to the next resolution."`
	RequireSignedBundles  bool   `json:"requireSignedBundles" doc:"A version with no recorded signature reference is excluded from every resolution while this is set."`
	CommunityNeedsReview  bool   `json:"communityNeedsReview" doc:"A version from a non-verified publisher is flagged for review rather than becoming immediately distributable."`
	RescanOnNewVersion    bool   `json:"rescanOnNewVersion" doc:"Publishing a version rescans the package's other versions under the running rule pack."`
	AllowPersonalProfiles bool   `json:"allowPersonalProfiles"`
}

// GroupRoleMapping is one row of group_role_map.
type GroupRoleMapping struct {
	GroupName string `json:"groupName" example:"security-team"`
	Role      string `json:"role" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only"`
}

// OrganizationCategory is one curated category with its usage count. Tags are
// never here: they stay manifest-derived.
type OrganizationCategory struct {
	ID    string `json:"id" format:"uuid"`
	Name  string `json:"name" example:"Productivity"`
	Slug  string `json:"slug" example:"productivity"`
	Count int    `json:"count" doc:"Packages currently carrying this category." example:"3"`
}

// Organization is the whole screen's read (getOrganization).
type Organization struct {
	Provider   OrganizationProvider   `json:"provider"`
	Policy     OrganizationPolicy     `json:"policy"`
	Mappings   []GroupRoleMapping     `json:"mappings"`
	Categories []OrganizationCategory `json:"categories"`
}

// IdentityConnectionTest is testIdentityConnection's answer: a real OIDC
// discovery and JWKS fetch against the configured issuer, never a stored value
// echoed back.
type IdentityConnectionTest struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty" doc:"The failure reason, in the terms discovery or the JWKS fetch gave. Absent on success."`
}

// UpdatePolicyRequest is the body of PUT /v1/organization/policy.
type UpdatePolicyRequest struct {
	ScanGate              string `json:"scanGate" enum:"block,approval,warn-with-override"`
	RequireSignedBundles  bool   `json:"requireSignedBundles"`
	CommunityNeedsReview  bool   `json:"communityNeedsReview"`
	RescanOnNewVersion    bool   `json:"rescanOnNewVersion"`
	AllowPersonalProfiles bool   `json:"allowPersonalProfiles"`
}

// CreateMappingRequest is the body of POST /v1/organization/mappings.
type CreateMappingRequest struct {
	GroupName string `json:"groupName" minLength:"1" maxLength:"200" example:"security-team"`
	Role      string `json:"role" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only"`
}

// CreateCategoryRequest is the body of POST /v1/organization/categories.
type CreateCategoryRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"100" example:"Productivity"`
}

// UpdateCategoryRequest is the body of PATCH /v1/organization/categories/{id}.
type UpdateCategoryRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"100" example:"Productivity tools"`
}
