package contract

// OrganizationProvider is the identity provider settings panel; it never
// carries the client secret, not even a masked stand-in.
type OrganizationProvider struct {
	Issuer   string   `json:"issuer" doc:"The trust anchor every ID token is checked against." example:"http://dex:5556/dex"`
	ClientID string   `json:"clientId" example:"agent-manager-web"`
	Scopes   []string `json:"scopes" doc:"Requested at every sign-in." example:"openid,profile,email,groups"`
	// DeviceAuthorizationEndpoint is read from the provider's discovery
	// document at request time, not cached at boot.
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint,omitempty" doc:"Absent when discovery could not be completed." example:"http://dex:5556/dex/device/code"`
}

type OrganizationPolicy struct {
	ScanGate              string `json:"scanGate" enum:"block,approval,warn-with-override" doc:"What a flagged verdict does to the next resolution."`
	RequireSignedBundles  bool   `json:"requireSignedBundles" doc:"A version with no recorded signature reference is excluded from every resolution while this is set."`
	CommunityNeedsReview  bool   `json:"communityNeedsReview" doc:"A version from a non-verified publisher is flagged for review rather than becoming immediately distributable."`
	RescanOnNewVersion    bool   `json:"rescanOnNewVersion" doc:"Publishing a version rescans the package's other versions under the running rule pack."`
	AllowPersonalProfiles bool   `json:"allowPersonalProfiles"`
}

type GroupRoleMapping struct {
	GroupName string `json:"groupName" example:"security-team"`
	Role      string `json:"role" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only"`
}

type OrganizationCategory struct {
	ID    string `json:"id" format:"uuid"`
	Name  string `json:"name" example:"Productivity"`
	Slug  string `json:"slug" example:"productivity"`
	Count int    `json:"count" doc:"Packages currently carrying this category." example:"3"`
}

type Organization struct {
	Provider   OrganizationProvider   `json:"provider"`
	Policy     OrganizationPolicy     `json:"policy"`
	Mappings   []GroupRoleMapping     `json:"mappings"`
	Categories []OrganizationCategory `json:"categories"`
}

// IdentityConnectionTest is a real OIDC discovery and JWKS fetch, never a
// stored value echoed back.
type IdentityConnectionTest struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty" doc:"The failure reason, in the terms discovery or the JWKS fetch gave. Absent on success."`
}

type UpdatePolicyRequest struct {
	ScanGate              string `json:"scanGate" enum:"block,approval,warn-with-override"`
	RequireSignedBundles  bool   `json:"requireSignedBundles"`
	CommunityNeedsReview  bool   `json:"communityNeedsReview"`
	RescanOnNewVersion    bool   `json:"rescanOnNewVersion"`
	AllowPersonalProfiles bool   `json:"allowPersonalProfiles"`
}

type CreateMappingRequest struct {
	GroupName string `json:"groupName" minLength:"1" maxLength:"200" example:"security-team"`
	Role      string `json:"role" enum:"catalog-admin,scanner-reviewer,profile-consumer,read-only"`
}

type CreateCategoryRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"100" example:"Productivity"`
}

type UpdateCategoryRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"100" example:"Productivity tools"`
}
