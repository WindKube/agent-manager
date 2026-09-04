package view

import "net/url"

// The Organization screen's view models.
//
// Almost nothing here is a rendering decision: a scan gate, a role and a policy
// toggle are canonical vocabulary on the wire and stay that way on the screen.
// What this file adds is access control (OrgAccessFor) and the labels a select
// element needs, mirrored from internal/api's vocabulary the same way ReviewFor
// mirrors it: this role may not import that package, so the vocabulary is
// restated here and the api stays authoritative over a refusal.

// OrganizationProvider is the identity provider settings panel.
type OrganizationProvider struct {
	Issuer                      string
	ClientID                    string
	Scopes                      []string
	DeviceAuthorizationEndpoint string
}

// OrganizationPolicy is the policy form's fields.
type OrganizationPolicy struct {
	ScanGate              string
	RequireSignedBundles  bool
	CommunityNeedsReview  bool
	RescanOnNewVersion    bool
	AllowPersonalProfiles bool
}

// GroupRoleMapping is one row of the mapping table.
type GroupRoleMapping struct {
	GroupName string
	Role      string
}

// OrganizationCategory is one row of the category table.
type OrganizationCategory struct {
	ID    string
	Name  string
	Slug  string
	Count int
}

// Organization is the whole screen's data.
type Organization struct {
	Provider   OrganizationProvider
	Policy     OrganizationPolicy
	Mappings   []GroupRoleMapping
	Categories []OrganizationCategory
}

// IdentityConnectionTest is the outcome of the provider panel's "Test
// connection" action.
type IdentityConnectionTest struct {
	OK     bool
	Detail string
}

// ScanGates is the gate select's options, in the order the design reads them.
var ScanGates = []string{"block", "approval", "warn-with-override"}

// ScanGateLabel is a gate as a person reads it.
func ScanGateLabel(gate string) string {
	switch gate {
	case "block":
		return "Block"
	case "approval":
		return "Require approval"
	case "warn-with-override":
		return "Warn, allow override"
	default:
		return gate
	}
}

// OrgRoles is the role select's options, most privileged first — the same
// precedence auth.HighestRole applies when an identity holds several.
var OrgRoles = []string{"catalog-admin", "scanner-reviewer", "profile-consumer", "read-only"}

// OrgRoleLabel is a role as a person reads it.
func OrgRoleLabel(role string) string {
	switch role {
	case "catalog-admin":
		return "Catalog admin"
	case "scanner-reviewer":
		return "Scanner reviewer"
	case "profile-consumer":
		return "Profile consumer"
	case "read-only":
		return "Read only"
	default:
		return role
	}
}

// OrgAdminRoles mirrors internal/api/org.go's orgAdminRoles.
var OrgAdminRoles = []string{"catalog-admin"}

// OrgAccess is what this viewer may do on this screen, and why not when they
// may not — the same shape Review is on the Scanner screen.
type OrgAccess struct {
	Allowed bool
	Reason  string
}

// OrgAccessFor decides what the viewer may do. There is no default viewer:
// nobody resolved means nobody may administer the organisation.
func OrgAccessFor(viewer *Viewer) OrgAccess {
	if viewer == nil || !viewer.SignedIn {
		return OrgAccess{Reason: "Sign in to administer the organisation."}
	}
	if !viewer.HasRole {
		return OrgAccess{Reason: "Your identity is not mapped to a role yet, so it holds none " +
			"of the organisation's administration."}
	}
	for _, role := range OrgAdminRoles {
		if viewer.Role == role {
			return OrgAccess{Allowed: true}
		}
	}
	return OrgAccess{Reason: "Your role, " + viewer.RoleLabel() + ", cannot administer the " +
		"organisation. This screen needs the catalog admin role."}
}

// SecretRotationReason is why the provider panel's rotate action is always
// disabled. It is stated up front rather than discovered by submitting.
const SecretRotationReason = "The identity provider's client secret is this role's own " +
	"environment configuration. This hub holds no provider-side registration for a rotation " +
	"to act on, so nothing here can generate a new one."

// DeleteMappingReason and DeleteCategoryReason are why those two actions are
// always disabled, for the same reason as SecretRotationReason: this
// deployment's database grants hold no DELETE on either table, and widening one
// is a decision for the project owner, not a request handler's.
const (
	DeleteMappingReason  = "Removing a mapping is not supported by this deployment's database grants."
	DeleteCategoryReason = "Deleting a category is not supported by this deployment's database grants."
)

// OrgNotice is the outcome of a save, said once at the top of the screen —
// the same pattern scanner.go's decisionNotice follows, and for the same
// reason: a token in a redirect's query string, looked up here rather than
// carried, so it cannot be edited into a sentence this hub did not write.
type OrgNotice string

const (
	OrgNoticePolicySaved     OrgNotice = "policy-saved"
	OrgNoticeMappingSaved    OrgNotice = "mapping-saved"
	OrgNoticeCategorySaved   OrgNotice = "category-saved"
	OrgNoticeCategoryRenamed OrgNotice = "category-renamed"
	OrgNoticeRefused         OrgNotice = "refused"
	OrgNoticeInvalid         OrgNotice = "invalid"
	OrgNoticeConflict        OrgNotice = "conflict"
	OrgNoticeFailed          OrgNotice = "failed"
	OrgNoticeUnavailable     OrgNotice = "unavailable"
)

// OrgNoticeFrom maps a save outcome onto the notice banner. detail is the api's
// own explanation for the invalid and conflict cases, already escaped by templ
// on render.
func OrgNoticeFrom(raw, detail string) *Notice {
	switch OrgNotice(raw) {
	case OrgNoticePolicySaved:
		return &Notice{Tone: "ok", Text: "Policy saved. Every toggle here governs the next " +
			"resolution, registration or scan — nothing already resolved is rewritten."}
	case OrgNoticeMappingSaved:
		return &Notice{Tone: "ok", Text: "Mapping saved. It takes effect at that group's next " +
			"token refresh, with no re-login required."}
	case OrgNoticeCategorySaved:
		return &Notice{Tone: "ok", Text: "Category added. Publishers can choose it at registration " +
			"from now on."}
	case OrgNoticeCategoryRenamed:
		return &Notice{Tone: "ok", Text: "Category renamed."}
	case OrgNoticeRefused:
		return &Notice{Tone: "dan", Text: "Your role may not administer the organisation, so " +
			"nothing was saved."}
	case OrgNoticeInvalid:
		text := "That request was not valid, so nothing was saved."
		if detail != "" {
			text = detail
		}
		return &Notice{Tone: "warn", Text: text}
	case OrgNoticeConflict:
		text := "The hub refused that change."
		if detail != "" {
			text = detail
		}
		return &Notice{Tone: "warn", Text: text}
	case OrgNoticeFailed:
		return &Notice{Tone: "dan", Text: "The hub refused that change and saved nothing."}
	case OrgNoticeUnavailable:
		return &Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing was saved."}
	default:
		return nil
	}
}

// MappingDeleteHref links a mapping row's disabled remove form, url.PathEscape'd
// the way PackageHref escapes a package id: a no-op on any group name that could
// exist, insurance against one that should not have been accepted.
func MappingDeleteHref(groupName string) string {
	return "/org/mappings/" + url.PathEscape(groupName) + "/delete"
}

// CategoryRenameHref and CategoryDeleteHref link a category row's two forms.
func CategoryRenameHref(id string) string { return "/org/categories/" + url.PathEscape(id) }

func CategoryDeleteHref(id string) string { return "/org/categories/" + url.PathEscape(id) + "/delete" }

// Org is the whole screen.
type Org struct {
	Data      Organization
	Access    OrgAccess
	Notice    *Notice
	Connected *IdentityConnectionTest

	GovernanceState
}
