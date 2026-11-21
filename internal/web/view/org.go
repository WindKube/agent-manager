package view

import (
	"net/url"
	"slices"
	"strconv"
)

// The vocabulary here is mirrored from internal/api, which the web role may not import; the api stays
// authoritative over a refusal.

// OrganizationProvider is the identity provider settings panel.
type OrganizationProvider struct {
	Issuer                      string
	ClientID                    string
	Scopes                      []string
	DeviceAuthorizationEndpoint string
}

type OrganizationPolicy struct {
	ScanGate              string
	RequireSignedBundles  bool
	CommunityNeedsReview  bool
	RescanOnNewVersion    bool
	AllowPersonalProfiles bool

	PackagesWithoutExpectedSigner int
}

// UnsignableNote counts the packages the signature requirement excludes outright.
func (p OrganizationPolicy) UnsignableNote() string {
	switch p.PackagesWithoutExpectedSigner {
	case 0:
		return ""
	case 1:
		return "1 published package has no expected signer, so it resolves nothing while this is on."
	default:
		return strconv.Itoa(p.PackagesWithoutExpectedSigner) +
			" published packages have no expected signer, so they resolve nothing while this is on."
	}
}

type GroupRoleMapping struct {
	GroupName string
	Role      string
}

type OrganizationCategory struct {
	ID    string
	Name  string
	Slug  string
	Count int
}

type Organization struct {
	Provider   OrganizationProvider
	Policy     OrganizationPolicy
	Mappings   []GroupRoleMapping
	Categories []OrganizationCategory
}

// IdentityConnectionTest is the outcome of the provider panel's "Test connection" action.
type IdentityConnectionTest struct {
	OK     bool
	Detail string
}

var ScanGates = []string{"block", "approval", "warn-with-override"}

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

// OrgRoles is ordered most privileged first, the precedence auth.HighestRole applies.
var OrgRoles = []string{"catalog-admin", "scanner-reviewer", "profile-consumer", "read-only"}

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

// OrgAccess is what this viewer may do on this screen, and why not.
type OrgAccess struct {
	Allowed bool
	Reason  string
}

// OrgAccessFor decides what the viewer may do; an unresolved viewer may do nothing.
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

// PackageDeleteAccessFor is the role gate on deleting a version or package from the catalog.
func PackageDeleteAccessFor(viewer *Viewer) OrgAccess {
	switch {
	case viewer == nil || !viewer.SignedIn:
		return OrgAccess{Reason: "Sign in to delete anything from the catalog."}
	case !viewer.HasRole:
		return OrgAccess{Reason: "Your identity is not mapped to a role yet, so it may not delete " +
			"a package or a version."}
	case !slices.Contains(OrgAdminRoles, viewer.Role):
		return OrgAccess{Reason: "Your role, " + viewer.RoleLabel() + ", may not delete a package " +
			"or a version. This needs the catalog admin role."}
	}
	return OrgAccess{Allowed: true}
}

// SecretRotationReason is why the provider panel's rotate action is always disabled.
const SecretRotationReason = "The identity provider's client secret is this role's own " +
	"environment configuration. This hub holds no provider-side registration for a rotation " +
	"to act on, so nothing here can generate a new one."

// OrgNotice is a save's outcome, carried through the redirect as a token so a link cannot inject prose.
type OrgNotice string

const (
	OrgNoticePolicySaved     OrgNotice = "policy-saved"
	OrgNoticeMappingSaved    OrgNotice = "mapping-saved"
	OrgNoticeMappingDeleted  OrgNotice = "mapping-deleted"
	OrgNoticeCategorySaved   OrgNotice = "category-saved"
	OrgNoticeCategoryRenamed OrgNotice = "category-renamed"
	OrgNoticeCategoryDeleted OrgNotice = "category-deleted"
	OrgNoticeRefused         OrgNotice = "refused"
	OrgNoticeInvalid         OrgNotice = "invalid"
	OrgNoticeConflict        OrgNotice = "conflict"
	OrgNoticeFailed          OrgNotice = "failed"
)

// OrgNoticeFrom maps a save outcome onto the notice banner; detail is the api's explanation for invalid and
// conflict cases.
func OrgNoticeFrom(raw, detail string) *Notice {
	switch OrgNotice(raw) {
	case OrgNoticePolicySaved:
		return &Notice{Tone: "ok", Text: "Policy saved. Every toggle here governs the next " +
			"resolution, registration or scan — nothing already resolved is rewritten."}
	case OrgNoticeMappingSaved:
		return &Notice{Tone: "ok", Text: "Mapping saved. It takes effect at that group's next " +
			"token refresh, with no re-login required."}
	case OrgNoticeMappingDeleted:
		return &Notice{Tone: "ok", Text: "Mapping removed. That group holds no role in this hub " +
			"from its next token refresh."}
	case OrgNoticeCategorySaved:
		return &Notice{Tone: "ok", Text: "Category added. Publishers can choose it at registration " +
			"from now on."}
	case OrgNoticeCategoryRenamed:
		return &Notice{Tone: "ok", Text: "Category renamed."}
	case OrgNoticeCategoryDeleted:
		return &Notice{Tone: "ok", Text: "Category deleted."}
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
	default:
		return nil
	}
}

func MappingDeleteHref(groupName string) string {
	return "/org/mappings/" + url.PathEscape(groupName) + "/delete"
}

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
