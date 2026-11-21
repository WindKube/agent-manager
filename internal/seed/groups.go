package seed

import "agent-manager/internal/store/models"

// These group names must match deploy/local/glauth/glauth.cfg; a mismatch
// silently leaves the user signed in with no role.
const (
	GroupEngPlatform = "eng-platform"
	GroupEngSecurity = "eng-security"
)

// GroupEngAll is a second group shared by both role-holders, so a group-shared
// profile is reachable; it maps to the least-privileged role. GroupContractors
// is vocabulary only.
const (
	GroupEngAll      = "eng-all"
	GroupContractors = "contractors"
)

// GroupUnmapped maps to no role, keeping the no-role screen reachable. It must
// stay absent from GroupRoles.
const GroupUnmapped = "vendors"

// The people in the local directory, matching deploy/local/glauth/glauth.cfg.
// The seed must not write identity rows for them: sign-in provisions those, and
// a seeded row would shadow the real one rather than be adopted.
const (
	DirectoryUserPlatform  = "kwiatrzyk"
	DirectoryEmailPlatform = "kwiatrzyk@example.com"
	DirectoryUserSecurity  = "anowak"
	DirectoryEmailSecurity = "anowak@example.com"
	// In GroupUnmapped.
	DirectoryUserUnmapped  = "dnowicki"
	DirectoryEmailUnmapped = "dnowicki@example.com"
)

// DirectoryPassword is the single copy of the local directory password
// (glauth.cfg holds only its sha256). glauth is reachable only on the compose network.
//
//nolint:gosec // G101: it IS a hard-coded credential, and that is the design.
const DirectoryPassword = "local-only-directory-password"

// DirectoryUser is one person the local directory can authenticate.
type DirectoryUser struct {
	Username string
	Email    string
	// Group is this person's primary group.
	Group string
	// Shared is a second group they are in, or "".
	Shared string
}

// DirectoryUsers lists every directory user, including the unmapped one.
var DirectoryUsers = []DirectoryUser{
	{DirectoryUserPlatform, DirectoryEmailPlatform, GroupEngPlatform, GroupEngAll},
	{DirectoryUserSecurity, DirectoryEmailSecurity, GroupEngSecurity, GroupEngAll},
	{DirectoryUserUnmapped, DirectoryEmailUnmapped, GroupUnmapped, ""},
}

// RoleOf is the role a group resolves to, or "" when none.
func RoleOf(group string) string {
	for _, mapping := range GroupRoles {
		if mapping.Group == group {
			return string(mapping.Role)
		}
	}
	return ""
}

// GroupRoles is the group-to-role mapping in display order.
var GroupRoles = []struct {
	Group string
	Role  models.OrgRole
}{
	{GroupEngPlatform, models.OrgRoleCatalogAdmin},
	{GroupEngSecurity, models.OrgRoleScannerReviewer},
	{GroupEngAll, models.OrgRoleProfileConsumer},
	{GroupContractors, models.OrgRoleReadOnly},
}
