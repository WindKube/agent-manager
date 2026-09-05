package seed

import "agent-manager/internal/store/models"

// The identity-provider coupling, in one place. These group names must
// match both the `group_role_map` rows this package writes and the local
// directory fixture (deploy/local/glauth/glauth.cfg); a mismatch fails
// silently, landing the user on a working page with no role.
const (
	GroupEngPlatform = "eng-platform"
	GroupEngSecurity = "eng-security"
)

// GroupEngAll is the second group both role-holding directory users are
// in, making a group-shared profile reachable by signing in. It maps to
// the least-privileged role, so being in it changes nobody's role — the
// third directory user deliberately isn't in it, to keep the no-role
// screen reachable. GroupContractors is vocabulary only.
const (
	GroupEngAll      = "eng-all"
	GroupContractors = "contractors"
)

// GroupUnmapped is a group the directory has that maps to nothing, so
// the signed-in-no-role screen is reachable in a browser, not only a
// test. It must stay absent from GroupRoles — a test asserts that.
const GroupUnmapped = "vendors"

// The two people in the local directory, matching deploy/local/glauth/glauth.cfg.
//
// The seed must not write an identity row for either: their rows are
// created by just-in-time provisioning on first sign-in, and a seeded
// row would not be adopted but shadowed — two identity rows for one
// human, one seeded and one real, both visible on screens that show a
// name the viewer isn't. Nothing fails at run time; a test asserts it.
const (
	DirectoryUserPlatform  = "kwiatrzyk"
	DirectoryEmailPlatform = "kwiatrzyk@example.com"
	DirectoryUserSecurity  = "anowak"
	DirectoryEmailSecurity = "anowak@example.com"
	// The third person, in GroupUnmapped; the same shadowing rule applies.
	DirectoryUserUnmapped  = "dnowicki"
	DirectoryEmailUnmapped = "dnowicki@example.com"
)

// DirectoryPassword is spelled exactly once here since glauth.cfg holds
// only its sha256; the quickstart and dev-hint screen both read this
// constant rather than keep their own copy. A laptop credential only:
// glauth listens on the compose network alone, and the hint that shows it
// renders only when an operator opts in.
//
//nolint:gosec // G101: it IS a hard-coded credential, and that is the design.
const DirectoryPassword = "local-only-directory-password"

// DirectoryUser is one person the local directory can authenticate.
type DirectoryUser struct {
	Username string
	Email    string
	// Group is this person's primary group; resolves no role for the
	// GroupUnmapped one.
	Group string
	// Shared is the second group they're also in, or "" — see GroupEngAll.
	Shared string
}

// DirectoryUsers is the set to walk. All three, including the unmapped
// one: a list of just the two role-holders would leave the third out of
// the collision check in internal/seed/identities_test.go.
var DirectoryUsers = []DirectoryUser{
	{DirectoryUserPlatform, DirectoryEmailPlatform, GroupEngPlatform, GroupEngAll},
	{DirectoryUserSecurity, DirectoryEmailSecurity, GroupEngSecurity, GroupEngAll},
	{DirectoryUserUnmapped, DirectoryEmailUnmapped, GroupUnmapped, ""},
}

// RoleOf is the role a group resolves to, "" when the hub maps it to
// none. A lookup over GroupRoles rather than a second map, so there's one
// answer to the question.
func RoleOf(group string) string {
	for _, mapping := range GroupRoles {
		if mapping.Group == group {
			return string(mapping.Role)
		}
	}
	return ""
}

// GroupRoles is the mapping as the Organization screen lists it. Order
// is presentational only: `group_role_map` is keyed on the group name.
var GroupRoles = []struct {
	Group string
	Role  models.OrgRole
}{
	{GroupEngPlatform, models.OrgRoleCatalogAdmin},
	{GroupEngSecurity, models.OrgRoleScannerReviewer},
	{GroupEngAll, models.OrgRoleProfileConsumer},
	{GroupContractors, models.OrgRoleReadOnly},
}
