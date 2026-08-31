package seed

import "agent-manager/internal/store/models"

// The identity-provider coupling, in one place.
//
// GroupEngPlatform and GroupEngSecurity are the two group names that must appear
// in BOTH the `group_role_map` rows this package writes AND the local directory
// fixture — `deploy/local/glauth/glauth.cfg`, whose group names Dex passes
// through into the `groups` claim (003 T018/T019, contracts/local-identity.md).
// Anything that generates or checks that fixture must read these constants
// rather than spell the names again.
//
// A mismatch is the hardest failure in the local stack to diagnose, because
// nothing fails: discovery answers, the password is accepted, the token carries a
// `groups` claim, the session row is written, and the resolve statement's
// `group_name = any (i.groups)` simply matches nothing. The user lands on a
// working page with no role and no error anywhere.
const (
	GroupEngPlatform = "eng-platform"
	GroupEngSecurity = "eng-security"
)

// The other two names the design's Organization screen shows. They are not part
// of the identity-provider coupling above — the local directory has two people —
// but they are what a membership row and the design's audit trail point at, so
// the vocabulary is seeded whole.
const (
	GroupEngAll      = "eng-all"
	GroupContractors = "contractors"
)

// The two people in the local directory, on this same surface and for the same
// reason: `deploy/local/glauth/glauth.cfg` spells these usernames and mails, and
// Dex hands the mail through as the `email` claim.
//
// THE SEED MUST NOT WRITE AN IDENTITY ROW FOR EITHER OF THEM. Their rows are
// created by just-in-time provisioning on first sign-in, which is this feature's
// whole model (FR-109). A seeded row cannot anticipate them: Dex's `sub` is an
// opaque encoding of the connector and the directory id, and `commands.Login`
// upserts `on conflict (subject)` — deliberately so, because matching identities
// on email would let a re-issued address take over an account. So a seeded row
// for a directory user does not get adopted at sign-in, it gets SHADOWED: two
// identity rows for one human, one holding the seeded history and one the person
// actually acting. The audit log and the sharing panel then show a name the
// viewer cannot be, which is the hard-coded viewer chip this feature exists to
// delete (SC-106) moved from a templ file into the database.
//
// Nothing fails at run time when that comes back, so a test does:
// TestNoSeededIdentityBelongsToSomeoneWhoCanSignIn.
//
// The bind account glauth also defines is absent here on purpose. It carries no
// `mail`, and Dex's user search is `username: mail`, so it can never authenticate
// a person and can never collide with a seeded row.
const (
	DirectoryUserPlatform  = "kwiatrzyk"
	DirectoryEmailPlatform = "kwiatrzyk@example.com"
	DirectoryUserSecurity  = "anowak"
	DirectoryEmailSecurity = "anowak@example.com"
)

// DirectoryUsers is the set to walk — generating the fixture, or checking nothing
// collides with it. The group is the one each user resolves a role through, and
// SC-104 turns on those two being different.
var DirectoryUsers = []struct {
	Username string
	Email    string
	Group    string
}{
	{DirectoryUserPlatform, DirectoryEmailPlatform, GroupEngPlatform},
	{DirectoryUserSecurity, DirectoryEmailSecurity, GroupEngSecurity},
}

// GroupRoles is the mapping as the Organization screen lists it (design line
// 1173). Order is presentational only: `group_role_map` is keyed on the group
// name and `auth.HighestRole` decides precedence when an identity is in several.
var GroupRoles = []struct {
	Group string
	Role  models.OrgRole
}{
	{GroupEngPlatform, models.OrgRoleCatalogAdmin},
	{GroupEngSecurity, models.OrgRoleScannerReviewer},
	{GroupEngAll, models.OrgRoleProfileConsumer},
	{GroupContractors, models.OrgRoleReadOnly},
}
