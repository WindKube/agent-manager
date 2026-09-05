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

// The other two names the design's Organization screen shows.
//
// GroupEngAll is part of the identity-provider coupling too, and in a way the two
// above are not: it is the SECOND group both role-holding directory users are in,
// carried by `othergroups` in the glauth fixture. That is what makes a profile
// shared with a GROUP reachable by signing in — the dataset shares SRE On-call
// with eng-all as consumer, and until both directory users were in it the group
// half of the sharing panel was only ever exercised by tests.
//
// It maps to profile-consumer, the least privileged role, and auth.HighestRole
// takes the most privileged of a person's groups, so being in it changes nobody's
// role. That is the property the arrangement rests on and it is asserted, not
// assumed. It is also why the third directory user is NOT in it: a role there
// would delete the only route to FR-117's no-role screen.
//
// GroupContractors is vocabulary only — no directory user is in it.
const (
	GroupEngAll      = "eng-all"
	GroupContractors = "contractors"
)

// GroupUnmapped is a group the local directory HAS and this hub maps to nothing.
//
// It exists so FR-117's screen — signed in, authenticated, holding no role — is
// reachable in a browser rather than only in a component test. Without it the
// only way to see that screen on the local stack is to break the group-to-role
// coupling on purpose, which is the same edit as the bug it is meant to
// distinguish from: a person who reached it would have no way to tell "this hub
// has not mapped my group" from "somebody typo'd the fixture".
//
// It must stay absent from GroupRoles. TestTheUnmappedGroupIsMappedToNothing
// asserts that, because mapping it is a one-line change that silently deletes the
// only route to a whole screen.
const GroupUnmapped = "vendors"

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
	// The third person, in GroupUnmapped. Everything above applies to them
	// unchanged — they are in the directory, they can sign in, and the seed must
	// not write them a row either.
	DirectoryUserUnmapped  = "dnowicki"
	DirectoryEmailUnmapped = "dnowicki@example.com"
)

// DirectoryPassword is the password BOTH people above authenticate with.
//
// It sits beside their usernames for the same reason the rest of this surface
// does: `deploy/local/glauth/glauth.cfg` holds only sha256 of it, and no amount of
// reading that file recovers the plaintext, so the plaintext has to be spelled
// somewhere — and it must be spelled exactly once. 001's quickstart table needs
// it, and so does the sign-in screen's development hint (003 FR-119), which is the
// caller that makes a second copy dangerous: a stale copy of a password on a
// screen sends a person to reset something that was never broken.
//
// It is a laptop credential and nothing more. glauth listens on the compose
// network only, the value is documented in the quickstart, and the hint that shows
// it renders ONLY when an operator set AGENT_MANAGER_WEB_DEV_CREDENTIAL_HINT.
//
//nolint:gosec // G101: it IS a hard-coded credential, and that is the design. See above.
const DirectoryPassword = "local-only-directory-password"

// DirectoryUser is one person the local directory can authenticate.
type DirectoryUser struct {
	Username string
	Email    string
	// Group is this person's PRIMARY group. For two of the three it is the group
	// they resolve a role through, and SC-104 turns on those two being different;
	// for the third it is GroupUnmapped, and they resolve none.
	Group string
	// Shared is the second group they are also in, or "" for the one who is in no
	// second group. It exists so a group membership the dataset writes covers a
	// person who can actually sign in; see GroupEngAll.
	Shared string
}

// DirectoryUsers is the set to walk — generating the fixture, checking nothing
// collides with it, or building the sign-in screen's development hint.
//
// ALL THREE, including the one who resolves no role. Every walk over this list is
// either "who can sign in" or "who must not be seeded", and the unmapped user is
// both of those: a list that held only the two role-holders would leave the third
// out of the collision check in internal/seed/identities_test.go, where a seeded
// row naming them would shadow the row their first sign-in creates.
var DirectoryUsers = []DirectoryUser{
	{DirectoryUserPlatform, DirectoryEmailPlatform, GroupEngPlatform, GroupEngAll},
	{DirectoryUserSecurity, DirectoryEmailSecurity, GroupEngSecurity, GroupEngAll},
	{DirectoryUserUnmapped, DirectoryEmailUnmapped, GroupUnmapped, ""},
}

// RoleOf is the role a group resolves to, and "" when the hub maps it to none.
//
// A lookup over GroupRoles rather than a second map, so there is one answer to
// the question and the unmapped case is a value rather than a missing key
// somebody has to remember to check.
func RoleOf(group string) string {
	for _, mapping := range GroupRoles {
		if mapping.Group == group {
			return string(mapping.Role)
		}
	}
	return ""
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
