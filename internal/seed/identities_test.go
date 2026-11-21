// Actor invariants nothing enforces at run time: a seeded row naming someone who
// can sign in silently gives that person two identities.
package seed

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/store/models"
)

func TestNoSeededIdentityBelongsToSomeoneWhoCanSignIn(t *testing.T) {
	require.NotEmpty(t, identities, "the dataset seeds no identity, so this test asserts nothing")

	for _, spec := range identities {
		for _, field := range []struct {
			what  string
			value string
		}{
			{"subject", spec.subject},
			{"email", spec.email},
			{"display name", spec.display},
		} {
			user, collides := directoryUserIn(field.value)
			require.Falsef(t, collides,
				"the seeded identity %q holds %s %q, which names the directory user %q — "+
					"that row shadows the one their first sign-in creates instead of becoming it",
				spec.email, field.what, field.value, user)
		}
	}
}

func TestNoSeededRowNamesSomeoneWhoCanSignIn(t *testing.T) {
	references := seededReferences()
	require.NotEmpty(t, references)

	for _, reference := range references {
		user, collides := directoryUserIn(reference.value)
		require.Falsef(t, collides,
			"%s is %q, which names the directory user %q — a seeded fixture must not grant "+
				"anything to, or claim an action by, a person who signs in for real",
			reference.where, reference.value, user)
	}
}

// An actor with no identity row renders as a bare email with no name or groups.
func TestEverySeededActorIsASeededIdentity(t *testing.T) {
	for _, reference := range seededReferences() {
		if !reference.isActor {
			continue
		}
		_, ok := identityBy(reference.value)
		require.Truef(t, ok, "%s is %q, who is not a seeded identity", reference.where, reference.value)
	}
}

// A mapped group with no member reads as a role nobody holds.
func TestEverySeededGroupHasAMemberIdentity(t *testing.T) {
	members := map[string]int{}
	for _, spec := range identities {
		for _, group := range spec.groups {
			members[group]++
		}
	}
	for _, mapping := range GroupRoles {
		require.NotZerof(t, members[mapping.Group],
			"no seeded identity is in %q, which %s is mapped to", mapping.Group, mapping.Role)
	}
}

// seededReference is an actor-shaped string in the dataset and where it came
// from. isActor marks values claiming a person did something.
type seededReference struct {
	where   string
	value   string
	isActor bool
}

func seededReferences() []seededReference {
	out := make([]seededReference, 0, 32)

	for i := range designProfiles {
		spec := &designProfiles[i]
		for _, member := range spec.members {
			if member.kind != models.SubjectKindUser {
				continue
			}
			out = append(out, seededReference{
				where:   "the " + string(member.role) + " of " + spec.slug,
				value:   member.ref,
				isActor: true,
			})
		}
	}

	for i := range designFindings {
		override := designFindings[i].override
		if override == nil {
			continue
		}
		out = append(out, seededReference{
			where:   "the reviewer who overrode " + designFindings[i].rule,
			value:   override.reviewer,
			isActor: true,
		})
	}

	// The version count does not affect the actors.
	for _, row := range auditRows(1) {
		out = append(out,
			seededReference{
				where:   "the actor of the " + string(row.kind) + " audit row",
				value:   row.actor,
				isActor: row.actorKind == models.ActorKindIdentity,
			},
			seededReference{
				where: "the source of the " + string(row.kind) + " audit row",
				value: row.source,
			},
		)
	}

	return out
}

// directoryUserIn reports whether a value names a local directory user. Emails
// match by containment since values embed them; usernames match exactly since
// they are substrings of unrelated addresses.
func directoryUserIn(value string) (string, bool) {
	folded := strings.ToLower(strings.TrimSpace(value))
	for _, user := range DirectoryUsers {
		if strings.EqualFold(folded, user.Username) ||
			strings.Contains(folded, strings.ToLower(user.Email)) {
			return user.Username, true
		}
	}
	return "", false
}

// Mapping GroupUnmapped looks like tidying up but removes the only way to reach
// the no-role screen locally.
func TestTheUnmappedGroupIsMappedToNothing(t *testing.T) {
	require.NotEmpty(t, GroupRoles, "no mappings, so this test asserts nothing")

	for _, mapping := range GroupRoles {
		require.NotEqualf(t, GroupUnmapped, mapping.Group,
			"%q now resolves to %q. That is the only group in the local directory that maps to "+
				"nothing, and the no-role screen has no other way to be reached in a browser: pick "+
				"a new unmapped group name and put the directory user in it, or delete the "+
				"requirement", GroupUnmapped, mapping.Role)
	}
	require.Empty(t, RoleOf(GroupUnmapped))

	// The group must also have a directory member to be a route at all.
	var found bool
	for _, user := range DirectoryUsers {
		if user.Group == GroupUnmapped {
			found = true
			require.Equal(t, DirectoryEmailUnmapped, user.Email)
		}
	}
	require.True(t, found, "no directory user is in %q", GroupUnmapped)
}

func TestEveryDirectoryGroupExceptTheUnmappedOneResolvesToARole(t *testing.T) {
	for _, user := range DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			if user.Group == GroupUnmapped {
				require.Empty(t, RoleOf(user.Group))
				return
			}
			require.NotEmptyf(t, RoleOf(user.Group),
				"%q is in %q, which maps to no role — so they sign in successfully and land on "+
					"the no-role screen. If that is intended, GroupUnmapped is the group to put "+
					"them in; if not, this is the silent coupling failure "+
					"internal/seed/groups.go describes", user.Username, user.Group)
		})
	}
}
