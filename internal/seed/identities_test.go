// The actor invariants, held by a test because nothing holds them at run time.
//
// A seeded row naming someone who can sign in produces no error anywhere: the
// seed succeeds, the sign-in succeeds, and the product simply shows two identities
// for one person — the seeded one carrying the history, the real one carrying the
// viewer. See DirectoryUsers in groups.go for why that is the defect this whole
// feature exists to remove and not a cosmetic duplicate.
//
// These tests are in `package seed` rather than beside the integration suite
// deliberately: the invariant is a property of the dataset, so it is worth
// knowing without a container, on every `go test ./...`.
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

// TestEverySeededActorIsASeededIdentity is the other half: an actor who is in no
// identity row renders as a bare email with no display name and no groups, which
// is how a reassignment gets half done.
func TestEverySeededActorIsASeededIdentity(t *testing.T) {
	for _, reference := range seededReferences() {
		if !reference.isActor {
			continue
		}
		_, ok := identityBy(reference.value)
		require.Truef(t, ok, "%s is %q, who is not a seeded identity", reference.where, reference.value)
	}
}

// TestEverySeededGroupHasAMemberIdentity keeps the Organization screen's
// vocabulary populated. A mapped group with no member reads as a role nobody
// holds, which is the empty state Phase 2 exists to avoid.
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

// seededReference is one actor-shaped string the dataset states, with where it
// came from so a failure names the row rather than the value alone. isActor
// marks the ones that assert a person DID something, as opposed to a source
// string that merely mentions a host.
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

	// The version count only reaches the rescan row's text; any value builds the
	// same set of actors.
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

// directoryUserIn reports whether a value names one of the people in
// deploy/local/glauth/glauth.cfg.
//
// The email is matched by containment because the values it has to catch embed it
// — `seed:kwiatrzyk@example.com`, `cli / kwiatrzyk@example.com`. The username is
// matched by equality instead: `anowak` is a substring of plenty of addresses that
// belong to somebody else entirely.
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
