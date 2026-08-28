package auth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

func TestHighestRoleTakesTheMostPrivilegedMappedGroup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mapped []string
		want   models.OrgRole
	}{
		{"no mapped group grants nothing", nil, ""},
		{"an unmapped group contributes nothing", []string{}, ""},
		{"one mapping is that role", []string{"scanner-reviewer"}, models.OrgRoleScannerReviewer},
		{
			"several mappings take the most privileged",
			[]string{"read-only", "catalog-admin", "profile-consumer"},
			models.OrgRoleCatalogAdmin,
		},
		{
			"order of arrival does not matter",
			[]string{"catalog-admin", "read-only"},
			models.OrgRoleCatalogAdmin,
		},
		{
			"a value outside the ranking grants nothing, not everything",
			[]string{"superuser"},
			"",
		},
		{
			"an unranked value beside a ranked one leaves the ranked one",
			[]string{"superuser", "read-only"},
			models.OrgRoleReadOnly,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, auth.HighestRole(tc.mapped))
		})
	}
}

// The ranking is a Go list and the value set is a Postgres enum. If a role is
// added to the enum and not to the ranking, HighestRole silently ignores it —
// which fails closed, but silently. This is the test that makes it loud.
func TestEveryOrgRoleTheSchemaAllowsIsRanked(t *testing.T) {
	values := models.EnumTypes()[models.PGOrgRole]
	require.NotEmpty(t, values, "the org_role enum has no values — this test would pass vacuously")

	for _, value := range values {
		require.Equalf(t, models.OrgRole(value), auth.HighestRole([]string{value}),
			"org_role %q is in the database enum but not in auth's precedence list", value)
	}
}

func TestHashTokenYieldsNoUsableCredential(t *testing.T) {
	token, err := auth.NewToken()
	require.NoError(t, err)

	// 32 bytes of crypto/rand, base64url without padding.
	raw, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	require.Len(t, raw, 32)

	hash := auth.HashToken(token)
	require.Len(t, hash, sha256.Size)
	require.NotContains(t, string(hash), token)
	require.NotEqual(t, []byte(token), hash)

	t.Run("the same token hashes the same way", func(t *testing.T) {
		require.Equal(t, hash, auth.HashToken(token))
	})

	t.Run("a different token hashes differently", func(t *testing.T) {
		other, err := auth.NewToken()
		require.NoError(t, err)
		require.NotEqual(t, hash, auth.HashToken(other))
	})

	t.Run("two tokens are never the same", func(t *testing.T) {
		seen := make(map[string]struct{}, 256)
		for range 256 {
			next, err := auth.NewToken()
			require.NoError(t, err)
			_, dup := seen[next]
			require.False(t, dup)
			seen[next] = struct{}{}
		}
	})
}

func TestPrincipalRefsNameOnlyWhatAMembershipMayMatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    auth.Principal
		want []string
	}{
		{"email first, because that is what the sharing panel shows",
			auth.Principal{Email: "kwiatrzyk@example.com", Subject: "sub-1"},
			[]string{"kwiatrzyk@example.com", "sub-1"}},
		{"an identity with no email is still matchable by subject",
			auth.Principal{Subject: "sub-1"}, []string{"sub-1"}},
		{"an empty principal names nothing, so it matches no membership row",
			auth.Principal{}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.p.Refs())
		})
	}
}

func TestCLISourceIdentifiesTheHost(t *testing.T) {
	// FR-050: a client source identifies the host.
	require.Equal(t, "cli / dev-laptop-01", auth.CLISource("dev-laptop-01"))
	require.True(t, strings.HasPrefix(auth.CLISource("x"), "cli / "))
}
