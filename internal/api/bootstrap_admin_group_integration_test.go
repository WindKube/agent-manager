//go:build integration

package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The bootstrap admin group, against a real Postgres.
//
// What makes this worth a file of its own is that it is the ONE mapping no
// person can have created: mapping a group requires catalog-admin and holding
// catalog-admin requires a mapping, so a hub with an empty group_role_map has no
// administrator and no way to appoint one. Every property below is about that
// escape hatch staying closed to everything else.

const bootstrapTestGroup = "WindKube:bootstrap-test"

func dropBootstrapTestGroup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(),
			`delete from group_role_map where group_name = ?`, bootstrapTestGroup)
		require.NoError(t, err)
	})
}

func roleOfGroup(t *testing.T, group string) string {
	t.Helper()
	var role string
	err := pool.QueryRow(context.Background(),
		`select role::text from group_role_map where group_name = $1`, group).Scan(&role)
	if err != nil {
		return ""
	}
	return role
}

// TestEnsureAdminGroupCreatesTheMappingAndAuditsItAsTheSystem covers the case the
// whole mechanism exists for: a hub where nobody can administer anything yet.
func TestEnsureAdminGroupCreatesTheMappingAndAuditsItAsTheSystem(t *testing.T) {
	dropBootstrapTestGroup(t)

	before := auditRowCount(t)
	changed, err := commands.EnsureAdminGroup(context.Background(), db, bootstrapTestGroup)
	require.NoError(t, err)
	require.True(t, changed, "a group that was not mapped is a change")

	require.Equal(t, string(models.OrgRoleCatalogAdmin), roleOfGroup(t, bootstrapTestGroup))
	require.Equal(t, before+1, auditRowCount(t))

	kind, actor, _ := lastAuditRow(t)
	require.Equal(t, "role", kind)
	require.Equal(t, commands.BootstrapActor, actor,
		"nobody clicked this, so it must not be attributed to an identity")
}

// TestEnsureAdminGroupIsSilentWhenItChangesNothing is why a restart does not fill
// the Audit screen with one row per deploy.
func TestEnsureAdminGroupIsSilentWhenItChangesNothing(t *testing.T) {
	dropBootstrapTestGroup(t)

	changed, err := commands.EnsureAdminGroup(context.Background(), db, bootstrapTestGroup)
	require.NoError(t, err)
	require.True(t, changed)

	before := auditRowCount(t)
	changed, err = commands.EnsureAdminGroup(context.Background(), db, bootstrapTestGroup)
	require.NoError(t, err)
	require.False(t, changed, "the mapping already said catalog-admin")
	require.Equal(t, before, auditRowCount(t), "an unchanged reconcile writes no audit row")
}

// TestEnsureAdminGroupReclaimsAGroupDemotedOnTheScreen is the property that makes
// this a reconcile rather than a seed, and the reason an operator who locks every
// administrator out can recover by restarting the api.
func TestEnsureAdminGroupReclaimsAGroupDemotedOnTheScreen(t *testing.T) {
	dropBootstrapTestGroup(t)

	_, err := commands.EnsureAdminGroup(context.Background(), db, bootstrapTestGroup)
	require.NoError(t, err)

	// The screen's own action, through the api, exactly as a catalog admin would.
	sendJSON[contract.GroupRoleMapping](t, kw, http.MethodPost, "/v1/organization/mappings",
		`{"groupName":"`+bootstrapTestGroup+`","role":"read-only"}`, http.StatusOK)
	require.Equal(t, "read-only", roleOfGroup(t, bootstrapTestGroup))

	changed, err := commands.EnsureAdminGroup(context.Background(), db, bootstrapTestGroup)
	require.NoError(t, err)
	require.True(t, changed, "a demoted group is a change to put back")
	require.Equal(t, string(models.OrgRoleCatalogAdmin), roleOfGroup(t, bootstrapTestGroup))
}

// TestEnsureAdminGroupDeclaredEmptyTouchesNothing: a hub whose mappings are
// already established names no group, and must not acquire one.
func TestEnsureAdminGroupDeclaredEmptyTouchesNothing(t *testing.T) {
	before := auditRowCount(t)

	for _, declared := range []string{"", "   "} {
		changed, err := commands.EnsureAdminGroup(context.Background(), db, declared)
		require.NoError(t, err)
		require.False(t, changed)
	}
	require.Equal(t, before, auditRowCount(t))
}
