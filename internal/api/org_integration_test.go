//go:build integration

package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The Organization screen's operations against a real Postgres.
//
// Three properties carry most of the weight here:
//
//   - getOrganization never carries the client secret, in any form;
//   - every save writes exactly one audit row, and every refusal writes none;
//   - a toggle changes what the NEXT resolution does, not merely its own row —
//     proven here for require_signed_bundles, the one of the four not already
//     covered by profile_gate_integration_test.go (the scan gate) or
//     scanner_integration_test.go (rescan_on_new_version).

// TestGetOrganizationNeverCarriesTheClientSecretInAnyForm asserts on the RAW
// body rather than on the decoded struct: a struct with no field for a secret
// proves nothing about a handler that marshalled one straight from a map.
func TestGetOrganizationNeverCarriesTheClientSecretInAnyForm(t *testing.T) {
	raw := send(t, kw, http.MethodGet, "/v1/organization", "", http.StatusOK)
	body := strings.ToLower(string(raw))
	require.NotContains(t, body, "secret")
	require.NotContains(t, body, "clientsecret")

	org := sendJSON[contract.Organization](t, kw, http.MethodGet, "/v1/organization", "", http.StatusOK)
	require.NotNil(t, org.Provider.Scopes, "the provider panel reads a slice, never a stand-in for a secret")
}

// TestOnlyCatalogAdminMayAdministerTheOrganization proves hiding an action on
// the screen is not the same guarantee as the api refusing one that arrives
// anyway.
func TestOnlyCatalogAdminMayAdministerTheOrganization(t *testing.T) {
	require.Equal(t, models.OrgRoleCatalogAdmin, principalFor(t, kw).Role)

	send(t, contractor, http.MethodGet, "/v1/organization", "", http.StatusForbidden)
	send(t, contractor, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"block","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusForbidden)
	send(t, contractor, http.MethodPost, "/v1/organization/mappings",
		`{"groupName":"eng-x","role":"read-only"}`, http.StatusForbidden)
	send(t, contractor, http.MethodPost, "/v1/organization/categories",
		`{"name":"Nope"}`, http.StatusForbidden)
}

// currentPolicy reads org_policy directly, for tests that need to restore it.
func currentPolicy(t *testing.T) contract.UpdatePolicyRequest {
	t.Helper()
	var out contract.UpdatePolicyRequest
	require.NoError(t, db.NewSelect().Model((*models.OrgPolicy)(nil)).
		Column("scan_gate", "require_signed_bundles", "community_needs_review",
			"rescan_on_new_version", "allow_personal_profiles").
		Where("id = ?", models.OrgPolicySingletonID).
		Scan(t.Context(), &out.ScanGate, &out.RequireSignedBundles, &out.CommunityNeedsReview,
			&out.RescanOnNewVersion, &out.AllowPersonalProfiles))
	return out
}

func restorePolicy(t *testing.T, p contract.UpdatePolicyRequest) {
	t.Helper()
	body := fmt.Sprintf(
		`{"scanGate":%q,"requireSignedBundles":%t,"communityNeedsReview":%t,"rescanOnNewVersion":%t,"allowPersonalProfiles":%t}`,
		p.ScanGate, p.RequireSignedBundles, p.CommunityNeedsReview, p.RescanOnNewVersion, p.AllowPersonalProfiles)
	send(t, kw, http.MethodPut, "/v1/organization/policy", body, http.StatusOK)
}

// TestUpdatingThePolicyWritesExactlyOnePolicyAuditRow is the audit half.
func TestUpdatingThePolicyWritesExactlyOnePolicyAuditRow(t *testing.T) {
	before := currentPolicy(t)
	t.Cleanup(func() { restorePolicy(t, before) })

	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"approval","requireSignedBundles":true,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	require.Equal(t, beforeCount+1, auditRowCount(t))

	kind, actor, _ := lastAuditRow(t)
	require.Equal(t, "policy", kind)
	require.NotEmpty(t, actor)
}

// TestAnInvalidScanGateIsRefusedAndWritesNoRow is the validation half.
func TestAnInvalidScanGateIsRefusedAndWritesNoRow(t *testing.T) {
	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"delete-everything","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusUnprocessableEntity)
	require.Equal(t, beforeCount, auditRowCount(t))
}

// TestRequireSignedBundlesExcludesAnUnsignedVersionFromTheNextResolution covers
// the one toggle profile_gate_integration_test.go does not already: this is
// the same version, read twice, with only org_policy changed between the two
// reads (the pattern that file's own comment explains).
func TestRequireSignedBundlesExcludesAnUnsignedVersionFromTheNextResolution(t *testing.T) {
	before := currentPolicy(t)
	t.Cleanup(func() { restorePolicy(t, before) })

	pkg := seedGatePackage(t, "signature-gate",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean, latest: true})

	slug := "gate/signature-gate"
	newGateProfile(t, slug, "Signature gate")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	// Off: the version has no signature row at all, and resolves anyway.
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	before2 := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "1.0.0", before2.Version)
	require.Nil(t, before2.Skip)

	// On: the same version, with the same bytes and the same verdict, is now
	// excluded — the ONLY thing that moved is org_policy.
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":true,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	after := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.NotNil(t, after.Skip,
		"require_signed_bundles must exclude a version carrying no signature reference, "+
			"whatever its verdict")
}

func TestCreatingAMappingWritesOneRoleAuditRow(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(),
			`delete from group_role_map where group_name = 'eng-org-test'`)
		require.NoError(t, err)
	})

	beforeCount := auditRowCount(t)
	mapping := sendJSON[contract.GroupRoleMapping](t, kw, http.MethodPost, "/v1/organization/mappings",
		`{"groupName":"eng-org-test","role":"read-only"}`, http.StatusOK)
	require.Equal(t, "eng-org-test", mapping.GroupName)
	require.Equal(t, "read-only", mapping.Role)
	require.Equal(t, beforeCount+1, auditRowCount(t))

	kind, _, _ := lastAuditRow(t)
	require.Equal(t, "role", kind)
}

func TestAnInvalidRoleIsRefusedAndWritesNoRow(t *testing.T) {
	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPost, "/v1/organization/mappings",
		`{"groupName":"eng-org-test-2","role":"super-admin"}`, http.StatusUnprocessableEntity)
	require.Equal(t, beforeCount, auditRowCount(t))
}

// TestDeletingAMappingWritesOneRoleAuditRowAndRemovesTheRow proves the delete
// is real: the row is gone afterward, and a second delete of the same group
// answers 404 rather than a silent no-op success.
func TestDeletingAMappingWritesOneRoleAuditRowAndRemovesTheRow(t *testing.T) {
	sendJSON[contract.GroupRoleMapping](t, kw, http.MethodPost, "/v1/organization/mappings",
		`{"groupName":"eng-org-delete-test","role":"read-only"}`, http.StatusOK)

	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodDelete, "/v1/organization/mappings/eng-org-delete-test", "", http.StatusNoContent)
	require.Equal(t, beforeCount+1, auditRowCount(t))

	kind, _, _ := lastAuditRow(t)
	require.Equal(t, "role", kind)

	mappings := sendJSON[[]contract.GroupRoleMapping](t, kw, http.MethodGet, "/v1/organization/mappings", "", http.StatusOK)
	for _, m := range mappings {
		require.NotEqual(t, "eng-org-delete-test", m.GroupName, "the mapping must be gone after the delete")
	}

	// A second delete of the same, now-absent, group is a 404, not a repeat
	// success.
	send(t, kw, http.MethodDelete, "/v1/organization/mappings/eng-org-delete-test", "", http.StatusNotFound)
}

// TestCreatingACategoryWritesOneCategoryAuditRowAndACollidingNameConflicts
// covers both halves: the write, and the refusal a duplicate name earns.
func TestCreatingACategoryWritesOneCategoryAuditRowAndACollidingNameConflicts(t *testing.T) {
	const name = "Org Screen Test Category"
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `delete from category where name = ?`, name)
		require.NoError(t, err)
	})

	beforeCount := auditRowCount(t)
	category := sendJSON[contract.OrganizationCategory](t, kw, http.MethodPost, "/v1/organization/categories",
		fmt.Sprintf(`{"name":%q}`, name), http.StatusOK)
	require.Equal(t, name, category.Name)
	require.NotEmpty(t, category.Slug)
	require.Equal(t, beforeCount+1, auditRowCount(t))

	kind, _, _ := lastAuditRow(t)
	require.Equal(t, "category", kind)

	// The collision: same name again.
	beforeCount = auditRowCount(t)
	send(t, kw, http.MethodPost, "/v1/organization/categories",
		fmt.Sprintf(`{"name":%q}`, name), http.StatusConflict)
	require.Equal(t, beforeCount, auditRowCount(t))

	// Renaming writes its own audit row.
	beforeCount = auditRowCount(t)
	renamed := sendJSON[contract.OrganizationCategory](t, kw, http.MethodPatch,
		"/v1/organization/categories/"+category.ID, `{"name":"Org Screen Test Category Renamed"}`,
		http.StatusOK)
	require.Equal(t, "Org Screen Test Category Renamed", renamed.Name)
	require.Equal(t, beforeCount+1, auditRowCount(t))
}

// TestDeletingACategoryWritesOneCategoryAuditRowAndRemovesTheRow proves an
// unreferenced category can really be deleted.
func TestDeletingACategoryWritesOneCategoryAuditRowAndRemovesTheRow(t *testing.T) {
	const name = "Org Screen Delete Test Category"
	category := sendJSON[contract.OrganizationCategory](t, kw, http.MethodPost, "/v1/organization/categories",
		fmt.Sprintf(`{"name":%q}`, name), http.StatusOK)

	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodDelete, "/v1/organization/categories/"+category.ID, "", http.StatusNoContent)
	require.Equal(t, beforeCount+1, auditRowCount(t))

	kind, _, _ := lastAuditRow(t)
	require.Equal(t, "category", kind)

	send(t, kw, http.MethodDelete, "/v1/organization/categories/"+category.ID, "", http.StatusNotFound)
}

// TestDeletingACategoryStillAssignedToAPackageRefusesAndWritesNoRow proves the
// refusal is the database's own foreign key, not a check this handler could
// forget: the category is left assigned to a real package.
func TestDeletingACategoryStillAssignedToAPackageRefusesAndWritesNoRow(t *testing.T) {
	const name = "Org Screen In-Use Test Category"
	category := sendJSON[contract.OrganizationCategory](t, kw, http.MethodPost, "/v1/organization/categories",
		fmt.Sprintf(`{"name":%q}`, name), http.StatusOK)
	// Registered before seedGatePackage's own cleanup below, so t.Cleanup's LIFO
	// order runs the package's cleanup FIRST: the category_id foreign key must be
	// gone before this can delete the category row.
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `delete from category where id = ?`, category.ID)
		require.NoError(t, err)
	})

	seedGatePackage(t, "org-category-in-use",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean, latest: true})
	_, err := db.ExecContext(context.Background(), `update package set category_id = ? where id = (
		select id from package where namespace = 'gate' and name = 'org-category-in-use')`, category.ID)
	require.NoError(t, err)

	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodDelete, "/v1/organization/categories/"+category.ID, "", http.StatusConflict)
	require.Equal(t, beforeCount, auditRowCount(t))
}

// TestRotatingTheClientSecretAlwaysRefusesAndWritesNoRow proves rotation is
// genuinely impossible from this hub (see commands.ErrSecretRotationUnsupported),
// so the refusal is the whole implementation and must never look like a write
// that silently did nothing.
func TestRotatingTheClientSecretAlwaysRefusesAndWritesNoRow(t *testing.T) {
	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPost, "/v1/organization/identity/secret", "", http.StatusConflict)
	require.Equal(t, beforeCount, auditRowCount(t))
}

// lastAuditRow reads back the most recently written audit_event row.
func lastAuditRow(t *testing.T) (kind, actor, text string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(context.Background(),
		`select kind::text, actor, text from audit_event order by occurred_at desc, id desc limit 1`).
		Scan(&kind, &actor, &text))
	return kind, actor, text
}
