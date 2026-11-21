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

// The Organization screen's operations against a real Postgres: the client secret never
// leaves, every save writes one audit row and every refusal none, and a toggle changes
// what the next resolution does.

// TestGetOrganizationNeverCarriesTheClientSecretInAnyForm asserts on the raw body: a struct
// with no secret field proves nothing about a handler that marshalled a map.
func TestGetOrganizationNeverCarriesTheClientSecretInAnyForm(t *testing.T) {
	raw := send(t, kw, http.MethodGet, "/v1/organization", "", http.StatusOK)
	body := strings.ToLower(string(raw))
	require.NotContains(t, body, "secret")
	require.NotContains(t, body, "clientsecret")

	org := sendJSON[contract.Organization](t, kw, http.MethodGet, "/v1/organization", "", http.StatusOK)
	require.NotNil(t, org.Provider.Scopes, "the provider panel reads a slice, never a stand-in for a secret")
}

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

func TestAnInvalidScanGateIsRefusedAndWritesNoRow(t *testing.T) {
	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"delete-everything","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusUnprocessableEntity)
	require.Equal(t, beforeCount, auditRowCount(t))
}

// TestRequireSignedBundlesExcludesAnUnsignedVersionFromTheNextResolution reads the same
// version twice with only org_policy changed in between.
func TestRequireSignedBundlesExcludesAnUnsignedVersionFromTheNextResolution(t *testing.T) {
	before := currentPolicy(t)
	t.Cleanup(func() { restorePolicy(t, before) })

	pkg := seedGatePackage(t, "signature-gate",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean, latest: true})

	slug := "gate/signature-gate"
	newGateProfile(t, slug, "Signature gate")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	before2 := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.Equal(t, "1.0.0", before2.Version)
	require.Nil(t, before2.Skip)

	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":true,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	after := entryByID(t, profileDetail(t, curator, slug), pkg.id)
	require.NotNil(t, after.Skip,
		"require_signed_bundles must exclude a version carrying no signature reference, "+
			"whatever its verdict")
}

// TestRequireSignedBundlesResolvesOnlyTheExpectedSigner changes only the expected signer,
// never the signature row, between reads.
func TestRequireSignedBundlesResolvesOnlyTheExpectedSigner(t *testing.T) {
	before := currentPolicy(t)
	t.Cleanup(func() { restorePolicy(t, before) })

	const (
		issuer   = "https://token.actions.githubusercontent.com"
		identity = "https://github.com/gate/signed/.github/workflows/release.yaml@refs/tags/v1.0.0"
	)
	pkg := seedGatePackage(t, "signed-gate",
		gateVersion{semver: "1.0.0", verdict: models.VerdictClean, latest: true})
	verified := models.SignatureResultVerified
	_, err := db.NewInsert().Model(&models.Signature{
		VersionID: pkg.versions["1.0.0"], Kind: models.SignatureKindCosignBundle, Result: &verified,
		Ref: "https://example.dev/signed.zip.sigstore.json", Bundle: []byte(`{}`), ArtifactDigest: bundleSHA,
		SignerIssuer: issuer, SignerIdentity: identity,
	}).Exec(t.Context())
	require.NoError(t, err)

	slug := "gate/signed-gate"
	newGateProfile(t, slug, "Signed gate")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)
	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":true,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)

	org := sendJSON[contract.Organization](t, kw, http.MethodGet, "/v1/organization", "", http.StatusOK)
	require.Positive(t, org.Policy.PackagesWithoutExpectedSigner)

	signerPath := "/v1/packages/" + pkg.id + "/signer"
	skipDetail := func() string {
		entry := entryByID(t, profileDetail(t, curator, slug), pkg.id)
		if entry.Skip == nil {
			return ""
		}
		require.Equal(t, "unsigned-and-signatures-required", entry.Skip.Reason)
		return entry.Skip.Detail
	}
	versionStatus := func() string {
		page := sendJSON[contract.PackageDetail](t, kw, http.MethodGet, "/v1/packages/"+pkg.id, "", http.StatusOK)
		return page.Versions[0].Signature.Status
	}

	require.Contains(t, skipDetail(), "no expected signer configured")
	require.Equal(t, "verified-no-expected-signer", versionStatus())

	send(t, kw, http.MethodPut, signerPath,
		fmt.Sprintf(`{"issuer":%q,"identity":%q}`, issuer, `https://github\.com/someone-else/.*`), http.StatusOK)
	require.Contains(t, skipDetail(), "not its package's expected signer")
	require.Equal(t, "verified-unexpected-signer", versionStatus())

	page := sendJSON[contract.PackageDetail](t, kw, http.MethodPut, signerPath,
		fmt.Sprintf(`{"issuer":%q,"identity":%q}`, issuer, `https://github\.com/gate/signed/\.github/workflows/release\.yaml@refs/tags/v.*`),
		http.StatusOK)
	require.Equal(t, issuer, page.Signer.Issuer)
	require.True(t, page.Signer.CanChange)
	require.Empty(t, skipDetail(), "the expected signer resolves")
	require.Equal(t, "verified-matching", versionStatus())

	var rows int
	require.NoError(t, db.QueryRowContext(t.Context(), `select count(*) from audit_event
	  where subject_kind = 'package' and subject_id = ? and data->>'action' = 'signer-changed'`, pkg.id).Scan(&rows))
	require.Equal(t, 2, rows)

	send(t, kw, http.MethodPut, signerPath, `{"issuer":"https://only-half.example"}`, http.StatusUnprocessableEntity)
	send(t, kw, http.MethodPut, signerPath, fmt.Sprintf(`{"issuer":%q,"identity":"("}`, issuer), http.StatusUnprocessableEntity)
	send(t, contractor, http.MethodPut, signerPath, `{}`, http.StatusForbidden)

	sendJSON[contract.PackageDetail](t, kw, http.MethodPut, signerPath, `{}`, http.StatusOK)
	require.Contains(t, skipDetail(), "no expected signer configured")
}

func TestAllowPersonalProfilesGatesPrivateVisibilityCreation(t *testing.T) {
	before := currentPolicy(t)
	t.Cleanup(func() { restorePolicy(t, before) })

	const slug = "org-personal-profile-gate-test"

	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":false}`, http.StatusOK)
	raw := send(t, kw, http.MethodPost, "/v1/profiles",
		fmt.Sprintf(`{"slug":%q,"name":"Personal gate","visibility":"private"}`, slug),
		http.StatusUnprocessableEntity)
	require.Contains(t, strings.ToLower(string(raw)), "private profiles are disabled")

	send(t, kw, http.MethodPut, "/v1/organization/policy",
		`{"scanGate":"warn-with-override","requireSignedBundles":false,"communityNeedsReview":false,`+
			`"rescanOnNewVersion":false,"allowPersonalProfiles":true}`, http.StatusOK)
	sendJSON[contract.Profile](t, kw, http.MethodPost, "/v1/profiles",
		fmt.Sprintf(`{"slug":%q,"name":"Personal gate","visibility":"private"}`, slug), http.StatusCreated)
	dropProfileOnCleanup(t, slug)
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

	send(t, kw, http.MethodDelete, "/v1/organization/mappings/eng-org-delete-test", "", http.StatusNotFound)
}

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

// TestDeletingACategoryStillAssignedToAPackageRefusesAndWritesNoRow relies on the database's
// foreign key, not a handler check.
func TestDeletingACategoryStillAssignedToAPackageRefusesAndWritesNoRow(t *testing.T) {
	const name = "Org Screen In-Use Test Category"
	category := sendJSON[contract.OrganizationCategory](t, kw, http.MethodPost, "/v1/organization/categories",
		fmt.Sprintf(`{"name":%q}`, name), http.StatusOK)
	// Registered first so LIFO runs the package's cleanup before this deletes the category.
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

// TestRotatingTheClientSecretAlwaysRefusesAndWritesNoRow: rotation is impossible from this hub
// (commands.ErrSecretRotationUnsupported), so it must never look like a silent no-op write.
func TestRotatingTheClientSecretAlwaysRefusesAndWritesNoRow(t *testing.T) {
	beforeCount := auditRowCount(t)
	send(t, kw, http.MethodPost, "/v1/organization/identity/secret", "", http.StatusConflict)
	require.Equal(t, beforeCount, auditRowCount(t))
}

func lastAuditRow(t *testing.T) (kind, actor, text string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(context.Background(),
		`select kind::text, actor, text from audit_event order by occurred_at desc, id desc limit 1`).
		Scan(&kind, &actor, &text))
	return kind, actor, text
}
