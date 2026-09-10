//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// Deleting from the catalog, against a real Postgres.
//
// Three properties carry the weight here, none of which a handler-shaped test
// with a fake store could prove: that the FK layer in 03-constraints.sql
// really does let an archive-in-place through where a hard delete of either
// row would be refused (package_latest_version_id_fkey is NO ACTION,
// on purpose, for exactly a version); that a profile entry pinned at the
// archived version and a published revision that already named it both keep
// resolving through GET /v1/bundles afterwards, so neither is silently
// orphaned; and that the api refuses the request before
// commands.DeleteVersion/DeletePackage ever runs, for an identity that does
// not hold catalog-admin.

// seedDeletableWidget creates a fresh publisher, package and two committed
// versions under their own namespace, so this file's tests share no state
// with the package seed() builds or with each other. v1 is the older,
// non-latest version; v2 is the package's current latest.
func seedDeletableWidget(t *testing.T, namespace string) (pkg *models.Package, v1, v2 *models.Version) {
	t.Helper()
	ctx := t.Context()

	publisher := &models.Publisher{ID: models.NewID(), Slug: namespace, DisplayName: namespace}
	require.NoError(t, dbInsertOne(ctx, publisher))

	pkg = &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: namespace, Name: "widget",
		Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
	}
	require.NoError(t, dbInsertOne(ctx, pkg))

	v1 = &models.Version{
		ID: models.NewID(), PackageID: pkg.ID, Semver: "1.0.0", SemverSort: "1.0.0",
		ObjectKey: bundleKey, Digest: bundleSHA, Manifest: json.RawMessage(`{"name":"widget"}`),
		Tags: []string{"widget"}, DistTag: models.DistTagNone, Verdict: models.VerdictClean, Visible: true,
	}
	require.NoError(t, dbInsertOne(ctx, v1))

	v2 = &models.Version{
		ID: models.NewID(), PackageID: pkg.ID, Semver: "2.0.0", SemverSort: "2.0.0",
		ObjectKey: bundleKey, Digest: bundleSHA, Manifest: json.RawMessage(`{"name":"widget"}`),
		Tags: []string{"widget"}, DistTag: models.DistTagLatest, Verdict: models.VerdictClean, Visible: true,
	}
	require.NoError(t, dbInsertOne(ctx, v2))

	_, err := db.NewUpdate().Model((*models.Package)(nil)).
		Set("latest_version_id = ?", v2.ID).
		Where("id = ?", pkg.ID).
		Exec(ctx)
	require.NoError(t, err)

	return pkg, v1, v2
}

func dbInsertOne(ctx context.Context, model any) error {
	_, err := db.NewInsert().Model(model).Exec(ctx)
	return err
}

func versionDistTag(t *testing.T, versionID string) string {
	t.Helper()
	var tag string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select dist_tag::text from version where id = $1`, versionID).Scan(&tag))
	return tag
}

func packageLatestVersionID(t *testing.T, packageID string) *string {
	t.Helper()
	var id *string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select latest_version_id::text from package where id = $1`, packageID).Scan(&id))
	return id
}

// TestDeleteVersionArchivesItAndKeepsAPinAndARevisionResolvable is the
// referenced case: the version DELETE targets is both pinned by a profile
// entry and named in a published revision's lockfile, and it is the
// package's current latest. Archiving it must promote the next version to
// latest, and must not orphan either reference.
func TestDeleteVersionArchivesItAndKeepsAPinAndARevisionResolvable(t *testing.T) {
	ctx := t.Context()
	pkg, v1, v2 := seedDeletableWidget(t, "catdel-pin")

	profile := &models.Profile{
		ID: models.NewID(), Slug: "catdel-pin-consumers", Name: "Consumers",
		Visibility: models.ProfileVisibilityOrganisation, DefaultPolicy: models.VersionPolicyPinned,
	}
	require.NoError(t, dbInsertOne(ctx, profile))
	require.NoError(t, dbInsertOne(ctx, &models.ProfileEntry{
		ProfileID: profile.ID, PackageID: pkg.ID, Mode: models.EntryModePinned,
		PinnedVersionID: &v2.ID, Position: 0,
	}))

	lockfile, err := json.Marshal(map[string]any{
		"profile": map[string]string{"slug": profile.Slug, "name": profile.Name},
		"entries": []map[string]string{{
			"id": "catdel-pin/widget", "kind": "skill", "version": "2.0.0",
			"objectKey": bundleKey,
		}},
	})
	require.NoError(t, err)
	require.NoError(t, dbInsertOne(ctx, &models.Revision{
		ID: models.NewID(), ProfileID: profile.ID, Seq: 1, Note: "seeded",
		Lockfile: lockfile, ObjectKey: "profiles/catdel-pin-consumers/r1.json", CreatedBy: "test",
	}))

	before := auditCount(t)

	out := sendJSON[contract.VersionDeleted](t, kw, http.MethodDelete,
		"/v1/packages/catdel-pin/widget/versions/2.0.0", "", http.StatusOK)
	require.Equal(t, 1, out.PinnedByProfiles, "the seeded profile_entry pins exactly this version")

	require.Equal(t, "archived", versionDistTag(t, v2.ID.String()), "the deleted version is archived, not removed")
	require.Equal(t, "latest", versionDistTag(t, v1.ID.String()), "the remaining version is promoted to latest")
	got := packageLatestVersionID(t, pkg.ID.String())
	require.NotNil(t, got)
	require.Equal(t, v1.ID.String(), *got, "latest_version_id follows the promotion")

	// Not orphaned: the version this profile entry pins, and this revision's
	// lockfile names, still resolves.
	send(t, kw, http.MethodGet, "/v1/bundles/catdel-pin/widget/2.0.0", "", http.StatusOK)

	// The profile entry itself is untouched — reading it to decide safety is
	// this branch's job; changing it is the profile screen's.
	var mode, pinnedID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select mode::text, pinned_version_id::text from profile_entry where profile_id = $1 and package_id = $2`,
		profile.ID, pkg.ID).Scan(&mode, &pinnedID))
	require.Equal(t, "pinned", mode)
	require.Equal(t, v2.ID.String(), pinnedID)

	require.Equal(t, before+1, auditCount(t), "exactly one audit row for the delete")
	kind, actor, text := lastCatalogDeleteAudit(t)
	require.Equal(t, "fetch", kind)
	require.Equal(t, "kwiatrzyk@example.com", actor)
	require.Contains(t, text, "deleted version 2.0.0 of catdel-pin/widget")
	require.Contains(t, text, "pinned by 1 profile entry")

	// The package still resolves — v1 carries latest now — and still lists
	// the archived version rather than hiding it from the history.
	detail := sendJSON[contract.PackageDetail](t, kw, http.MethodGet, "/v1/packages/catdel-pin/widget", "", http.StatusOK)
	require.Equal(t, "1.0.0", detail.Version)
	var sawArchived bool
	for _, v := range detail.Versions {
		if v.Version == "2.0.0" {
			sawArchived = true
			require.Equal(t, "archived", v.DistTag)
		}
	}
	require.True(t, sawArchived, "the withdrawn version stays in the history, marked archived")
}

// TestDeletePackageArchivesEveryVersionAndTheCatalogStopsFindingIt is the
// package-scoped delete: every version archives, latest_version_id clears,
// and the package's own detail read — which joins through that column —
// answers exactly as it would for a package with no published version.
func TestDeletePackageArchivesEveryVersionAndTheCatalogStopsFindingIt(t *testing.T) {
	pkg, v1, v2 := seedDeletableWidget(t, "catdel-pkg")

	send(t, kw, http.MethodGet, "/v1/packages/catdel-pkg/widget", "", http.StatusOK)

	before := auditCount(t)
	out := sendJSON[contract.PackageDeleted](t, kw, http.MethodDelete,
		"/v1/packages/catdel-pkg/widget", "", http.StatusOK)
	require.Equal(t, 2, out.VersionsArchived)

	require.Equal(t, "archived", versionDistTag(t, v1.ID.String()))
	require.Equal(t, "archived", versionDistTag(t, v2.ID.String()))
	require.Nil(t, packageLatestVersionID(t, pkg.ID.String()), "latest_version_id is cleared")

	send(t, kw, http.MethodGet, "/v1/packages/catdel-pkg/widget", "", http.StatusNotFound)

	// Neither version's bytes vanished: both still resolve for whatever
	// already recorded them.
	send(t, kw, http.MethodGet, "/v1/bundles/catdel-pkg/widget/1.0.0", "", http.StatusOK)
	send(t, kw, http.MethodGet, "/v1/bundles/catdel-pkg/widget/2.0.0", "", http.StatusOK)

	require.Equal(t, before+1, auditCount(t))
	kind, _, text := lastCatalogDeleteAudit(t)
	require.Equal(t, "fetch", kind)
	require.Contains(t, text, "deleted package catdel-pkg/widget")
	require.Contains(t, text, "archived 2 version(s)")
}

// TestDeleteRefusesWithoutCatalogAdminRole proves the refusal happens in the
// api, not merely that the web screen would grey the button out.
func TestDeleteRefusesWithoutCatalogAdminRole(t *testing.T) {
	pkg, _, v2 := seedDeletableWidget(t, "catdel-role")

	for _, who := range []actor{an, contractor} {
		send(t, who, http.MethodDelete, "/v1/packages/catdel-role/widget/versions/2.0.0", "", http.StatusForbidden)
		send(t, who, http.MethodDelete, "/v1/packages/catdel-role/widget", "", http.StatusForbidden)
	}

	// Neither refusal mutated anything.
	require.Equal(t, "latest", versionDistTag(t, v2.ID.String()))
	got := packageLatestVersionID(t, pkg.ID.String())
	require.NotNil(t, got)
	require.Equal(t, v2.ID.String(), *got)
}

// TestDeleteRefusesNotFoundAndAlreadyWithdrawn covers the two ordinary
// refusals that are not about references at all.
func TestDeleteRefusesNotFoundAndAlreadyWithdrawn(t *testing.T) {
	seedDeletableWidget(t, "catdel-conflict")

	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/no-such-widget", "", http.StatusNotFound)
	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/widget/versions/9.9.9", "", http.StatusNotFound)

	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/widget/versions/1.0.0", "", http.StatusOK)
	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/widget/versions/1.0.0", "", http.StatusConflict)

	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/widget", "", http.StatusOK)
	send(t, kw, http.MethodDelete, "/v1/packages/catdel-conflict/widget", "", http.StatusConflict)
}

// lastCatalogDeleteAudit reads back the most recent row of the kind these two
// commands write. See commands.writeCatalogDeleteAudit for why that is
// `fetch` rather than a dedicated kind.
func lastCatalogDeleteAudit(t *testing.T) (kind, actor, text string) {
	t.Helper()
	require.NoError(t, pool.QueryRow(context.Background(),
		`select kind::text, actor, text from audit_event order by occurred_at desc, id desc limit 1`).
		Scan(&kind, &actor, &text))
	return kind, actor, text
}
