//go:build integration

// Package visibility enforcement against a real Postgres (feat/package-visibility).
//
// Every path here answers a caller who is not the package's owner the same way
// it answers a request for a package that plain does not exist: queries.ErrNotFound,
// one 404, no distinguishable message. That symmetry is asserted directly rather
// than trusted, because a hub that told the two apart would leak existence by
// status code alone.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// probePackage seeds a publisher, a package at the given visibility and
// owner, and one clean, visible version with a REAL packed bundle — so the
// catalog, detail, bundle and file read paths can all be exercised against
// the same row. Torn down via dropOnCleanup so it cannot perturb another
// test's catalog totals or facet counts.
func probePackage(t *testing.T, namespace, name string, visibility models.PackageVisibility,
	owner *uuid.UUID,
) (id, key string, packed []byte) {
	t.Helper()
	ctx := context.Background()

	publisher := &models.Publisher{
		ID: models.NewID(), Slug: namespace + "/team", DisplayName: namespace,
	}
	_, err := db.NewInsert().Model(publisher).Exec(ctx)
	require.NoError(t, err)
	dropOnCleanup(t, publisher.ID)

	pkg := &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: namespace, Name: name,
		Kind: models.PackageKindSkill, Visibility: visibility, OwnerIdentityID: owner,
	}
	_, err = db.NewInsert().Model(pkg).Exec(ctx)
	require.NoError(t, err)

	key = fmt.Sprintf("skills/%s/%s/1.0.0/bundle.tar.zst", namespace, name)
	packed = packBundle(t, map[string]string{"SKILL.md": "# " + name + "\n"})
	version := &models.Version{
		ID: models.NewID(), PackageID: pkg.ID, Semver: "1.0.0", SemverSort: "1.0.0",
		ObjectKey: key, Digest: bundleSHA,
		Manifest: json.RawMessage(`{"name":"` + name + `"}`), Tags: []string{},
		DistTag: models.DistTagLatest, Verdict: models.VerdictClean, Visible: true,
	}
	_, err = db.NewInsert().Model(version).Exec(ctx)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `update package set latest_version_id = $1 where id = $2`, version.ID, pkg.ID)
	require.NoError(t, err)

	return namespace + "/" + name, key, packed
}

// T-owner-1: registration cannot set an owner other than the authenticated
// actor — there is no field on the form that names one, and this proves the
// row that lands is the caller's own identity regardless.
func TestRegistrationRecordsTheAuthenticatedActorAsOwnerNeverARequestValue(t *testing.T) {
	handler := liveHandler(t)

	contentType, body := upload(t, nil, map[string]string{
		"source": "git", "url": "https://github.com/example/owner-probe", "ref": "v1.0.0",
		"publisher": "ownerprobe/team", "name": "owner-probe", "visibility": "organisation",
	})
	rec := postForm(t, handler, "/v1/packages", an.token, contentType, body)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	var publisherID uuid.UUID
	require.NoError(t, pool.QueryRow(t.Context(),
		`select id from publisher where slug = 'ownerprobe/team'`).Scan(&publisherID))
	dropOnCleanup(t, publisherID)

	var ownerIDText string
	require.NoError(t, pool.QueryRow(t.Context(),
		`select coalesce(owner_identity_id::text, '') from package
		  where namespace = 'ownerprobe' and name = 'owner-probe'`).Scan(&ownerIDText))
	require.Equal(t, principalFor(t, an).IdentityID.String(), ownerIDText,
		"the owner is the authenticated actor — the form carries no field that could name anyone else")
}

// T-private-1: a private package is invisible to everyone but its owner, in
// the catalog list, by search, and by a direct request for its detail — and
// the direct request answers exactly as a nonexistent package would.
func TestAPrivatePackageIsInvisibleToEveryoneButItsOwner(t *testing.T) {
	owner := principalFor(t, an).IdentityID
	id, _, _ := probePackage(t, "privateprobe", "secret-skill", models.PackageVisibilityPrivate, &owner)

	mine := catalog(t, liveHandler(t), an.token, query("q", "secret-skill", "pageSize", "50"))
	require.Contains(t, idsOf(mine), id, "the owner sees their own private package")

	own := detail(t, liveHandler(t), an.token, id)
	require.Equal(t, id, own.ID)

	notMine := catalog(t, liveHandler(t), kw.token, query("q", "secret-skill", "pageSize", "50"))
	require.Empty(t, notMine.Packages,
		"a private package must not appear merely because the reader is signed in")

	handler := liveHandler(t)
	got := request(t, handler, http.MethodGet, "/v1/packages/"+id, kw.token, "")
	wantMissing := request(t, handler, http.MethodGet, "/v1/packages/privateprobe/no-such-thing", kw.token, "")
	require.Equal(t, http.StatusNotFound, got.Code, got.Body.String())
	require.Equal(t, wantMissing.Code, got.Code, "a private package and one that plain does not exist "+
		"must answer with the same status")

	var gotProblem, wantProblem contract.Error
	require.NoError(t, json.Unmarshal(got.Body.Bytes(), &gotProblem))
	require.NoError(t, json.Unmarshal(wantMissing.Body.Bytes(), &wantProblem))
	require.Equal(t, wantProblem.Detail, gotProblem.Detail,
		"and the same message — a different one would leak existence by wording instead of status")
}

// T-team-1: "team" means the package owner's own identity-provider groups.
// curator shares kw's eng-platform group and sees it; an (eng-security) and
// contractor (an unmapped group) do not.
func TestATeamPackageIsVisibleOnlyToIdentitiesSharingTheOwnersGroup(t *testing.T) {
	owner := principalFor(t, kw).IdentityID
	id, _, _ := probePackage(t, "teamprobe", "shared-skill", models.PackageVisibilityTeam, &owner)

	sameGroup := catalog(t, liveHandler(t), curator.token, query("q", "shared-skill", "pageSize", "50"))
	require.Contains(t, idsOf(sameGroup), id, "curator shares the owner's eng-platform group")

	differentGroup := catalog(t, liveHandler(t), an.token, query("q", "shared-skill", "pageSize", "50"))
	require.NotContains(t, idsOf(differentGroup), id, "an's eng-security group does not overlap")

	unmapped := catalog(t, liveHandler(t), contractor.token, query("q", "shared-skill", "pageSize", "50"))
	require.NotContains(t, idsOf(unmapped), id, "an unmapped group is still a group, and still does not overlap")

	handler := liveHandler(t)
	rec := request(t, handler, http.MethodGet, "/v1/packages/"+id, an.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	ownerSees := request(t, handler, http.MethodGet, "/v1/packages/"+id, kw.token, "")
	require.Equal(t, http.StatusOK, ownerSees.Code, ownerSees.Body.String())
}

// T-bundle-1: the bundle download endpoint follows the same refusal
// GET /v1/bundles/{publisher}/{name}/{version} already gives a rejected
// version (FR-029) — before this fix, queries.Bundle applied NO visibility
// filter at all.
func TestBundleDownloadRefusesAPrivatePackageNotOwnedByTheCaller(t *testing.T) {
	owner := principalFor(t, an).IdentityID
	id, key, packed := probePackage(t, "bundleprobe", "guarded-skill", models.PackageVisibilityPrivate, &owner)
	handler := liveHandler(t, map[string][]byte{key: packed})

	rec := request(t, handler, http.MethodGet, "/v1/bundles/"+id+"/1.0.0", an.token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, packed, rec.Body.Bytes())

	refused := request(t, handler, http.MethodGet, "/v1/bundles/"+id+"/1.0.0", kw.token, "")
	require.Equal(t, http.StatusNotFound, refused.Code, refused.Body.String())
}

// T-files-1: the file-listing and file-content endpoints both resolve
// through queries.LatestBundle, so a caller who cannot read the package
// cannot read its files either — the same 404 the detail screen gives.
func TestPackageFileEndpointsRefuseAPrivatePackageNotOwnedByTheCaller(t *testing.T) {
	owner := principalFor(t, an).IdentityID
	id, key, packed := probePackage(t, "filesprobe", "guarded-files", models.PackageVisibilityPrivate, &owner)
	handler := liveHandler(t, map[string][]byte{key: packed})
	namespace, name, _ := strings.Cut(id, "/")

	ok := request(t, handler, http.MethodGet, "/v1/packages/"+namespace+"/"+name+"/files", an.token, "")
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())

	refusedList := request(t, handler, http.MethodGet, "/v1/packages/"+namespace+"/"+name+"/files", kw.token, "")
	require.Equal(t, http.StatusNotFound, refusedList.Code, refusedList.Body.String())

	refusedContent := request(t, handler, http.MethodGet,
		"/v1/packages/"+namespace+"/"+name+"/files/content?path=SKILL.md", kw.token, "")
	require.Equal(t, http.StatusNotFound, refusedContent.Code, refusedContent.Body.String())
}

// T-owner-2: a package seeded before this column existed carries no owner,
// and must stay visible to everyone rather than becoming invisible or
// accidentally private. designPackages predates owner_identity_id entirely.
func TestAnOwnerLessOrganisationPackagePredatingTheColumnStaysVisibleToEveryone(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	var ownerIDText string
	require.NoError(t, pool.QueryRow(t.Context(),
		`select coalesce(owner_identity_id::text, '') from package
		  where namespace = 'example' and name = 'platform-toolkit'`).Scan(&ownerIDText))
	require.Empty(t, ownerIDText, "a package seeded before this column existed carries no owner")

	for _, who := range []actor{kw, an, contractor} {
		page := catalog(t, handler, who.token, query("q", "platform-toolkit", "pageSize", "50"))
		require.Containsf(t, idsOf(page), "example/platform-toolkit",
			"an owner-less organisation-visibility package must stay visible to %s", who.claims.Email)
	}
}

// T-change-1: FR-126 and constitution principle IV — changing an existing
// package's visibility is gated to its owner or a catalog admin, refuses
// everyone else naming who may act, and writes exactly one audit row.
func TestChangingVisibilityIsGatedToTheOwnerOrACatalogAdminAndWritesOneAuditRow(t *testing.T) {
	owner := principalFor(t, curator).IdentityID // curator: eng-platform, not a catalog admin
	id, _, _ := probePackage(t, "visctl", "governed-skill", models.PackageVisibilityOrganisation, &owner)
	path := "/v1/packages/" + id + "/visibility"

	refusalBody := send(t, an, http.MethodPut, path, `{"visibility":"private"}`, http.StatusForbidden)
	var refusal contract.Error
	require.NoError(t, json.Unmarshal(refusalBody, &refusal))
	require.Contains(t, refusal.Detail, "owner",
		"the caller can already see the package (it answered 200 on the GET); the only useful "+
			"thing left to say is who may act on it")

	before := countRows(t, "select count(*) from audit_event where kind = 'share'")

	changed := sendJSON[contract.PackageDetail](t, curator, http.MethodPut, path,
		`{"visibility":"private"}`, http.StatusOK)
	require.Equal(t, "private", changed.Visibility)
	require.Equal(t, before+1, countRows(t, "select count(*) from audit_event where kind = 'share'"),
		"a visibility change is a state change and writes exactly one audit row, same as registration")

	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindShare), kind)
	require.Equal(t, curator.claims.Email, who)
	require.Contains(t, text, id)

	// A catalog admin may act on a package it does not own.
	back := sendJSON[contract.PackageDetail](t, kw, http.MethodPut, path,
		`{"visibility":"organisation"}`, http.StatusOK)
	require.Equal(t, "organisation", back.Visibility)
}

// T-change-2: an owner-less package may not be narrowed past organisation —
// team and private are both enforced by matching a reader against the
// OWNER, so narrowing one with no owner would make it invisible to
// everyone, including the catalog admin who just narrowed it.
func TestAnOwnerLessPackageMayNotBeNarrowedPastOrganisation(t *testing.T) {
	id, _, _ := probePackage(t, "noownerctl", "adrift-skill", models.PackageVisibilityOrganisation, nil)
	path := "/v1/packages/" + id + "/visibility"

	rec := send(t, kw, http.MethodPut, path, `{"visibility":"private"}`, http.StatusUnprocessableEntity)
	var refusal contract.Error
	require.NoError(t, json.Unmarshal(rec, &refusal))
	require.Contains(t, refusal.Detail, "no recorded owner")
}

// T-profile-1: a package already resolved into a shared profile must stop
// resolving there the instant its visibility narrows past what the reader
// may see — a private package in a shared profile is a leak through a
// different door if the resolver still hands over its version, digest and
// verdict to a reader who could no longer open the package directly. The
// entry stays LISTED (a curator may still see which packages the profile
// names) but resolves to nothing, the same generic "nothing to resolve"
// state an unpublished package already produces.
func TestNarrowingAPackagesVisibilityAfterItIsInAProfileStopsItResolvingForOtherReaders(t *testing.T) {
	owner := principalFor(t, kw).IdentityID
	id, _, _ := probePackage(t, "narrowprobe", "narrows-in-profile", models.PackageVisibilityOrganisation, &owner)

	slug := "curate/narrow-profile"
	sendJSON[contract.Profile](t, kw, http.MethodPost, "/v1/profiles",
		fmt.Sprintf(`{"slug":%q,"name":"Narrow Profile","visibility":"organisation"}`, slug),
		http.StatusCreated)
	dropProfileOnCleanup(t, slug)
	setEntries(t, kw, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, id), http.StatusOK)

	before := profileDetail(t, an, slug)
	beforeEntry := entryByID(t, before, id)
	require.Equal(t, "1.0.0", beforeEntry.Version, "an organisation-visible package resolves for any reader")
	require.Equal(t, "resolved", beforeEntry.Outcome)

	sendJSON[contract.PackageDetail](t, kw, http.MethodPut, "/v1/packages/"+id+"/visibility",
		`{"visibility":"private"}`, http.StatusOK)

	after := profileDetail(t, an, slug)
	narrowed := entryByID(t, after, id)
	require.Empty(t, narrowed.Version,
		"a package narrowed to private after joining a profile must stop resolving for a reader who is not its owner")
	require.Equal(t, "skipped", narrowed.Outcome)
	require.NotNil(t, narrowed.Skip)
	require.Equal(t, "no-clean-version-available", narrowed.Skip.Reason,
		"the same generic reason an unpublished package gets — never a distinguishable visibility reason")

	stillMine := profileDetail(t, kw, slug)
	require.Equal(t, "1.0.0", entryByID(t, stillMine, id).Version,
		"private means visible to the owner, not invisible to everyone including them")
}
