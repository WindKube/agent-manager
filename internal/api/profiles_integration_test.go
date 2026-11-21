//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The profile write path against a real Postgres: readability as 404 on every path, the gate's
// effect computed by the resolver rather than SQL, revisions as the only thing machines sync,
// concurrent publishes, and forks as copies rather than subscriptions.

// curated writes its package rows directly rather than through the fetcher, because ingestion
// is not under test here.
type curated struct {
	id        string
	packageID uuid.UUID
	versions  map[string]uuid.UUID
}

type curatedVersion struct {
	semver    string
	verdict   models.Verdict
	visible   bool
	latest    bool
	flaggedBy string
}

func curatePackage(t *testing.T, name string, versions ...curatedVersion) curated {
	t.Helper()
	ctx := context.Background()

	publisher := &models.Publisher{
		ID: models.NewID(), Slug: "curate/team-" + name, DisplayName: "Curate " + name,
	}
	_, err := db.NewInsert().Model(publisher).Exec(ctx)
	require.NoError(t, err)
	dropOnCleanup(t, publisher.ID)

	pkg := &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: "curate", Name: name,
		Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
	}
	_, err = db.NewInsert().Model(pkg).Exec(ctx)
	require.NoError(t, err)

	out := curated{id: "curate/" + name, packageID: pkg.ID, versions: map[string]uuid.UUID{}}
	for _, spec := range versions {
		sortable, sortErr := models.SemverSort(spec.semver)
		require.NoError(t, sortErr)
		version := &models.Version{
			ID:         models.NewID(),
			PackageID:  pkg.ID,
			Semver:     spec.semver,
			SemverSort: sortable,
			ObjectKey:  fmt.Sprintf("skills/curate/%s/%s/bundle.tar.zst", name, spec.semver),
			Digest:     bundleSHA,
			Manifest:   json.RawMessage(`{"name":"` + name + `"}`),
			DistTag:    models.DistTagNone,
			Verdict:    spec.verdict,
			Visible:    spec.visible,
		}
		if spec.latest {
			version.DistTag = models.DistTagLatest
		}
		_, err = db.NewInsert().Model(version).Exec(ctx)
		require.NoError(t, err)
		out.versions[spec.semver] = version.ID

		if spec.latest {
			_, err = db.NewUpdate().Model((*models.Package)(nil)).
				Set("latest_version_id = ?", version.ID).Where("id = ?", pkg.ID).Exec(ctx)
			require.NoError(t, err)
		}
		if spec.flaggedBy == "" {
			continue
		}

		scan := &models.Scan{
			ID: models.NewID(), VersionID: version.ID, PackVersion: "1.4.0",
			Verdict: spec.verdict,
		}
		_, err = db.NewInsert().Model(scan).Exec(ctx)
		require.NoError(t, err)
		_, err = db.NewInsert().Model(&models.Finding{
			ID: models.NewID(), ScanID: scan.ID, VersionID: version.ID,
			RuleID: spec.flaggedBy, Severity: models.FindingSeverityHigh,
			Title: "Something the scanner did not like", EvidencePath: "SKILL.md",
			State: models.FindingStateOpen,
		}).Exec(ctx)
		require.NoError(t, err)
	}
	return out
}

// dropOnCleanup removes everything one curated publisher put in the catalog. Other tests
// assert catalog totals, so a leftover package breaks them under -shuffle=on. Deletes run
// deepest first because the foreign keys are NO ACTION.
func dropOnCleanup(t *testing.T, publisherID uuid.UUID) {
	t.Helper()

	t.Cleanup(func() {
		for _, statement := range []string{
			`update package set latest_version_id = null where publisher_id = ?`,
			`delete from profile_entry where package_id in (
			   select id from package where publisher_id = ?)`,
			`delete from override where finding_id in (
			   select f.id from finding f join version v on v.id = f.version_id
			   join package p on p.id = v.package_id where p.publisher_id = ?)`,
			`delete from finding where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from scan where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from version where package_id in (select id from package where publisher_id = ?)`,
			`delete from package where publisher_id = ?`,
			`delete from publisher where id = ?`,
		} {
			_, err := db.ExecContext(context.Background(), statement, publisherID)
			require.NoError(t, err)
		}
	})
}

// dropProfileOnCleanup removes one profile this file created. forked_from_id is nulled first
// because a fork created by a raw POST registers no cleanup and would block the upstream's.
func dropProfileOnCleanup(t *testing.T, slug string) {
	t.Helper()

	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(),
			`update profile set forked_from_id = null
			  where forked_from_id in (select id from profile where slug = ?)`, slug)
		require.NoError(t, err)

		for _, table := range []string{"profile_entry", "membership", "sync_target", "revision"} {
			_, err = db.ExecContext(context.Background(),
				`delete from `+table+` where profile_id in (select id from profile where slug = ?)`,
				slug)
			require.NoError(t, err)
		}
		_, err = db.ExecContext(context.Background(), `delete from profile where slug = ?`, slug)
		require.NoError(t, err)
	})
}

// profilePath escapes the slug, which carries several segments, into one path parameter.
func profilePath(slug string, suffix ...string) string {
	out := "/v1/profiles/" + url.PathEscape(slug)
	for _, part := range suffix {
		out += "/" + part
	}
	return out
}

// profileAuditCount counts only profile and sharing audit rows, so unrelated audit writes
// during the run cannot make a delta look right.
func profileAuditCount(t *testing.T) int {
	t.Helper()
	return countRows(t, "select count(*) from audit_event where kind in ('profile', 'share')")
}

func latestAuditRow(t *testing.T) (kind, actor, text string) {
	t.Helper()

	require.NoError(t, pool.QueryRow(context.Background(),
		`select kind::text, actor, text from audit_event
		  where kind in ('profile', 'share') order by occurred_at desc, id desc limit 1`).
		Scan(&kind, &actor, &text))
	return kind, actor, text
}

func send(t *testing.T, who actor, method, path, body string, want int) []byte {
	t.Helper()

	rec := request(t, liveHandler(t), method, path, who.token, body)
	require.Equalf(t, want, rec.Code, "%s %s answered %s", method, path, rec.Body.String())
	return rec.Body.Bytes()
}

func sendJSON[T any](t *testing.T, who actor, method, path, body string, want int) T {
	t.Helper()

	var out T
	raw := send(t, who, method, path, body, want)
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func newProfile(t *testing.T, who actor, slug, name string) contract.ProfileDetail {
	t.Helper()

	body := fmt.Sprintf(`{"slug":%q,"name":%q}`, slug, name)
	sendJSON[contract.Profile](t, who, http.MethodPost, "/v1/profiles", body, http.StatusCreated)

	dropProfileOnCleanup(t, slug)
	return profileDetail(t, who, slug)
}

func profileDetail(t *testing.T, who actor, slug string) contract.ProfileDetail {
	t.Helper()
	return sendJSON[contract.ProfileDetail](t, who, http.MethodGet, profilePath(slug), "", http.StatusOK)
}

func profileList(t *testing.T, who actor) contract.ProfileList {
	t.Helper()
	return sendJSON[contract.ProfileList](t, who, http.MethodGet, "/v1/profiles", "", http.StatusOK)
}

func findProfile(t *testing.T, list contract.ProfileList, slug string) contract.Profile {
	t.Helper()
	for _, profile := range list.Profiles {
		if profile.Slug == slug {
			return profile
		}
	}
	t.Fatalf("%s is not in this identity's own readable list", slug)
	return contract.Profile{}
}

func setEntries(t *testing.T, who actor, slug, entries string, want int) []byte {
	t.Helper()
	return send(t, who, http.MethodPut, profilePath(slug, "entries"),
		`{"entries":`+entries+`}`, want)
}

func publish(t *testing.T, who actor, slug, note string) contract.Lockfile {
	t.Helper()
	return sendJSON[contract.Lockfile](t, who, http.MethodPost, profilePath(slug, "revisions"),
		fmt.Sprintf(`{"note":%q}`, note), http.StatusCreated)
}

func entryByID(t *testing.T, detail contract.ProfileDetail, id string) contract.ProfileEntry {
	t.Helper()

	for i := range detail.Entries {
		if detail.Entries[i].ID == id {
			return detail.Entries[i]
		}
	}
	t.Fatalf("%s holds no entry %s", detail.Slug, id)
	return contract.ProfileEntry{}
}

// A 403 would confirm that a private profile with this slug exists, so a profile someone
// else owns must answer exactly like a slug nobody has used, down to the body.
func TestAProfileThisIdentityMayNotReadAnswersExactlyAsOneThatDoesNotExist(t *testing.T) {
	slug := "curate/hidden-from-kw"
	newProfile(t, curator, slug, "Hidden")

	hidden := send(t, kw, http.MethodGet, profilePath(slug), "", http.StatusNotFound)
	absent := send(t, kw, http.MethodGet, profilePath("curate/no-such-profile"), "",
		http.StatusNotFound)

	var hiddenBody, absentBody contract.Error
	require.NoError(t, json.Unmarshal(hidden, &hiddenBody))
	require.NoError(t, json.Unmarshal(absent, &absentBody))
	hiddenBody.CorrelationID, absentBody.CorrelationID = "", ""
	require.Equal(t, absentBody, hiddenBody,
		"the two answers differ, so a client can tell a private profile from a missing one")

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPut, profilePath(slug, "entries"), `{"entries":[]}`},
		{http.MethodPut, profilePath(slug, "sharing"),
			`{"members":[{"kind":"user","ref":"kwiatrzyk@example.com","role":"owner"}]}`},
		{http.MethodPut, profilePath(slug, "targets"), `{"targets":[]}`},
		{http.MethodPost, profilePath(slug, "revisions"), `{}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			send(t, kw, tc.method, tc.path, tc.body, http.StatusNotFound)
		})
	}
}

// The gate's effect on the screen is computed by internal/domain/resolve, not restated in SQL.
// Neither row below is producible by a plausible SQL predicate: a pin at a rejected version is
// excluded naming the version, and a flagged version under warn-with-override resolves with a note.
func TestTheProfileDetailStatesWhatTheGateDidByCallingTheResolver(t *testing.T) {
	guard := curatePackage(t, "gate-guard",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true},
		curatedVersion{semver: "1.1.0", verdict: models.VerdictFlagged, visible: true,
			latest: true, flaggedBy: "SH-SQL-004"},
	)
	doomed := curatePackage(t, "gate-doomed",
		curatedVersion{semver: "0.9.0", verdict: models.VerdictRejected, visible: true, latest: true},
	)

	slug := "curate/gate-effects"
	newProfile(t, curator, slug, "Gate effects")
	setEntries(t, curator, slug, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"pinned","version":"0.9.0"}]`,
		guard.id, doomed.id), http.StatusOK)

	detail := profileDetail(t, curator, slug)
	require.Equal(t, string(models.ScanGateWarnWithOverride), detail.Gate)

	flagged := entryByID(t, detail, guard.id)
	require.Equal(t, "warned", flagged.Outcome,
		"warn-with-override INCLUDES a flagged version; the screen must say it did")
	require.Equal(t, "1.1.0", flagged.Version)
	require.Equal(t, string(models.VerdictFlagged), flagged.Verdict)
	require.Nil(t, flagged.Skip)
	require.Contains(t, flagged.Note, "SH-SQL-004",
		"the note has to name the finding, or the row states a policy with no reason")
	require.Contains(t, flagged.Note, "SKILL.md")
	// The Scan badge is the catalog's answer; the resolution is the gate's.
	require.Equal(t, "1.1.0", flagged.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), flagged.LatestVerdict)

	rejected := entryByID(t, detail, doomed.id)
	require.Equal(t, "skipped", rejected.Outcome)
	require.NotNil(t, rejected.Skip, "an excluded package is reported, never omitted")
	require.Equal(t, "version-rejected", rejected.Skip.Reason)
	require.Equal(t, "0.9.0", rejected.Skip.WouldHaveResolvedTo,
		"a pin is never re-pointed, so the exclusion has to name what the owner asked for")
	require.Empty(t, rejected.Version, "a skipped entry resolves to nothing")
	require.Equal(t, "pinned", rejected.Mode,
		"a pin the gate refused is still a pin; relabelling it would hide the conflict")
	require.NotEmpty(t, rejected.Note)

	require.Len(t, detail.Entries, 2)
}

func TestCreatingAProfileMakesItsAuthorTheOwnerAndWritesOneAuditRow(t *testing.T) {
	before := profileAuditCount(t)

	detail := newProfile(t, curator, "curate/owned", "Owned")
	require.Equal(t, before+1, profileAuditCount(t),
		"a create must write exactly one audit row: zero leaves the action unaccounted for")
	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindProfile), kind)
	require.Equal(t, curator.claims.Email, who,
		"the row names the person, not the service account the tx ran as")
	require.Contains(t, text, "curate/owned")

	require.Equal(t, string(models.ProfileVisibilityPrivate), detail.Visibility,
		"a profile nobody has chosen to publish is not readable by the whole organisation")
	require.Equal(t, string(models.MembershipRoleOwner), detail.Role)
	require.Equal(t, contract.ProfilePermissions{Curate: true, Share: true, Publish: true, Delete: true},
		detail.Permissions, "an owner may delete outright; the has-revisions refusal is a separate, later check")
	require.Equal(t, 0, detail.HeadRevision)
	require.True(t, detail.UnpublishedChanges, "nothing has been published, so a revision is owed")
	require.Equal(t, []contract.ProfileMember{{
		Kind: string(models.SubjectKindUser), Ref: curator.claims.Email,
		Role: string(models.MembershipRoleOwner), DisplayName: curator.claims.Name,
	}}, detail.Members)

	// Without the owner membership the profile would be permanently uneditable: am_api holds no
	// DELETE on membership to repair it.
	require.Equal(t, 1, countRows(t, `
select count(*) from membership as m
join profile as p on p.id = m.profile_id
where p.slug = 'curate/owned' and m.role = 'owner'`))
}

func TestASlugThatIsTakenIsRefusedRatherThanReusedForASecondProfile(t *testing.T) {
	newProfile(t, curator, "curate/taken", "Taken")

	before := profileAuditCount(t)
	send(t, curator, http.MethodPost, "/v1/profiles",
		`{"slug":"curate/taken","name":"Also taken"}`, http.StatusConflict)
	require.Equal(t, before, profileAuditCount(t),
		"a refused create must write nothing: an audit row for a profile that was not created "+
			"is indistinguishable from a real one")
}

// The upstream publishes after the fork is taken, and the fork must gain neither its entries
// nor a revision.
func TestAForkTakesTheUpstreamsEntriesOnceAndNoLaterRevisionOfIt(t *testing.T) {
	first := curatePackage(t, "fork-first",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})
	second := curatePackage(t, "fork-second",
		curatedVersion{semver: "2.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	upstream := "curate/fork-upstream"
	newProfile(t, curator, upstream, "Upstream")
	setEntries(t, curator, upstream, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, first.id),
		http.StatusOK)
	publish(t, curator, upstream, "the state the fork is taken from")

	sendJSON[contract.Profile](t, curator, http.MethodPost, "/v1/profiles",
		fmt.Sprintf(`{"slug":"curate/fork-downstream","name":"Downstream","forkOf":%q}`, upstream),
		http.StatusCreated)
	dropProfileOnCleanup(t, "curate/fork-downstream")

	fork := profileDetail(t, curator, "curate/fork-downstream")
	require.Equal(t, upstream, fork.ForkedFrom, "lineage is recorded")
	require.Len(t, fork.Entries, 1, "the fork took the upstream's entries")
	require.Equal(t, first.id, fork.Entries[0].ID)
	require.Equal(t, 0, fork.HeadRevision,
		"a fork inherits no revision, not even the one that existed when it was taken")

	setEntries(t, curator, upstream, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"latest"}]`, first.id, second.id),
		http.StatusOK)
	after := publish(t, curator, upstream, "a revision the fork must never see")
	require.Equal(t, 2, after.Revision)
	require.Len(t, after.Entries, 2)

	unchanged := profileDetail(t, curator, "curate/fork-downstream")
	require.Len(t, unchanged.Entries, 1,
		"the fork gained the upstream's new package, so something is subscribing it")
	require.Equal(t, 0, unchanged.HeadRevision)
	require.Empty(t, unchanged.Revisions)

	own := publish(t, curator, "curate/fork-downstream", "the fork's own first")
	require.Equal(t, 1, own.Revision, "the fork's sequence starts at 1, unrelated to the upstream's")
	require.Len(t, own.Entries, 1)
	require.Equal(t, "curate/fork-downstream", own.Profile.Slug)
}

func TestTogglingAPinChangesTheResolutionAndNothingAMachineSyncsUntilItIsPublished(t *testing.T) {
	pkg := curatePackage(t, "pin-toggle",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true},
		curatedVersion{semver: "2.0.0", verdict: models.VerdictClean, visible: true, latest: true},
	)

	slug := "curate/pin-toggle"
	newProfile(t, curator, slug, "Pin toggle")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)
	published := publish(t, curator, slug, "floating")
	require.Equal(t, "2.0.0", published.Entries[0].Version)

	settled := profileDetail(t, curator, slug)
	require.False(t, settled.UnpublishedChanges, "nothing has moved since the publish")
	require.False(t, entryByID(t, settled, pkg.id).Unpublished)

	drafted := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut,
		profilePath(slug, "entries"),
		fmt.Sprintf(`{"entries":[{"id":%q,"mode":"pinned","version":"1.0.0"}]}`, pkg.id),
		http.StatusOK)

	entry := entryByID(t, drafted, pkg.id)
	require.Equal(t, "1.0.0", entry.Version, "the displayed resolved version follows the pin")
	require.Equal(t, "pinned", entry.Mode)
	require.True(t, entry.Unpublished)
	require.True(t, drafted.UnpublishedChanges)

	// What a machine can still fetch is the old resolution.
	head := sendJSON[contract.Lockfile](t, curator, http.MethodGet,
		profilePath(slug, "revisions", "head"), "", http.StatusOK)
	require.Equal(t, 1, head.Revision)
	require.Equal(t, "2.0.0", head.Entries[0].Version,
		"the draft reached the lockfile, so the change was durable before anybody published it")

	frozen := publish(t, curator, slug, "pinned to 1.0.0")
	require.Equal(t, 2, frozen.Revision)
	require.Equal(t, "1.0.0", frozen.Entries[0].Version)
	require.Equal(t, "pinned", frozen.Entries[0].Resolution)

	settled = profileDetail(t, curator, slug)
	require.False(t, settled.UnpublishedChanges)
	require.False(t, entryByID(t, settled, pkg.id).Unpublished)
}

func TestACurationRequestIsRefusedForEverythingItCouldGetWrong(t *testing.T) {
	pkg := curatePackage(t, "curation-refusals",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})
	other := curatePackage(t, "curation-second",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/refusals"
	newProfile(t, curator, slug, "Refusals")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	for _, tc := range []struct{ name, entries, says string }{
		{
			name:    "a package this hub has never heard of",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"latest"},{"id":"curate/imaginary","mode":"latest"}]`, pkg.id),
			says:    "curate/imaginary",
		},
		{
			name:    "a pin at a version this hub does not hold",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"pinned","version":"9.9.9"}]`, pkg.id),
			says:    "9.9.9",
		},
		{
			name:    "a pin with nothing to pin to",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"pinned"}]`, pkg.id),
			says:    "needs the version",
		},
		{
			name:    "a range that is not a constraint",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"range","version":"not a range"}]`, pkg.id),
			says:    "not a constraint",
		},
		{
			name:    "the same package twice, so its position is undefined",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"pinned","version":"1.0.0"}]`, pkg.id, pkg.id),
			says:    "named twice",
		},
		{
			// am_api holds no DELETE on profile_entry, so a silent 200 would leave the stored set
			// disagreeing with the accepted request.
			name:    "a request that leaves out a package the profile holds",
			entries: fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, other.id),
			says:    pkg.id,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := setEntries(t, curator, slug, tc.entries, http.StatusUnprocessableEntity)

			var body contract.Error
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Contains(t, body.Detail, tc.says,
				"the refusal has to name what was wrong with the request")
		})
	}

	after := profileDetail(t, curator, slug)
	require.Len(t, after.Entries, 1)
	require.Equal(t, pkg.id, after.Entries[0].ID)
	require.Equal(t, "latest", after.Entries[0].Mode)
}

// punter is catalog-admin with only a consumer membership here and still may not publish:
// the organisation role never stands in for a profile membership.
func TestOnlyTheRolesFR037NamesMayCurateShareOrPublish(t *testing.T) {
	pkg := curatePackage(t, "sharing-subject",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/shared"
	newProfile(t, curator, slug, "Shared")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	before := profileAuditCount(t)
	shared := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"maintainer"},
		                         {"kind":"user","ref":%q,"role":"consumer"},
		                         {"kind":"group","ref":"eng-security","role":"reviewer"}]}`,
			mate.claims.Email, punter.claims.Email),
		http.StatusOK)
	require.Equal(t, before+1, profileAuditCount(t), "sharing writes exactly one audit row")
	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindShare), kind,
		"a sharing change is searchable as sharing, not folded into every other profile edit")
	require.Equal(t, curator.claims.Email, who)
	require.Contains(t, text, slug)
	require.Len(t, shared.Members, 4)

	entries := fmt.Sprintf(`{"entries":[{"id":%q,"mode":"pinned","version":"1.0.0"}]}`, pkg.id)
	sharing := `{"members":[{"kind":"user","ref":"someone@example.com","role":"consumer"}]}`

	for _, tc := range []struct {
		name                           string
		who                            actor
		role                           models.MembershipRole
		curate, share, publish, delete bool
	}{
		{"the owner", curator, models.MembershipRoleOwner, true, true, true, true},
		{"a maintainer curates and publishes and does not re-share or delete", mate,
			models.MembershipRoleMaintainer, true, false, true, false},
		{"a consumer holding the organisation's top role still may not publish or delete", punter,
			models.MembershipRoleConsumer, false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail := profileDetail(t, tc.who, slug)
			require.Equal(t, string(tc.role), detail.Role)
			require.Equal(t, contract.ProfilePermissions{
				Curate: tc.curate, Share: tc.share, Publish: tc.publish, Delete: tc.delete,
			}, detail.Permissions, "the screen is told what it may offer")

			// The bulk list carries the same permissions, so callers need not read every detail.
			row := findProfile(t, profileList(t, tc.who), slug)
			require.Equal(t, tc.curate, row.CanCurate,
				"the list's canCurate must agree with the detail's Permissions.Curate")

			for _, attempt := range []struct {
				what, method, path, body string
				allowed                  bool
				ok                       int
			}{
				{"curate", http.MethodPut, profilePath(slug, "entries"), entries, tc.curate, http.StatusOK},
				{"targets", http.MethodPut, profilePath(slug, "targets"), `{"targets":["codex"]}`,
					tc.curate, http.StatusOK},
				{"share", http.MethodPut, profilePath(slug, "sharing"), sharing, tc.share, http.StatusOK},
				{"publish", http.MethodPost, profilePath(slug, "revisions"), `{}`, tc.publish,
					http.StatusCreated},
			} {
				want := http.StatusForbidden
				if attempt.allowed {
					want = attempt.ok
				}
				raw := send(t, tc.who, attempt.method, attempt.path, attempt.body, want)
				if attempt.allowed {
					continue
				}
				var body contract.Error
				require.NoError(t, json.Unmarshal(raw, &body))
				require.Contains(t, body.Detail, string(tc.role),
					"the refusal has to name the role this identity holds")
			}
		})
	}
}

// Nothing can remove a membership, so demoting the last owner would freeze sharing forever.
func TestSharingMayNotLeaveAProfileWithNoOwner(t *testing.T) {
	slug := "curate/last-owner"
	newProfile(t, curator, slug, "Last owner")

	raw := send(t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"maintainer"}]}`,
			curator.claims.Email),
		http.StatusUnprocessableEntity)

	var body contract.Error
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body.Detail, "no owner")

	require.Equal(t, string(models.MembershipRoleOwner), profileDetail(t, curator, slug).Role,
		"the refused demotion must not have half-applied")

	sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"owner"}]}`, mate.claims.Email),
		http.StatusOK)
	sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"maintainer"}]}`,
			curator.claims.Email),
		http.StatusOK)
	require.Equal(t, string(models.MembershipRoleMaintainer),
		profileDetail(t, curator, slug).Role)
}

// A target affects only what a client writes, never what the server resolves.
func TestChangingSyncTargetsChangesTheClientInstructionAndNothingTheServerResolves(t *testing.T) {
	pkg := curatePackage(t, "target-subject",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/targets"
	newProfile(t, curator, slug, "Targets")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	// The whole target vocabulary is reported so a screen need not hard-code the enum.
	fresh := profileDetail(t, curator, slug)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex)},
		{Target: string(models.SyncTargetKindOpenCode)},
	}, fresh.Targets)

	both := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":["codex","claude-code"]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode), Enabled: true},
		{Target: string(models.SyncTargetKindCodex), Enabled: true},
		{Target: string(models.SyncTargetKindOpenCode)},
	}, both.Targets, "the answer is in the vocabulary's order, not in the order they were sent")

	first := publish(t, curator, slug, "both targets")
	require.Equal(t, []string{"claude-code", "codex"}, first.Targets)

	// An omitted target is disabled rather than removed, since there is no DELETE grant.
	one := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":["codex"]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex), Enabled: true},
		{Target: string(models.SyncTargetKindOpenCode)},
	}, one.Targets)

	second := publish(t, curator, slug, "codex only")
	require.Equal(t, []string{"codex"}, second.Targets)
	require.Equal(t, first.Entries, second.Entries,
		"a target change moved a resolved version, so it is not client-side")
	require.Equal(t, first.Skipped, second.Skipped)

	withOpenCode := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":["opencode","claude-code"]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode), Enabled: true},
		{Target: string(models.SyncTargetKindCodex)},
		{Target: string(models.SyncTargetKindOpenCode), Enabled: true},
	}, withOpenCode.Targets)
	require.Equal(t, []string{"claude-code", "opencode"}, publish(t, curator, slug, "opencode").Targets)

	none := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":[]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex)},
		{Target: string(models.SyncTargetKindOpenCode)},
	}, none.Targets)
	require.Equal(t, []string{}, publish(t, curator, slug, "nothing").Targets)
}

func TestEachPublishWritesTheNextRevisionAndLeavesEveryPreviousOneReadable(t *testing.T) {
	first := curatePackage(t, "revision-first",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})
	second := curatePackage(t, "revision-second",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/revisions"
	newProfile(t, curator, slug, "Revisions")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, first.id), http.StatusOK)

	before := profileAuditCount(t)
	r1 := publish(t, curator, slug, "first")
	require.Equal(t, before+1, profileAuditCount(t), "a publish writes exactly one audit row")
	require.Equal(t, 1, r1.Revision)

	setEntries(t, curator, slug, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"latest"}]`, first.id, second.id),
		http.StatusOK)
	r2 := publish(t, curator, slug, "second")
	require.Equal(t, 2, r2.Revision)

	stored := sendJSON[contract.Lockfile](t, curator, http.MethodGet,
		profilePath(slug, "revisions", "1"), "", http.StatusOK)
	require.Equal(t, r1, stored,
		"the published document and the one a client fetches back have to be the same bytes")
	require.Len(t, stored.Entries, 1)
	require.Len(t, r2.Entries, 2)

	head := sendJSON[contract.Lockfile](t, curator, http.MethodGet,
		profilePath(slug, "revisions", "head"), "", http.StatusOK)
	require.Equal(t, r2, head)

	detail := profileDetail(t, curator, slug)
	require.Equal(t, 2, detail.HeadRevision)
	require.Equal(t, []int{2, 1}, []int{detail.Revisions[0].Revision, detail.Revisions[1].Revision},
		"the history is most recent first")
	require.Equal(t, "first", detail.Revisions[1].Note)
	require.Equal(t, curator.claims.Email, detail.Revisions[0].PublishedBy)

	// Republishing a number is refused by the database, not by a branch.
	_, err := pool.Exec(context.Background(), `
insert into revision (id, profile_id, seq, lockfile, object_key, created_by)
select $1, id, 2, '{}'::jsonb, 'profiles/curate/revisions/r2.json', 'a-second-writer'
from profile where slug = $2`, models.NewID(), slug)
	require.ErrorContains(t, err, "revision_profile_seq",
		"r2 was overwritten or duplicated; a published revision is final")
}

// select ... for update serialises concurrent publishes, and the sequence must be read in its
// own statement afterwards so it sees a fresh snapshot; reading it beside the lock 500s under contention.
func TestTwoPublishesRacingProduceTwoConsecutiveRevisionsWithNoGap(t *testing.T) {
	pkg := curatePackage(t, "race-subject",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/race"
	newProfile(t, curator, slug, "Race")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	const racers = 4
	var (
		wait      sync.WaitGroup
		mutex     sync.Mutex
		codes     []int
		revisions []int
	)
	handler := liveHandler(t)
	wait.Add(racers)
	for i := range racers {
		go func() {
			defer wait.Done()
			rec := request(t, handler, http.MethodPost, profilePath(slug, "revisions"),
				curator.token, fmt.Sprintf(`{"note":"racer %d"}`, i))

			mutex.Lock()
			defer mutex.Unlock()
			codes = append(codes, rec.Code)
			var body contract.Lockfile
			if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
				revisions = append(revisions, body.Revision)
			}
		}()
	}
	wait.Wait()

	require.Equal(t, []int{201, 201, 201, 201}, codes,
		"a publish lost the race and answered %v; the lock is meant to serialise them, "+
			"not to let one fail on the unique index", codes)
	require.ElementsMatch(t, []int{1, 2, 3, 4}, revisions,
		"the sequence has to be gapless and each number used once (data-model.md)")
	require.Equal(t, racers, countRows(t, `
select count(*) from revision as r join profile as p on p.id = r.profile_id
where p.slug = 'curate/race'`))
}

// What the revision froze is what the screen was displaying, because both come from one function.
func TestThePublishedLockfileIsTheResolutionTheScreenWasShowing(t *testing.T) {
	guard := curatePackage(t, "displayed-guard",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true},
		curatedVersion{semver: "1.1.0", verdict: models.VerdictFlagged, visible: true,
			latest: true, flaggedBy: "SH-NET-002"},
	)
	doomed := curatePackage(t, "displayed-doomed",
		curatedVersion{semver: "0.9.0", verdict: models.VerdictRejected, visible: true, latest: true})

	slug := "curate/displayed"
	newProfile(t, curator, slug, "Displayed")
	setEntries(t, curator, slug, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"pinned","version":"0.9.0"}]`,
		guard.id, doomed.id), http.StatusOK)

	displayed := profileDetail(t, curator, slug)
	frozen := publish(t, curator, slug, "what the screen said")

	require.Len(t, frozen.Entries, 1)
	require.Len(t, frozen.Skipped, 1)

	resolved := entryByID(t, displayed, guard.id)
	require.Equal(t, resolved.Version, frozen.Entries[0].Version)
	require.Equal(t, resolved.Verdict, frozen.Entries[0].Verdict)
	require.Equal(t, resolved.Mode, frozen.Entries[0].Resolution)
	require.Equal(t, resolved.Digest, frozen.Entries[0].Digest)

	excluded := entryByID(t, displayed, doomed.id)
	require.Equal(t, *excluded.Skip, frozen.Skipped[0],
		"the screen's exclusion and the lockfile's are the same shape for exactly this reason")

	require.Equal(t, displayed.Gate, frozen.Gate)
	require.Equal(t, displayed.DefaultPolicy, frozen.DefaultPolicy)
	require.Equal(t, displayed.Slug, frozen.Profile.Slug)
}

// removeEntry posts the dedicated remove command, since SetProfileEntries refuses a body that
// omits a held entry.
func removeEntry(t *testing.T, who actor, slug, id string, want int) []byte {
	t.Helper()
	return send(t, who, http.MethodPost, profilePath(slug, "entries", "remove"),
		fmt.Sprintf(`{"id":%q}`, id), want)
}

func TestRemovingAnEntryTakesOutExactlyThatPackageAndWritesAnAuditRow(t *testing.T) {
	first := curatePackage(t, "remove-first",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})
	second := curatePackage(t, "remove-second",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/remove-entry"
	newProfile(t, curator, slug, "Remove entry")
	setEntries(t, curator, slug, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"latest"}]`, first.id, second.id), http.StatusOK)

	before := profileAuditCount(t)
	detail := sendJSON[contract.ProfileDetail](t, curator, http.MethodPost,
		profilePath(slug, "entries", "remove"), fmt.Sprintf(`{"id":%q}`, first.id), http.StatusOK)
	require.Equal(t, before+1, profileAuditCount(t), "a remove must write exactly one audit row")
	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindProfile), kind)
	require.Equal(t, curator.claims.Email, who)
	require.Contains(t, text, first.id)

	require.Len(t, detail.Entries, 1, "only the untouched package is left")
	require.Equal(t, second.id, detail.Entries[0].ID)
}

func TestRemovingAnEntryNotHeldIsRefusedRatherThanANoOp(t *testing.T) {
	pkg := curatePackage(t, "remove-absent",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})
	other := curatePackage(t, "remove-not-held",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/remove-absent"
	newProfile(t, curator, slug, "Remove absent")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	raw := removeEntry(t, curator, slug, other.id, http.StatusUnprocessableEntity)
	var body contract.Error
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body.Detail, "nothing to remove")

	after := profileDetail(t, curator, slug)
	require.Len(t, after.Entries, 1, "the refused request must not have changed anything")
}

func TestRemovingAnEntryIsRefusedForARoleThatMayNotCurate(t *testing.T) {
	pkg := curatePackage(t, "remove-role",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/remove-role"
	newProfile(t, curator, slug, "Remove role")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)
	sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"consumer"}]}`, punter.claims.Email),
		http.StatusOK)

	raw := removeEntry(t, punter, slug, pkg.id, http.StatusForbidden)
	var body contract.Error
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body.Detail, "consumer")

	after := profileDetail(t, curator, slug)
	require.Len(t, after.Entries, 1, "a refused remove must not have changed anything")
}

func TestDeletingAProfileWithNoRevisionsRemovesItOutrightAndWritesAnAuditRow(t *testing.T) {
	pkg := curatePackage(t, "delete-clean",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/delete-clean"
	newProfile(t, curator, slug, "Delete clean")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	before := profileAuditCount(t)
	send(t, curator, http.MethodDelete, profilePath(slug), "", http.StatusNoContent)
	require.Equal(t, before+1, profileAuditCount(t), "a delete must write exactly one audit row")
	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindProfile), kind)
	require.Equal(t, curator.claims.Email, who)
	require.Contains(t, text, slug)

	send(t, curator, http.MethodGet, profilePath(slug), "", http.StatusNotFound)
	require.Equal(t, 0, countRows(t, fmt.Sprintf(
		`select count(*) from profile where slug = '%s'`, slug)),
		"the row itself, not only its readability, must be gone")
}

// A client may already have synced a published revision, so the database's NO ACTION foreign
// key refuses the delete; no pre-check duplicates it.
func TestDeletingAProfileWithPublishedRevisionsIsRefused(t *testing.T) {
	pkg := curatePackage(t, "delete-published",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/delete-published"
	newProfile(t, curator, slug, "Delete published")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)
	publish(t, curator, slug, "one revision, now unsyncable if deleted")

	raw := send(t, curator, http.MethodDelete, profilePath(slug), "", http.StatusConflict)
	var body contract.Error
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body.Detail, "published revisions")

	detail := profileDetail(t, curator, slug)
	require.Len(t, detail.Entries, 1)
	require.Equal(t, 1, detail.HeadRevision)
}

// MayDelete is owner-only, even for a maintainer who may curate and publish.
func TestDeletingAProfileIsRefusedForARoleThatIsNotOwner(t *testing.T) {
	slug := "curate/delete-role"
	newProfile(t, curator, slug, "Delete role")
	sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "sharing"),
		fmt.Sprintf(`{"members":[{"kind":"user","ref":%q,"role":"maintainer"}]}`, mate.claims.Email),
		http.StatusOK)

	raw := send(t, mate, http.MethodDelete, profilePath(slug), "", http.StatusForbidden)
	var body contract.Error
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body.Detail, "maintainer")

	require.Equal(t, string(models.MembershipRoleOwner), profileDetail(t, curator, slug).Role)
}
