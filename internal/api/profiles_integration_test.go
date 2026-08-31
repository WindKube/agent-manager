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

// The profile write path against a real Postgres (003 T079-T083, 001 US5).
//
// What is asserted here is what a handler-shaped test with a fake store could not
// see: that an unreadable profile is a 404 on every path rather than a filtered
// list, that the gate's effect on the screen comes out of the resolver rather
// than out of a query, that a curation change reaches no machine until a revision
// freezes it, that the revision sequence survives two publishes racing, and that
// a fork is a copy rather than a subscription.
//
// The gate MODES themselves — 001 US5 scenarios 2, 3 and 4, one test per gate —
// are T089 and are not here. What is here is the one assertion T089 rests on: the
// screen's answer is computed by internal/domain/resolve and not restated in SQL.

// ---- fixtures ----------------------------------------------------------------

// curated is a package this file registers for itself, with the versions a test
// needs. It writes rows directly rather than going through the fetcher, because
// what is under test is the profile surface and not ingestion.
type curated struct {
	id        string
	packageID uuid.UUID
	versions  map[string]uuid.UUID
}

type curatedVersion struct {
	semver  string
	verdict models.Verdict
	visible bool
	latest  bool
	// flaggedBy raises a finding on the version, so a flagged verdict has the
	// evidence a policy note is rendered from.
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

// dropOnCleanup removes everything one curated publisher put in the catalog.
//
// Not tidiness. This package's other files assert catalog TOTALS — that the
// unfiltered list is exactly the ten seeded packages, that a sort comes out in a
// known order — and a curated package left behind changes those answers. The
// suite passed anyway only because Go runs tests in source order by default, so
// the leak sat downstream of everything that counts. Under `-shuffle=on` it goes
// red immediately, and a test that depends on its own position in a file is a
// test that will fail for the next person for a reason that has nothing to do
// with what they changed.
//
// Ordered by dependency, deepest first, because the schema's foreign keys are
// NO ACTION and will refuse anything else. `latest_version_id` is nulled before
// the versions go, for the same reason.
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

// dropProfileOnCleanup removes one profile this file created.
//
// Same reason as dropOnCleanup: ListProfiles asserts the readable set is exactly
// what the seed holds, and a profile created here is in it.
//
// `forked_from_id` is nulled on any child FIRST. Cleanups run last-registered-
// first, which is the right order for a fork taken after its upstream — but a
// fork created by a raw POST rather than through newProfile registers nothing,
// and then the upstream's own cleanup dies on the lineage constraint. Nulling
// lineage costs nothing when there is no child and is the difference between a
// leak and a failure when there is one.
func dropProfileOnCleanup(t *testing.T, slug string) {
	t.Helper()

	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(),
			`update profile set forked_from_id = null
			  where forked_from_id in (select id from profile where slug = ?)`, slug)
		require.NoError(t, err)

		for _, table := range []string{"profile_entry", "membership", "sync_target", "revision"} {
			_, err := db.ExecContext(context.Background(),
				`delete from `+table+` where profile_id in (select id from profile where slug = ?)`,
				slug)
			require.NoError(t, err)
		}
		_, err = db.ExecContext(context.Background(), `delete from profile where slug = ?`, slug)
		require.NoError(t, err)
	})
}

// ---- HTTP helpers ------------------------------------------------------------

// profilePath escapes the slug the way a generated client does. A slug carries
// several segments in the representative dataset, and the frozen path template
// has one parameter for it; every caller therefore sends %2F.
func profilePath(slug string, suffix ...string) string {
	out := "/v1/profiles/" + url.PathEscape(slug)
	for _, part := range suffix {
		out += "/" + part
	}
	return out
}

// profileAuditCount counts only the two kinds the profile surface writes, so a
// login or a sync landing in the same table during the run cannot make a delta of
// one look right. Sharing is its own kind because the audit vocabulary already
// separates it — "who can see this" is the question a reviewer searches for by
// itself.
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

// ---- FR-044 ------------------------------------------------------------------

// The readability predicate is a WHERE clause on every profile path, not only on
// the list. A 403 here would confirm that a private profile with this exact slug
// exists, which is the enumeration FR-044 forbids — so the answer for a profile
// somebody else owns has to be the same answer as for a slug nobody has ever
// used, down to the body.
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

	// And every mutating path says the same thing, including the ones whose
	// refusal would otherwise be a 403 naming a role.
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

// ---- T078 --------------------------------------------------------------------

// The claim T078 is entirely about: the gate's effect on the screen is COMPUTED
// by internal/domain/resolve, not restated in the query.
//
// The two rows below are chosen because no SQL predicate a screen query would
// plausibly carry produces them. A pin at a REJECTED version is not "resolve to
// the pin" and not "fall back to a clean one" — FR-029 puts the version out of
// reach of every gate, and the resolver refuses to re-point a pin, so the only
// correct answer is an exclusion that names the version it would have taken. And
// a flagged version under `warn-with-override` RESOLVES, carrying a note, which
// the naive reading of "flagged" would have dropped.
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
		"warn-with-override INCLUDES a flagged version (FR-035); the screen must say it did")
	require.Equal(t, "1.1.0", flagged.Version)
	require.Equal(t, string(models.VerdictFlagged), flagged.Verdict)
	require.Nil(t, flagged.Skip)
	require.Contains(t, flagged.Note, "SH-SQL-004",
		"the note has to name the finding, or the row states a policy with no reason")
	require.Contains(t, flagged.Note, "SKILL.md")
	// The Scan badge is the catalog's answer and the resolution is the gate's.
	// Conflating the two is how a row claims a package is clean because the
	// version the gate fell back to is.
	require.Equal(t, "1.1.0", flagged.LatestVersion)
	require.Equal(t, string(models.VerdictFlagged), flagged.LatestVerdict)

	rejected := entryByID(t, detail, doomed.id)
	require.Equal(t, "skipped", rejected.Outcome)
	require.NotNil(t, rejected.Skip, "FR-036: an excluded package is reported, never omitted")
	require.Equal(t, "version-rejected", rejected.Skip.Reason)
	require.Equal(t, "0.9.0", rejected.Skip.WouldHaveResolvedTo,
		"a pin is never re-pointed, so the exclusion has to name what the owner asked for")
	require.Empty(t, rejected.Version, "a skipped entry resolves to nothing")
	require.Equal(t, "pinned", rejected.Mode,
		"a pin the gate refused is still a pin; relabelling it would hide the conflict")
	require.NotEmpty(t, rejected.Note)

	// Both rows are drawn, which is the other half of FR-036: the screen shows one
	// row per package the profile holds and not one per package that survived.
	require.Len(t, detail.Entries, 2)
}

// ---- T079 --------------------------------------------------------------------

func TestCreatingAProfileMakesItsAuthorTheOwnerAndWritesOneAuditRow(t *testing.T) {
	before := profileAuditCount(t)

	detail := newProfile(t, curator, "curate/owned", "Owned")
	require.Equal(t, before+1, profileAuditCount(t),
		"a create must write exactly one audit row: zero leaves the action unaccounted for")
	kind, who, text := latestAuditRow(t)
	require.Equal(t, string(models.AuditKindProfile), kind)
	require.Equal(t, curator.claims.Email, who,
		"FR-051: the row names the person, not the service account the tx ran as")
	require.Contains(t, text, "curate/owned")

	require.Equal(t, string(models.ProfileVisibilityPrivate), detail.Visibility,
		"a profile nobody has chosen to publish is not readable by the whole organisation")
	require.Equal(t, string(models.MembershipRoleOwner), detail.Role)
	require.Equal(t, contract.ProfilePermissions{Curate: true, Share: true, Publish: true},
		detail.Permissions)
	require.Equal(t, 0, detail.HeadRevision)
	require.True(t, detail.UnpublishedChanges, "nothing has been published, so a revision is owed")
	require.Equal(t, []contract.ProfileMember{{
		Kind: string(models.SubjectKindUser), Ref: curator.claims.Email,
		Role: string(models.MembershipRoleOwner), DisplayName: curator.claims.Name,
	}}, detail.Members)

	// The owner membership is what makes every other operation reachable. Without
	// it the profile would be readable and permanently uneditable, and `am_api`
	// holds no DELETE on `membership` with which to repair that.
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

// FR-038, and the assertion is deliberately about the ABSENCE of a mechanism:
// the upstream publishes a revision after the fork is taken, and the fork does
// not see it, does not gain an entry from it, and does not gain a revision of its
// own.
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

	// The upstream moves on.
	setEntries(t, curator, upstream, fmt.Sprintf(
		`[{"id":%q,"mode":"latest"},{"id":%q,"mode":"latest"}]`, first.id, second.id),
		http.StatusOK)
	after := publish(t, curator, upstream, "a revision the fork must never see")
	require.Equal(t, 2, after.Revision)
	require.Len(t, after.Entries, 2)

	unchanged := profileDetail(t, curator, "curate/fork-downstream")
	require.Len(t, unchanged.Entries, 1,
		"FR-038: the fork gained the upstream's new package, so something is subscribing it")
	require.Equal(t, 0, unchanged.HeadRevision)
	require.Empty(t, unchanged.Revisions)

	// And publishing the fork freezes the fork, not the upstream.
	own := publish(t, curator, "curate/fork-downstream", "the fork's own first")
	require.Equal(t, 1, own.Revision, "the fork's sequence starts at 1, unrelated to the upstream's")
	require.Len(t, own.Entries, 1)
	require.Equal(t, "curate/fork-downstream", own.Profile.Slug)
}

// ---- T080 --------------------------------------------------------------------

// 001 US5 scenario 1, end to end: a pin toggled on the screen changes what the
// profile RESOLVES to and changes nothing a machine syncs, until a revision is
// published.
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

	// The toggle the design's row carries.
	drafted := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut,
		profilePath(slug, "entries"),
		fmt.Sprintf(`{"entries":[{"id":%q,"mode":"pinned","version":"1.0.0"}]}`, pkg.id),
		http.StatusOK)

	entry := entryByID(t, drafted, pkg.id)
	require.Equal(t, "1.0.0", entry.Version, "the displayed resolved version follows the pin")
	require.Equal(t, "pinned", entry.Mode)
	require.True(t, entry.Unpublished)
	require.True(t, drafted.UnpublishedChanges)

	// The half that matters: what a machine can still fetch is the OLD resolution.
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
			// The refusal that only exists because `am_api` holds no DELETE on
			// profile_entry. Answering 200 and quietly keeping the entry would leave
			// the stored set disagreeing with the request that was accepted.
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

	// Nothing above was written. A refusal that half-applied would be worse than
	// one that explained itself badly.
	after := profileDetail(t, curator, slug)
	require.Len(t, after.Entries, 1)
	require.Equal(t, pkg.id, after.Entries[0].ID)
	require.Equal(t, "latest", after.Entries[0].Mode)
}

// ---- T081 --------------------------------------------------------------------

// FR-037's four levels, and the sharpest case in the table: `punter` holds
// catalog-admin, the organisation's most privileged role, and a CONSUMER
// membership on this profile. They may not publish it. An authorisation model in
// which the organisation role could stand in for the membership would have two
// answers to one question, and the other answer is already fixed — a catalog
// admin cannot read a private profile they hold no membership on at all.
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
		name                   string
		who                    actor
		role                   models.MembershipRole
		curate, share, publish bool
	}{
		{"the owner", curator, models.MembershipRoleOwner, true, true, true},
		{"a maintainer curates and publishes and does not re-share", mate,
			models.MembershipRoleMaintainer, true, false, true},
		{"a consumer holding the organisation's top role still may not publish", punter,
			models.MembershipRoleConsumer, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Everyone here can READ it, which is what makes the refusals below a
			// membership decision rather than a readability one.
			detail := profileDetail(t, tc.who, slug)
			require.Equal(t, string(tc.role), detail.Role)
			require.Equal(t, contract.ProfilePermissions{
				Curate: tc.curate, Share: tc.share, Publish: tc.publish,
			}, detail.Permissions, "FR-126: the screen is told what it may offer")

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
					"the refusal has to name the role this identity holds (FR-117, FR-126)")
			}
		})
	}
}

// The invariant sharing has to enforce, and the reason it has to: nothing can
// remove a membership, so a body that demoted the last owner would leave a
// profile whose sharing can never be changed again by anybody.
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

	// A second owner makes the demotion legal, because the profile keeps one.
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

// ---- T082 --------------------------------------------------------------------

// 001 US5 scenario 7: a target affects only what a CLIENT writes, never what the
// server stores. The test is the pair — the target list moves and the resolution
// beside it does not.
func TestChangingSyncTargetsChangesTheClientInstructionAndNothingTheServerResolves(t *testing.T) {
	pkg := curatePackage(t, "target-subject",
		curatedVersion{semver: "1.0.0", verdict: models.VerdictClean, visible: true, latest: true})

	slug := "curate/targets"
	newProfile(t, curator, slug, "Targets")
	setEntries(t, curator, slug, fmt.Sprintf(`[{"id":%q,"mode":"latest"}]`, pkg.id), http.StatusOK)

	// A brand new profile enables nothing, and the whole vocabulary is reported so
	// a screen draws its checkboxes without holding a copy of the enum.
	fresh := profileDetail(t, curator, slug)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex)},
	}, fresh.Targets)

	both := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":["codex","claude-code"]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode), Enabled: true},
		{Target: string(models.SyncTargetKindCodex), Enabled: true},
	}, both.Targets, "the answer is in the vocabulary's order, not in the order they were sent")

	first := publish(t, curator, slug, "both targets")
	require.Equal(t, []string{"claude-code", "codex"}, first.Targets)

	// Disable one. An omitted target is disabled rather than removed, which is how
	// a replacement works with no DELETE grant.
	one := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":["codex"]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex), Enabled: true},
	}, one.Targets)

	second := publish(t, curator, slug, "codex only")
	require.Equal(t, []string{"codex"}, second.Targets)
	require.Equal(t, first.Entries, second.Entries,
		"a target change moved a resolved version, so it is not client-side (FR-039)")
	require.Equal(t, first.Skipped, second.Skipped)

	// Emptying it is legal: the profile writes nothing until somebody chooses.
	none := sendJSON[contract.ProfileDetail](t, curator, http.MethodPut, profilePath(slug, "targets"),
		`{"targets":[]}`, http.StatusOK)
	require.Equal(t, []contract.ProfileTarget{
		{Target: string(models.SyncTargetKindClaudeCode)},
		{Target: string(models.SyncTargetKindCodex)},
	}, none.Targets)
	require.Equal(t, []string{}, publish(t, curator, slug, "nothing").Targets)
}

// ---- T083 --------------------------------------------------------------------

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

	// FR-034. The old document is still there, still says what it said, and is not
	// the new one.
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

	// Principle IV: republishing a number is refused by the database and not by a
	// branch. Attempted directly, because the operation gives a client no number
	// to name — which is itself the first half of the property.
	_, err := pool.Exec(context.Background(), `
insert into revision (id, profile_id, seq, lockfile, object_key, created_by)
select $1, id, 2, '{}'::jsonb, 'profiles/curate/revisions/r2.json', 'a-second-writer'
from profile where slug = $2`, models.NewID(), slug)
	require.ErrorContains(t, err, "revision_profile_seq",
		"r2 was overwritten or duplicated; FR-034 makes a published revision final")
}

// The other way a sequence goes wrong, and the one a single-threaded test cannot
// see: two publishes in flight at the same instant.
//
// `select ... for update` on the profile row serialises them, and the sequence is
// then read in a statement of ITS OWN so the second transaction takes a fresh
// snapshot after the lock is granted. Reading it beside the lock instead is the
// subtle version of this bug: correct under no contention, and a unique-violation
// 500 under any.
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

// 003 US5 scenario 3's server half: what the revision froze is what the screen
// was displaying, because both come out of one function.
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
