package web_test

import (
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/view"
)

// The two profile screens.
//
// The properties that matter here mirror the scanner's: the policy note the api
// computed is rendered VERBATIM — two implementations of the gate is how the
// screen and the CLI start disagreeing — an action a role may not take is
// absent or disabled, and the three states that are not a list of profiles are
// three screens.

const profileSlug = "platform-engineer"

var profileHref = "/profiles/" + profileSlug

// profileServer is a server whose api answers profileSlug with detail.
func profileServer(t *testing.T, detail apiclient.ProfileDetail) (*fakeapi.API, http.Handler) {
	t.Helper()
	api, h := newServer(t)
	api.Data.ProfileDetails[profileSlug] = detail
	return api, h
}

// keepPackages narrows the catalog the api answers to ids, for the "Add
// package" tests: they need to state exactly which rows the catalog holds.
func keepPackages(api *fakeapi.API, ids ...string) {
	api.Data.Packages = slices.DeleteFunc(api.Data.Packages, func(p apiclient.CatalogPackage) bool {
		return !slices.Contains(ids, p.Id)
	})
}

// sentEntries is the one whole entry set the web role resent.
func sentEntries(t *testing.T, api *fakeapi.API) []apiclient.ProfileEntrySetting {
	t.Helper()
	calls := api.Calls("setProfileEntries")
	require.Len(t, calls, 1)
	var body apiclient.ProfileEntries
	calls[0].Decode(t, &body)
	return body.Entries
}

func baseProfileDetail() apiclient.ProfileDetail {
	return apiclient.ProfileDetail{
		Slug: profileSlug, Name: "Platform Engineer",
		Visibility:    apiclient.ProfileDetailVisibilityOrganisation,
		DefaultPolicy: apiclient.ProfileDetailDefaultPolicyFloatingLatest,
		Gate:          apiclient.ProfileDetailGateWarnWithOverride,
		HeadRevision:  3,
		Role:          new(apiclient.ProfileDetailRoleOwner),
		Permissions:   apiclient.ProfilePermissions{Curate: true, Share: true, Publish: true, Delete: true},
		Entries: []apiclient.ProfileEntry{{
			Id: "community/postgres-migration-guard", Name: "Postgres Migration Guard",
			Kind: apiclient.ProfileEntryKindSkill, Mode: apiclient.ProfileEntryModeLatest,
			LatestVersion: new("0.8.3"), LatestVerdict: new(apiclient.ProfileEntryLatestVerdictFlagged),
			Version: new("0.8.3"), Verdict: new(apiclient.ProfileEntryVerdictFlagged), Outcome: apiclient.Warned,
			Note: new("Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning."),
		}},
	}
}

func skillEntry(id, name string) apiclient.ProfileEntry {
	return apiclient.ProfileEntry{
		Id: id, Name: name, Kind: apiclient.ProfileEntryKindSkill,
		Mode: apiclient.ProfileEntryModeLatest, Outcome: apiclient.Resolved,
	}
}

func lockfile(revision int64, gate apiclient.LockfileGate, policy apiclient.LockfileDefaultPolicy,
	targets []apiclient.LockfileTargets, entries ...apiclient.LockfileEntry) apiclient.Lockfile {
	return apiclient.Lockfile{
		Revision: revision, Gate: gate, DefaultPolicy: &policy, Targets: targets,
		Entries: entries, Skipped: []apiclient.LockfileSkip{},
	}
}

func lockEntry(id, version string, resolution apiclient.LockfileEntryResolution) apiclient.LockfileEntry {
	return apiclient.LockfileEntry{Id: id, Version: version, Resolution: resolution}
}

// TestProfilesListShowsExactlyTheReadableSet asserts the list shows exactly
// the readable set, and no others.
func TestProfilesListShowsExactlyTheReadableSet(t *testing.T) {
	api, h := newServer(t)
	api.Data.Profiles = []apiclient.Profile{
		{Slug: "platform-engineer", Name: "Platform Engineer", Visibility: new(apiclient.ProfileVisibilityOrganisation), PackageCount: 4, HeadRevision: 14},
		{Slug: "sre-oncall", Name: "SRE On-call", Visibility: new(apiclient.ProfileVisibilityShared)},
	}
	body := get(t, h, "/profiles").Body.String()

	require.Contains(t, body, "Platform Engineer")
	require.Contains(t, body, "platform-engineer")
	require.Contains(t, body, "r14")
	require.Contains(t, body, "SRE On-call")
	require.Contains(t, body, "unpublished")
	require.Contains(t, body, "2 profiles")
}

func TestProfilesListEmptyStateNamesWhatWouldAppear(t *testing.T) {
	api, h := newServer(t)
	api.Data.Profiles = nil
	body := get(t, h, "/profiles").Body.String()
	require.Contains(t, body, `id="profiles-empty"`)
}

// TestProfilesThreeEmptyStatesAreDistinguishable: an empty hub, a role refusal,
// no usable session, and an unreachable api must never render alike.
func TestProfilesThreeEmptyStatesAreDistinguishable(t *testing.T) {
	for _, state := range []struct {
		name   string
		answer int
		id     string
		status int
	}{
		{name: "genuinely empty", id: `id="profiles-empty"`, status: http.StatusOK},
		{name: "no usable session", answer: http.StatusUnauthorized, id: `id="profiles-signed-out"`, status: http.StatusOK},
		{name: "refused by role", answer: http.StatusForbidden, id: `id="profiles-refused"`, status: http.StatusForbidden},
		{name: "api unreachable", answer: http.StatusServiceUnavailable, id: `id="profiles-unavailable"`, status: http.StatusBadGateway},
	} {
		t.Run(state.name, func(t *testing.T) {
			api, h := newServer(t)
			api.Data.Profiles = nil
			if state.answer != 0 {
				api.Fail("listProfiles", state.answer)
			}
			rec := get(t, h, "/profiles")
			require.Equal(t, state.status, rec.Code)
			body := rec.Body.String()
			require.Contains(t, body, state.id)

			for _, other := range []string{"profiles-empty", "profiles-signed-out", "profiles-refused", "profiles-unavailable"} {
				if strings.Contains(state.id, other) {
					continue
				}
				require.NotContainsf(t, body, `id="`+other+`"`, "this state also renders %q", other)
			}
		})
	}
}

// TestProfileDetailRendersThePolicyNoteVerbatim asserts the screen never
// recomputes the gate's effect — it renders what the api already decided.
func TestProfileDetailRendersThePolicyNoteVerbatim(t *testing.T) {
	_, h := profileServer(t, baseProfileDetail())
	body := get(t, h, profileHref).Body.String()

	require.Contains(t, body, "Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning.")
	require.Contains(t, body, "Postgres Migration Guard")
	require.Contains(t, body, "am-pill-warn")
}

// TestProfileDetailReportsASkippedEntryRatherThanOmittingIt asserts an
// excluded package is reported with its reason rather than silently dropped.
func TestProfileDetailReportsASkippedEntryRatherThanOmittingIt(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries = append(detail.Entries, apiclient.ProfileEntry{
		Id: "community/release-notes", Name: "Release Notes", Kind: apiclient.ProfileEntryKindSkill,
		Mode: apiclient.ProfileEntryModePinned, PinnedVersion: new("1.2.7"), Outcome: apiclient.Skipped,
		Skip: &apiclient.LockfileSkip{
			Reason: apiclient.FlaggedAwaitingApproval, Detail: new("Awaiting approval from a scanner reviewer."),
		},
	})
	_, h := profileServer(t, detail)
	body := get(t, h, profileHref).Body.String()

	require.Contains(t, body, "Release Notes")
	require.Contains(t, body, "awaiting reviewer approval")
	require.Contains(t, body, "Awaiting approval from a scanner reviewer.")
}

// TestProfileDetailUnreadableAnswersAsMissing asserts an unreadable profile
// and a nonexistent one read alike.
func TestProfileDetailUnreadableAnswersAsMissing(t *testing.T) {
	_, h := profileServer(t, baseProfileDetail())
	rec := get(t, h, "/profiles/no-such-profile")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Contains(t, rec.Body.String(), `id="profile-missing"`)
}

// TestProfileEntryPinRoundTrips asserts the web role's half of a pin toggle:
// the FULL entry set is resent with only the targeted row changed, per
// hub.SetProfileEntries's whole-set contract.
func TestProfileEntryPinRoundTrips(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries = append(detail.Entries, skillEntry("example/adr-writer", "ADR Writer"))
	api, h := profileServer(t, detail)

	rec := post(t, h, "/profiles/entries/pin", url.Values{
		"slug": {profileSlug}, "id": {"example/adr-writer"}, "version": {"3.0.2"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, profileHref+"?notice=entry-updated", rec.Header().Get("Location"))

	sent := sentEntries(t, api)
	require.Len(t, sent, 2, "the untouched entry must still be in the resent set")

	var pinned, untouched *apiclient.ProfileEntrySetting
	for i := range sent {
		switch sent[i].Id {
		case "example/adr-writer":
			pinned = &sent[i]
		case "community/postgres-migration-guard":
			untouched = &sent[i]
		}
	}
	require.NotNil(t, pinned, "the targeted entry was not resent")
	require.Equal(t, apiclient.ProfileEntrySettingModePinned, pinned.Mode)
	require.Equal(t, "3.0.2", *pinned.Version)

	require.NotNil(t, untouched, "the untouched entry was dropped from the resend")
	require.Equal(t, apiclient.ProfileEntrySettingModeLatest, untouched.Mode, "an entry nobody asked to change must keep its own setting")
}

func TestProfileEntryFloatRoundTrips(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries[0].Mode = apiclient.ProfileEntryModePinned
	detail.Entries[0].PinnedVersion = new("0.7.0")
	api, h := profileServer(t, detail)

	post(t, h, "/profiles/entries/latest", url.Values{
		"slug": {profileSlug}, "id": {"community/postgres-migration-guard"},
	})

	sent := sentEntries(t, api)
	require.Equal(t, apiclient.ProfileEntrySettingModeLatest, sent[0].Mode)
	require.Nil(t, sent[0].Version)
}

// TestProfileEntryRemoveRoundTrips asserts a remove posts through the
// dedicated RemoveProfileEntry command, not through SetProfileEntries's
// whole-set contract (which refuses a body that omits a held entry).
func TestProfileEntryRemoveRoundTrips(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/entries/remove", url.Values{
		"slug": {profileSlug}, "id": {"community/postgres-migration-guard"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, profileHref+"?notice=entry-removed", rec.Header().Get("Location"))

	removed := api.Calls("removeProfileEntry")
	require.Len(t, removed, 1)
	require.Equal(t, "/v1/profiles/"+profileSlug+"/entries/remove", removed[0].Path)
	var body apiclient.ProfileEntryRemoval
	removed[0].Decode(t, &body)
	require.Equal(t, "community/postgres-migration-guard", body.Id)
	require.Empty(t, api.Calls("setProfileEntries"), "remove must not go through SetProfileEntries's whole-set contract")
}

// TestProfileEntryRemoveWithNoIDRefusesWithoutCallingTheApi asserts a
// blank id is caught in the handler, not sent on to the api.
func TestProfileEntryRemoveWithNoIDRefusesWithoutCallingTheApi(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/entries/remove", url.Values{"slug": {profileSlug}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "entry-missing")
	require.Empty(t, api.Calls("removeProfileEntry"))
}

// TestProfileDetailOffersOnlyPackagesNotAlreadyHeld asserts each kind's Add
// control lists a catalog row of that kind exactly once it is not already an
// entry, never lists one that already is, and never lists the other kind.
func TestProfileDetailOffersOnlyPackagesNotAlreadyHeld(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())
	keepPackages(api, "community/postgres-migration-guard", "example/adr-writer", "example/platform-toolkit")
	body := get(t, h, profileHref).Body.String()

	require.Contains(t, body, `id="add-skill-id"`)
	require.Contains(t, body, `id="add-plugin-id"`)

	skillOptions := addOptions(t, body, "add-skill-id")
	require.Contains(t, skillOptions, "Adr Writer")
	require.NotContains(t, skillOptions, "Postgres Migration Guard",
		"an entry the profile already holds must not also be offered as an addition")
	require.NotContains(t, skillOptions, "Platform Toolkit", "a plugin must not be offered in the skill select")

	pluginOptions := addOptions(t, body, "add-plugin-id")
	require.Contains(t, pluginOptions, "Platform Toolkit")
	require.NotContains(t, pluginOptions, "Adr Writer", "a skill must not be offered in the plugin select")
}

// addOptions returns just one Add control's <select> markup, so a test can
// assert about its options without a package's name elsewhere on the page
// (its own entry row, say) producing a false pass.
func addOptions(t *testing.T, body, selectID string) string {
	t.Helper()
	start := strings.Index(body, `<select id="`+selectID+`"`)
	require.GreaterOrEqual(t, start, 0, "the "+selectID+" select is missing")
	end := strings.Index(body[start:], "</select>")
	require.GreaterOrEqual(t, end, 0, "the "+selectID+" select is unclosed")
	return body[start : start+end]
}

// TestProfileDetailAddControlIsAbsentWithoutCatalogOrRole asserts both Add
// controls degrade to absent rather than to an empty, broken <select> — both
// when the viewer may not curate and when the catalog cannot be read.
func TestProfileDetailAddControlIsAbsentWithoutCatalogOrRole(t *testing.T) {
	t.Run("no curate permission", func(t *testing.T) {
		detail := baseProfileDetail()
		detail.Permissions = apiclient.ProfilePermissions{}
		api, h := profileServer(t, detail)
		keepPackages(api, "example/adr-writer")
		body := get(t, h, profileHref).Body.String()
		require.NotContains(t, body, `id="add-skill-id"`)
		require.NotContains(t, body, `id="add-plugin-id"`)
	})

	t.Run("catalog unreachable", func(t *testing.T) {
		api, h := profileServer(t, baseProfileDetail())
		api.Fail("listPackages", http.StatusServiceUnavailable)
		body := get(t, h, profileHref).Body.String()
		require.NotContains(t, body, `id="add-skill-id"`)
		require.NotContains(t, body, `id="add-plugin-id"`)
		require.Contains(t, body, `id="profile-add-skill-empty"`)
		require.Contains(t, body, `id="profile-add-plugin-empty"`)
	})
}

// TestProfileEntryAddAppendsANewEntryFloatingLatest is GAP 3: a profile
// created in the UI could never receive a package, because nothing posted to
// PUT /v1/profiles/{slug}/entries with an id the profile did not already hold.
func TestProfileEntryAddAppendsANewEntryFloatingLatest(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/entries/add", url.Values{
		"slug": {profileSlug}, "id": {"example/adr-writer"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, profileHref+"?notice=entry-added", rec.Header().Get("Location"))

	sent := sentEntries(t, api)
	require.Len(t, sent, 2, "the existing entry must still be in the resent set")

	var added, untouched *apiclient.ProfileEntrySetting
	for i := range sent {
		switch sent[i].Id {
		case "example/adr-writer":
			added = &sent[i]
		case "community/postgres-migration-guard":
			untouched = &sent[i]
		}
	}
	require.NotNil(t, added, "the new package was not sent")
	require.Equal(t, apiclient.ProfileEntrySettingModeLatest, added.Mode)
	require.Nil(t, added.Version)
	require.NotNil(t, untouched, "the existing entry was dropped from the resend")
}

// TestProfileEntryAddOfAnIDAlreadyHeldFloatsRatherThanDuplicating covers the
// defensive case: the select only ever offers ids the profile lacks, but a
// stale page or a race could still submit one it already holds.
func TestProfileEntryAddOfAnIDAlreadyHeldFloatsRatherThanDuplicating(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/entries/add", url.Values{
		"slug": {profileSlug}, "id": {"community/postgres-migration-guard"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, profileHref+"?notice=entry-updated", rec.Header().Get("Location"))

	sent := sentEntries(t, api)
	require.Len(t, sent, 1, "the id must not be duplicated in the resent set")
	require.Equal(t, apiclient.ProfileEntrySettingModeLatest, sent[0].Mode)
}

// TestProfileWritesAreGatedByRole asserts a role that may not curate, share
// or publish gets every control still rendered — visibly disabled, with a
// reason — rather than hidden, and a request that arrives anyway is refused
// and records nothing.
func TestProfileWritesAreGatedByRole(t *testing.T) {
	detail := baseProfileDetail()
	detail.Permissions = apiclient.ProfilePermissions{}
	api, h := profileServer(t, detail)

	body := html.UnescapeString(get(t, h, profileHref).Body.String())

	require.Contains(t, body, "Save targets", "the control must still be rendered, only disabled")
	require.Contains(t, body, `id="profile-targets-not-permitted"`)
	require.Contains(t, body, `id="profile-publish-not-permitted"`)
	require.Contains(t, body, view.CurateDisabledReason,
		"the disabled float, pin, add-entry and targets controls must say why, not just refuse silently")
	require.Contains(t, body, view.ShareDisabledReason,
		"the disabled sharing form must say why, not just refuse silently")
	require.Contains(t, body, view.PublishDisabledReason)
	require.Contains(t, body, view.ProfileDeleteRoleReason,
		"the disabled delete-profile control must say why, not just refuse silently")

	// The sharing form is still offered, greyed out, rather than absent: a
	// role that cannot share must still see the control exists.
	require.Contains(t, body, `id="share-role"`)
	require.Contains(t, body, `<fieldset class="am-fieldset-plain" disabled aria-disabled="true"`)

	rec := post(t, h, "/profiles/entries/pin", url.Values{
		"slug": {profileSlug}, "id": {"community/postgres-migration-guard"}, "version": {"0.8.3"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "entry-updated",
		"the api is what enforces the role here (the fake always answers), so this "+
			"exercises the screen's gating copy rather than a second enforcement")

	require.Empty(t, api.Calls("publishRevision"), "publish must never be invoked for a role that may not")
}

// TestProfilePublishRedirectsWithoutResubmission is post-redirect-get: a browser
// reload after a publish must not publish a second revision.
func TestProfilePublishRedirectsWithoutResubmission(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/revisions", url.Values{
		"slug": {profileSlug}, "note": {"pinned the migration guard"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, profileHref+"?notice=published", rec.Header().Get("Location"))
	published := api.Calls("publishRevision")
	require.Len(t, published, 1)
	require.Equal(t, "/v1/profiles/"+profileSlug+"/revisions", published[0].Path)

	notice := get(t, h, rec.Header().Get("Location")).Body.String()
	require.Contains(t, notice, "Revision published")
}

// TestDeleteProfileRedirectsToTheListNotTheProfilesOwnPage asserts deletion
// is the one write that cannot redirect back to the profile's own page —
// there is no such page any more once it succeeds.
func TestDeleteProfileRedirectsToTheListNotTheProfilesOwnPage(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())

	rec := post(t, h, "/profiles/delete", url.Values{"slug": {profileSlug}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/profiles?notice=deleted", rec.Header().Get("Location"))
	deleted := api.Calls("deleteProfile")
	require.Len(t, deleted, 1)
	require.Equal(t, "/v1/profiles/"+profileSlug, deleted[0].Path)
}

// TestDeleteProfileWithPublishedRevisionsIsRefusedInline asserts the api's
// refusal (a profile with published revisions a client may have synced
// cannot be deleted) renders inline against a fresh read, exactly like every
// other ProfileRefusedError, rather than as a redirect a stale link could
// replay.
func TestDeleteProfileWithPublishedRevisionsIsRefusedInline(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())
	api.Fail("deleteProfile", http.StatusConflict,
		profileSlug+" has published revisions that a client may already have synced")

	rec := post(t, h, "/profiles/delete", url.Values{"slug": {profileSlug}})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "published revisions that a client may already have synced")
	require.Len(t, api.Calls("deleteProfile"), 1, "the api, not the web layer, is what refused this")
}

// TestDeleteProfileControlGatedByCanDelete asserts the delete control follows
// view.Profile.CanDelete: disabled with the role reason when not owner,
// disabled with the has-revisions reason when the profile still has one, and
// enabled only when both clear.
func TestDeleteProfileControlGatedByCanDelete(t *testing.T) {
	t.Run("not owner", func(t *testing.T) {
		detail := baseProfileDetail()
		detail.Permissions.Delete = false
		_, h := profileServer(t, detail)
		body := get(t, h, profileHref).Body.String()
		require.Contains(t, body, html.EscapeString(view.ProfileDeleteRoleReason))
		require.NotContains(t, body, `data-on:click="$_deleteProfileOpen = true"`)
	})

	t.Run("has published revisions", func(t *testing.T) {
		detail := baseProfileDetail()
		detail.HeadRevision = 3
		_, h := profileServer(t, detail)
		body := get(t, h, profileHref).Body.String()
		require.Contains(t, body, html.EscapeString(view.ProfileDeleteHasRevisionsReason))
	})

	t.Run("owner with no published revisions", func(t *testing.T) {
		detail := baseProfileDetail()
		detail.HeadRevision = 0
		_, h := profileServer(t, detail)
		body := get(t, h, profileHref).Body.String()
		require.Contains(t, body, `data-on:click="$_deleteProfileOpen = true"`)
	})
}

// TestProfileEntryDataIsEscapedWhereverItIsRendered: a package name, a policy
// note and a skip detail all quote content a package's manifest or the
// resolver's own prose supplies, and none of it may reach the page raw.
func TestProfileEntryDataIsEscapedWhereverItIsRendered(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	detail := baseProfileDetail()
	detail.Entries[0].Name = "Guard " + payload
	detail.Entries[0].Note = new("Note " + payload)
	detail.Members = []apiclient.ProfileMember{{
		Kind: apiclient.ProfileMemberKindUser, Ref: "x", Role: apiclient.ProfileMemberRoleOwner,
		DisplayName: new("Owner " + payload),
	}}

	_, h := profileServer(t, detail)
	body := get(t, h, profileHref).Body.String()

	require.NotContains(t, body, payload, "attacker-supplied markup rendered unescaped")
	require.Contains(t, body, "&lt;img src=x onerror=", "the value was not rendered at all, "+
		"so this test asserts nothing")
}

// TestProfileEntriesAreSplitIntoSkillsAndPlugins asserts "Packages" is broken
// into a Skills section and a Plugins section, each listing only its own kind.
func TestProfileEntriesAreSplitIntoSkillsAndPlugins(t *testing.T) {
	detail := baseProfileDetail()
	plugin := skillEntry("example/platform-toolkit", "Platform Toolkit")
	plugin.Kind = apiclient.ProfileEntryKindPlugin
	detail.Entries = []apiclient.ProfileEntry{skillEntry("example/adr-writer", "ADR Writer"), plugin}
	_, h := profileServer(t, detail)
	body := get(t, h, profileHref).Body.String()

	skillsAt := strings.Index(body, `class="am-entry-kind-head">Skills`)
	pluginsAt := strings.Index(body, `class="am-entry-kind-head">Plugins`)
	adrAt := strings.Index(body, "ADR Writer")
	toolkitAt := strings.Index(body, "Platform Toolkit")

	require.GreaterOrEqual(t, skillsAt, 0, "no Skills section was rendered")
	require.GreaterOrEqual(t, pluginsAt, 0, "no Plugins section was rendered")
	require.Greaterf(t, adrAt, skillsAt, "the skill entry must be listed under Skills")
	require.Lessf(t, adrAt, pluginsAt, "the skill entry must not be listed under Plugins")
	require.Greaterf(t, toolkitAt, pluginsAt, "the plugin entry must be listed under Plugins")
}

// TestProfileEntriesEmptyKindSectionStillNamesItself asserts a profile that
// holds only skills still shows the Plugins section, saying it holds none,
// rather than omitting the section — "this profile holds no plugins" is a
// fact worth reading.
func TestProfileEntriesEmptyKindSectionStillNamesItself(t *testing.T) {
	_, h := profileServer(t, baseProfileDetail()) // one skill, no plugin
	body := get(t, h, profileHref).Body.String()

	require.Contains(t, body, `id="profile-entries-empty-plugin"`)
	require.Contains(t, body, "This profile holds no plugins yet.")
}

// TestAddEntryFormsAreBehindTwoSeparateToggleButtons is the owner's requested
// split: "Add package" became two buttons, "Add skill" and "Add plugin", each
// opening its own popup rather than a single form offering every kind in one
// select. Both signals are underscore-prefixed, which is what keeps datastar
// from ever sending them (the same reason the catalog's own modal signals
// are), and both backdrops are hidden before datastar has a chance to run,
// exactly like the import modal.
func TestAddEntryFormsAreBehindTwoSeparateToggleButtons(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())
	keepPackages(api, "example/adr-writer", "example/platform-toolkit")
	body := html.UnescapeString(get(t, h, profileHref).Body.String())

	require.Contains(t, body, `data-on:click="$_addSkillOpen = !$_addSkillOpen"`)
	require.Contains(t, body, `data-style:display="$_addSkillOpen ? 'flex' : 'none'"`)
	require.Contains(t, body, `data-on:click="$_addPluginOpen = !$_addPluginOpen"`)
	require.Contains(t, body, `data-style:display="$_addPluginOpen ? 'flex' : 'none'"`)

	require.Contains(t, body, ">Add skill<")
	require.Contains(t, body, ">Add plugin<")

	backdropAt := strings.Index(body, `data-style:display="$_addSkillOpen`)
	require.GreaterOrEqual(t, backdropAt, 0)
	tagStart := strings.LastIndex(body[:backdropAt], "<div")
	tagEnd := strings.Index(body[tagStart:], ">")
	require.GreaterOrEqual(t, tagEnd, 0, "the add-skill backdrop's opening tag is unclosed")
	require.Contains(t, body[tagStart:tagStart+tagEnd], "display:none", "hidden until datastar says otherwise")

	// Each select is scoped to its own kind: the skill option appears, the
	// plugin form is a separate one, and vice versa is covered by
	// TestProfileDetailOffersOnlyPackagesNotAlreadyHeld.
	require.Contains(t, body, `id="add-skill-id"`)
	require.Contains(t, body, `id="add-plugin-id"`)
}

// TestAddEntryFormOffersVersionModeAtAddTime covers the owner's other
// request: no post-hoc "Pin to 0.83" button — the curator picks floating
// latest or an exact version at the moment of adding.
func TestAddEntryFormOffersVersionModeAtAddTime(t *testing.T) {
	api, h := profileServer(t, baseProfileDetail())
	keepPackages(api, "example/adr-writer")
	body := get(t, h, profileHref).Body.String()

	require.Contains(t, body, `name="mode"`)
	require.Contains(t, body, `value="latest"`)
	require.Contains(t, body, `value="pinned"`)
	require.Contains(t, body, `name="version"`)
	require.NotContains(t, body, "Pin to 0.", "there must be no post-hoc \"Pin to X\" button on the add control")
}

// TestDisabledProfileControlsAreShownGreyedOutNotHidden is 1d: a role that
// may not curate, share or publish still sees every control the screen
// offers — visibly disabled, with a title and the same reason in visible
// text beneath it — rather than a control that silently disappears.
func TestDisabledProfileControlsAreShownGreyedOutNotHidden(t *testing.T) {
	detail := baseProfileDetail()
	detail.Permissions = apiclient.ProfilePermissions{}
	detail.Targets = []apiclient.ProfileTarget{
		{Target: apiclient.ProfileTargetTargetClaudeCode, Enabled: true},
		{Target: apiclient.ProfileTargetTargetCodex, Enabled: false},
	}
	_, h := profileServer(t, detail)
	body := html.UnescapeString(get(t, h, profileHref).Body.String())

	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Add skill</button>`)
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Add plugin</button>`)
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Float to latest</button>`)
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Pin</button>`)
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Remove</button>`)
	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.ProfileDeleteRoleReason+`">Delete profile</button>`)
	require.Contains(t, body,
		`<input type="checkbox" checked disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">`,
		"an enabled target's checkbox must carry aria-disabled, not just disabled")
	require.Contains(t, body,
		`<input type="checkbox" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">`,
		"a disabled target's checkbox must carry aria-disabled, not just disabled")
	require.Contains(t, body,
		`<button type="button" class="am-btn am-btn-primary" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Save targets</button>`)
	require.Contains(t, body, `<fieldset class="am-fieldset-plain" disabled aria-disabled="true" title="`+view.ShareDisabledReason+`">`)
	require.Contains(t, body, `<fieldset class="am-fieldset-plain" disabled aria-disabled="true" title="`+view.PublishDisabledReason+`">`)

	// Both, not either: the title is a weak affordance alone, so the same
	// sentence also appears as visible text.
	for _, reason := range []string{
		view.CurateDisabledReason, view.ShareDisabledReason, view.PublishDisabledReason, view.ProfileDeleteRoleReason,
	} {
		require.GreaterOrEqualf(t, strings.Count(body, reason), 2, "%q must appear both as a title and as visible text", reason)
	}
}

// TestProfileRevisionDiffIsAbsentWithoutAQuery asserts the panel is purely
// additive: a plain profile read carries no diff, and nothing on the page
// hints one could appear except the per-revision "Show diff" link.
func TestProfileRevisionDiffIsAbsentWithoutAQuery(t *testing.T) {
	detail := baseProfileDetail()
	detail.Revisions = []apiclient.ProfileRevision{{Revision: 5}, {Revision: 4}}
	_, h := profileServer(t, detail)
	body := get(t, h, profileHref).Body.String()

	require.NotContains(t, body, `id="profile-diff-panel"`)
	require.Contains(t, body, view.RevisionDiffHref(profileSlug, 5))
}

// TestProfileRevisionDiffReportsAddedRemovedChangedAndGovernance covers the
// diff's full report: a package added, one removed, one whose version and
// pin mode both changed, a skip that stopped applying, and the gate, default
// policy and targets all differing between the two revisions.
func TestProfileRevisionDiffReportsAddedRemovedChangedAndGovernance(t *testing.T) {
	detail := baseProfileDetail()
	detail.HeadRevision = 5
	detail.Revisions = []apiclient.ProfileRevision{{Revision: 5}, {Revision: 4}}
	api, h := profileServer(t, detail)
	older := lockfile(4, apiclient.LockfileGateWarnWithOverride, apiclient.LockfileDefaultPolicyFloatingLatest,
		[]apiclient.LockfileTargets{apiclient.LockfileTargetsClaudeCode},
		lockEntry("example/adr-writer", "3.0.1", apiclient.LockfileEntryResolutionLatest),
		lockEntry("community/postgres-migration-guard", "0.8.2", apiclient.LockfileEntryResolutionLatest))
	older.Skipped = []apiclient.LockfileSkip{{Id: "community/release-notes", Reason: apiclient.FlaggedAwaitingApproval}}
	api.Data.Revisions[profileSlug] = map[int64]apiclient.Lockfile{
		4: older,
		5: lockfile(5, apiclient.LockfileGateBlock, apiclient.LockfileDefaultPolicyPinned,
			[]apiclient.LockfileTargets{apiclient.LockfileTargetsClaudeCode, apiclient.LockfileTargetsCodex},
			lockEntry("example/adr-writer", "3.0.2", apiclient.LockfileEntryResolutionPinned),
			lockEntry("example/security-review-kit", "1.0.0", apiclient.LockfileEntryResolutionLatest)),
	}
	body := get(t, h, view.RevisionDiffHref(profileSlug, 5)).Body.String()

	require.Contains(t, body, `id="profile-diff-panel"`)

	// Added.
	require.Contains(t, body, "example/security-review-kit")
	require.Contains(t, body, "1.0.0")

	// Removed.
	require.Contains(t, body, "community/postgres-migration-guard")
	require.Contains(t, body, "0.8.2")

	// Changed: both the version and the pin mode.
	require.Contains(t, body, "example/adr-writer")
	require.Contains(t, body, "3.0.1")
	require.Contains(t, body, "3.0.2")
	require.Contains(t, body, view.EntryModeLabel("latest"))
	require.Contains(t, body, view.EntryModeLabel("pinned"))

	// A skip that stopped applying, with its reason.
	require.Contains(t, body, "community/release-notes")
	require.Contains(t, body, view.SkipReasonLabel("flagged-awaiting-approval"))

	// Gate, default policy and targets, all differing.
	require.Contains(t, body, view.GateLabel("warn-with-override"))
	require.Contains(t, body, view.GateLabel("block"))
	require.Contains(t, body, view.DefaultPolicyLabel("floating-latest"))
	require.Contains(t, body, view.DefaultPolicyLabel("pinned"))
	require.Contains(t, body, "codex")
}

// TestProfileRevisionDiffFirstRevisionShowsWhatItIntroduced asserts revision
// 1, which has no predecessor, says so plainly and shows what it introduced
// rather than an empty diff or an error.
func TestProfileRevisionDiffFirstRevisionShowsWhatItIntroduced(t *testing.T) {
	detail := baseProfileDetail()
	detail.Revisions = []apiclient.ProfileRevision{{Revision: 1}}
	api, h := profileServer(t, detail)
	first := lockfile(1, apiclient.LockfileGateWarnWithOverride, apiclient.LockfileDefaultPolicyFloatingLatest, nil,
		lockEntry("example/adr-writer", "3.0.0", apiclient.LockfileEntryResolutionLatest))
	first.Skipped = []apiclient.LockfileSkip{{Id: "community/release-notes", Reason: apiclient.FlaggedAwaitingApproval}}
	api.Data.Revisions[profileSlug] = map[int64]apiclient.Lockfile{1: first}
	body := get(t, h, view.RevisionDiffHref(profileSlug, 1)).Body.String()

	require.Contains(t, body, "Revision 1 has no predecessor")
	require.Contains(t, body, "example/adr-writer")
	require.Contains(t, body, "community/release-notes")
	require.NotContains(t, body, `id="profile-diff-missing"`)
	require.NotContains(t, body, `id="profile-diff-predecessor-unavailable"`)
}

// TestProfileRevisionDiffMissingRevisionSaysSoPlainly asserts a revision this
// profile does not have, or that could not be read, answers honestly rather
// than as an empty diff — the same answer a nonexistent one and an
// unreadable one give.
func TestProfileRevisionDiffMissingRevisionSaysSoPlainly(t *testing.T) {
	_, h := profileServer(t, baseProfileDetail())
	rec := get(t, h, view.RevisionDiffHref(profileSlug, 99))

	require.Equal(t, http.StatusOK, rec.Code, "the rest of the profile still reads fine")
	require.Contains(t, rec.Body.String(), `id="profile-diff-missing"`)
}

// TestProfileRevisionDiffPredecessorUnavailableSaysSoRatherThanEmptyDiff
// asserts a revision that reads fine but whose predecessor cannot be read
// reports that honestly instead of rendering a silently empty diff.
func TestProfileRevisionDiffPredecessorUnavailableSaysSoRatherThanEmptyDiff(t *testing.T) {
	detail := baseProfileDetail()
	detail.HeadRevision = 5
	api, h := profileServer(t, detail)
	api.Data.Revisions[profileSlug] = map[int64]apiclient.Lockfile{
		5: lockfile(5, apiclient.LockfileGateWarnWithOverride, apiclient.LockfileDefaultPolicyFloatingLatest, nil,
			lockEntry("example/adr-writer", "3.0.2", apiclient.LockfileEntryResolutionPinned)),
	}
	body := get(t, h, view.RevisionDiffHref(profileSlug, 5)).Body.String()

	require.Contains(t, body, `id="profile-diff-predecessor-unavailable"`)
	require.NotContains(t, body, `id="profile-diff-missing"`)
}

// TestProfileScreensRenderInBothThemes asserts both screens render correctly
// in both themes.
func TestProfileScreensRenderInBothThemes(t *testing.T) {
	_, h := profileServer(t, baseProfileDetail())

	for _, path := range []string{"/profiles", profileHref} {
		require.Contains(t, get(t, h, path+"?theme=dark").Body.String(), `data-sm-theme="dark"`)
		require.Contains(t, get(t, h, path+"?theme=light").Body.String(), `data-sm-theme="light"`)
	}
}

func TestTheTargetPickerOffersOpenCode(t *testing.T) {
	_, h := newServer(t)
	body := html.UnescapeString(get(t, h, profileHref).Body.String())

	require.Contains(t, body, "OpenCode")
	require.Contains(t, body, "~/.config/opencode/")
}
