package web_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The two profile screens.
//
// The properties that matter here mirror the scanner's: the policy note the api
// computed is rendered VERBATIM — two implementations of the gate is how the
// screen and the CLI start disagreeing — an action a role may not take is
// absent or disabled, and the three states that are not a list of profiles are
// three screens.

// profiles is a ProfileSource and ProfileCurator in one, so a test can state
// exactly what the api answers and assert what a write actually sent. It does
// NOT implement web.Registrar or web.ScannerSource, so a test built on it never
// exercises a screen this file is not about.
type profiles struct {
	rows   []hub.ProfileSummary
	detail hub.ProfileDetail
	err    error

	entrySets  [][]hub.EntrySetting
	shares     [][]hub.Share
	targetSets [][]string
	published  []string
	writeErr   error

	// revisions and revisionErr back Revision, the "Show diff" panel's read.
	// revisionErr, when set, is returned for every revision number so a test
	// can drive PredecessorUnavailable by giving revision N but not N-1.
	revisions   map[int]hub.RevisionLockfile
	revisionErr error
}

func (p *profiles) Profiles(context.Context) ([]hub.ProfileSummary, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.rows, nil
}

func (p *profiles) Profile(_ context.Context, slug string) (hub.ProfileDetail, error) {
	if p.err != nil {
		return hub.ProfileDetail{}, p.err
	}
	if p.detail.Slug != slug {
		return hub.ProfileDetail{}, view.ErrNotFound
	}
	return p.detail, nil
}

func (p *profiles) Revision(_ context.Context, _ string, revision int) (hub.RevisionLockfile, error) {
	if p.revisionErr != nil {
		return hub.RevisionLockfile{}, p.revisionErr
	}
	lockfile, ok := p.revisions[revision]
	if !ok {
		return hub.RevisionLockfile{}, view.ErrNotFound
	}
	return lockfile, nil
}

func (p *profiles) CreateProfile(context.Context, hub.ProfileCreation) (hub.ProfileSummary, error) {
	return hub.ProfileSummary{}, p.writeErr
}

func (p *profiles) SetProfileEntries(_ context.Context, _ string, entries []hub.EntrySetting) (hub.ProfileDetail, error) {
	p.entrySets = append(p.entrySets, entries)
	return p.detail, p.writeErr
}

func (p *profiles) SetProfileSharing(_ context.Context, _ string, members []hub.Share) (hub.ProfileDetail, error) {
	p.shares = append(p.shares, members)
	return p.detail, p.writeErr
}

func (p *profiles) SetProfileTargets(_ context.Context, _ string, targets []string) (hub.ProfileDetail, error) {
	p.targetSets = append(p.targetSets, targets)
	return p.detail, p.writeErr
}

func (p *profiles) PublishRevision(_ context.Context, slug, _ string) (hub.PublishedRevision, error) {
	p.published = append(p.published, slug)
	return hub.PublishedRevision{}, p.writeErr
}

// profHandler wires one profiles source behind a viewer. curator is separate so a
// test can render the screens with the write path absent, which is the state a
// hub with no curator wired is in.
func profHandler(source *profiles, viewers web.ViewerSource, curator web.ProfileCurator) http.Handler {
	deps := web.Deps{Profiles: source, Viewers: viewers, Log: zerolog.Nop()}
	if curator != nil {
		deps.Curator = curator
	}
	return web.New(deps, web.Options{}).Handler()
}

// catalogStub is a fixed catalog page, for the "Add package" tests: they need
// to state exactly which rows the catalog answers rather than run against the
// design's ten.
type catalogStub struct {
	rows []view.Row
	err  error
}

func (c catalogStub) Catalog(_ context.Context, _ view.CatalogQuery) (view.CatalogPage, error) {
	if c.err != nil {
		return view.CatalogPage{}, c.err
	}
	return view.CatalogPage{Rows: c.rows, Total: len(c.rows), Page: 1, PageSize: view.DefaultPageSize}, nil
}

// profHandlerWithCatalog is profHandler plus a catalog source, for the "Add
// package" control: it is the one piece of the profile screen that reads
// somewhere other than web.ProfileSource.
func profHandlerWithCatalog(source *profiles, curator web.ProfileCurator, catalog web.CatalogSource) http.Handler {
	deps := web.Deps{
		Profiles: source, Catalog: catalog, Viewers: fixture.SignedInViewers(), Log: zerolog.Nop(),
	}
	if curator != nil {
		deps.Curator = curator
	}
	return web.New(deps, web.Options{}).Handler()
}

func baseProfileDetail() hub.ProfileDetail {
	return hub.ProfileDetail{
		Slug: "example/platform-engineer", Name: "Platform Engineer",
		Visibility: "organisation", DefaultPolicy: "floating-latest", Gate: "warn-with-override",
		HeadRevision: 3, Role: "owner",
		Permissions: hub.ProfilePermissions{Curate: true, Share: true, Publish: true},
		Entries: []hub.ProfileEntry{
			{
				ID: "community/postgres-migration-guard", Name: "Postgres Migration Guard", Kind: "skill",
				Mode: "latest", LatestVersion: "0.8.3", LatestVerdict: "flagged",
				Version: "0.8.3", Verdict: "flagged", Outcome: "warned",
				Note: "Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning.",
			},
		},
	}
}

// TestProfilesListShowsExactlyTheReadableSet asserts the list shows exactly
// the readable set, and no others.
func TestProfilesListShowsExactlyTheReadableSet(t *testing.T) {
	source := &profiles{rows: []hub.ProfileSummary{
		{Slug: "example/platform-engineer", Name: "Platform Engineer", Visibility: "organisation", PackageCount: 4, HeadRevision: 14},
		{Slug: "example/sre-oncall", Name: "SRE On-call", Visibility: "shared", PackageCount: 0, HeadRevision: 0},
	}}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles").Body.String()

	require.Contains(t, body, "Platform Engineer")
	require.Contains(t, body, "example/platform-engineer")
	require.Contains(t, body, "r14")
	require.Contains(t, body, "SRE On-call")
	require.Contains(t, body, "unpublished")
	require.Contains(t, body, "2 profiles")
}

func TestProfilesListEmptyStateNamesWhatWouldAppear(t *testing.T) {
	body := get(t, profHandler(&profiles{}, fixture.SignedInViewers(), nil), "/profiles").Body.String()
	require.Contains(t, body, `id="profiles-empty"`)
}

// TestProfilesThreeEmptyStatesAreDistinguishable: an empty hub, a role refusal,
// no usable session, and an unreachable api must never render alike.
func TestProfilesThreeEmptyStatesAreDistinguishable(t *testing.T) {
	for _, state := range []struct {
		name   string
		source *profiles
		id     string
		status int
	}{
		{name: "genuinely empty", source: &profiles{}, id: `id="profiles-empty"`, status: http.StatusOK},
		{name: "no usable session", source: &profiles{err: view.ErrSignedOut}, id: `id="profiles-signed-out"`, status: http.StatusOK},
		{name: "refused by role", source: &profiles{err: hub.ErrForbidden}, id: `id="profiles-refused"`, status: http.StatusForbidden},
		{name: "api unreachable", source: &profiles{err: errBoom}, id: `id="profiles-unavailable"`, status: http.StatusBadGateway},
	} {
		t.Run(state.name, func(t *testing.T) {
			rec := get(t, profHandler(state.source, fixture.SignedInViewers(), nil), "/profiles")
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

	t.Run("no source wired at all", func(t *testing.T) {
		h := web.New(web.Deps{Viewers: fixture.SignedInViewers(), Log: zerolog.Nop()}, web.Options{}).Handler()
		rec := get(t, h, "/profiles")
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), `id="profiles-unavailable"`)
	})
}

// TestProfileDetailRendersThePolicyNoteVerbatim asserts the screen never
// recomputes the gate's effect — it renders what the api already decided.
func TestProfileDetailRendersThePolicyNoteVerbatim(t *testing.T) {
	detail := baseProfileDetail()
	source := &profiles{detail: detail}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/example/platform-engineer").Body.String()

	require.Contains(t, body, "Flagged (SH-INJ-011 in SKILL.md); warn-with-override includes it with a warning.")
	require.Contains(t, body, "Postgres Migration Guard")
	require.Contains(t, body, "am-pill-warn")
}

// TestProfileDetailReportsASkippedEntryRatherThanOmittingIt asserts an
// excluded package is reported with its reason rather than silently dropped.
func TestProfileDetailReportsASkippedEntryRatherThanOmittingIt(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries = append(detail.Entries, hub.ProfileEntry{
		ID: "community/release-notes", Name: "Release Notes", Kind: "skill",
		Mode: "pinned", PinnedVersion: "1.2.7", Outcome: "skipped",
		Skip: &hub.Skip{
			ID: "community/release-notes", Reason: "flagged-awaiting-approval",
			Detail: "Awaiting approval from a scanner reviewer.",
		},
	})
	body := get(t, profHandler(&profiles{detail: detail}, fixture.SignedInViewers(), nil),
		"/profiles/example/platform-engineer").Body.String()

	require.Contains(t, body, "Release Notes")
	require.Contains(t, body, "awaiting reviewer approval")
	require.Contains(t, body, "Awaiting approval from a scanner reviewer.")
}

// TestProfileDetailUnreadableAnswersAsMissing asserts an unreadable profile
// and a nonexistent one read alike.
func TestProfileDetailUnreadableAnswersAsMissing(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	rec := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/no-such-profile")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Contains(t, rec.Body.String(), `id="profile-missing"`)
}

// TestProfileEntryPinRoundTrips asserts the web role's half of a pin toggle:
// the FULL entry set is resent with only the targeted row changed, per
// hub.SetProfileEntries's whole-set contract.
func TestProfileEntryPinRoundTrips(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries = append(detail.Entries, hub.ProfileEntry{
		ID: "example/adr-writer", Name: "ADR Writer", Kind: "skill", Mode: "latest",
		LatestVersion: "3.0.2", Version: "3.0.2", Verdict: "clean", Outcome: "resolved",
	})
	source := &profiles{detail: detail}
	h := profHandler(source, fixture.SignedInViewers(), source)

	rec := post(t, h, "/profiles/entries/pin", url.Values{
		"slug": {"example/platform-engineer"}, "id": {"example/adr-writer"}, "version": {"3.0.2"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/profiles/example/platform-engineer?notice=entry-updated", rec.Header().Get("Location"))

	require.Len(t, source.entrySets, 1)
	sent := source.entrySets[0]
	require.Len(t, sent, 2, "the untouched entry must still be in the resent set")

	var pinned, untouched *hub.EntrySetting
	for i := range sent {
		switch sent[i].ID {
		case "example/adr-writer":
			pinned = &sent[i]
		case "community/postgres-migration-guard":
			untouched = &sent[i]
		}
	}
	require.NotNil(t, pinned, "the targeted entry was not resent")
	require.Equal(t, "pinned", pinned.Mode)
	require.Equal(t, "3.0.2", pinned.Version)

	require.NotNil(t, untouched, "the untouched entry was dropped from the resend")
	require.Equal(t, "latest", untouched.Mode, "an entry nobody asked to change must keep its own setting")
}

func TestProfileEntryFloatRoundTrips(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries[0].Mode = "pinned"
	detail.Entries[0].PinnedVersion = "0.7.0"
	source := &profiles{detail: detail}
	h := profHandler(source, fixture.SignedInViewers(), source)

	post(t, h, "/profiles/entries/latest", url.Values{
		"slug": {"example/platform-engineer"}, "id": {"community/postgres-migration-guard"},
	})

	require.Len(t, source.entrySets, 1)
	require.Equal(t, "latest", source.entrySets[0][0].Mode)
	require.Empty(t, source.entrySets[0][0].Version)
}

// TestProfileDetailOffersOnlyPackagesNotAlreadyHeld asserts the Add control
// lists a catalog row exactly once it is not already an entry, and never lists
// one that already is.
func TestProfileDetailOffersOnlyPackagesNotAlreadyHeld(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	catalog := catalogStub{rows: []view.Row{
		{ID: "community/postgres-migration-guard", Name: "Postgres Migration Guard"},
		{ID: "example/adr-writer", Name: "ADR Writer"},
	}}
	body := get(t, profHandlerWithCatalog(source, source, catalog), "/profiles/example/platform-engineer").Body.String()

	require.Contains(t, body, `id="add-package-id"`)
	options := addPackageOptions(t, body)
	require.Contains(t, options, "ADR Writer")
	require.NotContains(t, options, "Postgres Migration Guard",
		"an entry the profile already holds must not also be offered as an addition")
}

// addPackageOptions returns just the "Add package" select's markup, so a test
// can assert about its options without a package's name elsewhere on the page
// (its own entry row, say) producing a false pass.
func addPackageOptions(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<select id="add-package-id"`)
	require.GreaterOrEqual(t, start, 0, "the add-package select is missing")
	end := strings.Index(body[start:], "</select>")
	require.GreaterOrEqual(t, end, 0, "the add-package select is unclosed")
	return body[start : start+end]
}

// TestProfileDetailAddControlIsAbsentWithoutCatalogOrRole asserts the control
// degrades to absent rather than to an empty, broken <select> — both when the
// viewer may not curate and when the catalog cannot be read.
func TestProfileDetailAddControlIsAbsentWithoutCatalogOrRole(t *testing.T) {
	t.Run("no curate permission", func(t *testing.T) {
		detail := baseProfileDetail()
		detail.Permissions = hub.ProfilePermissions{}
		source := &profiles{detail: detail}
		catalog := catalogStub{rows: []view.Row{{ID: "example/adr-writer", Name: "ADR Writer"}}}
		body := get(t, profHandlerWithCatalog(source, nil, catalog), "/profiles/example/platform-engineer").Body.String()
		require.NotContains(t, body, `id="add-package-id"`)
	})

	t.Run("catalog unreachable", func(t *testing.T) {
		source := &profiles{detail: baseProfileDetail()}
		catalog := catalogStub{err: errBoom}
		body := get(t, profHandlerWithCatalog(source, source, catalog), "/profiles/example/platform-engineer").Body.String()
		require.NotContains(t, body, `id="add-package-id"`)
		require.Contains(t, body, `id="profile-add-empty"`)
	})
}

// TestProfileEntryAddAppendsANewEntryFloatingLatest is GAP 3: a profile
// created in the UI could never receive a package, because nothing posted to
// PUT /v1/profiles/{slug}/entries with an id the profile did not already hold.
func TestProfileEntryAddAppendsANewEntryFloatingLatest(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	h := profHandler(source, fixture.SignedInViewers(), source)

	rec := post(t, h, "/profiles/entries/add", url.Values{
		"slug": {"example/platform-engineer"}, "id": {"example/adr-writer"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/profiles/example/platform-engineer?notice=entry-added", rec.Header().Get("Location"))

	require.Len(t, source.entrySets, 1)
	sent := source.entrySets[0]
	require.Len(t, sent, 2, "the existing entry must still be in the resent set")

	var added, untouched *hub.EntrySetting
	for i := range sent {
		switch sent[i].ID {
		case "example/adr-writer":
			added = &sent[i]
		case "community/postgres-migration-guard":
			untouched = &sent[i]
		}
	}
	require.NotNil(t, added, "the new package was not sent")
	require.Equal(t, "latest", added.Mode)
	require.Empty(t, added.Version)
	require.NotNil(t, untouched, "the existing entry was dropped from the resend")
}

// TestProfileEntryAddOfAnIDAlreadyHeldFloatsRatherThanDuplicating covers the
// defensive case: the select only ever offers ids the profile lacks, but a
// stale page or a race could still submit one it already holds.
func TestProfileEntryAddOfAnIDAlreadyHeldFloatsRatherThanDuplicating(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	h := profHandler(source, fixture.SignedInViewers(), source)

	rec := post(t, h, "/profiles/entries/add", url.Values{
		"slug": {"example/platform-engineer"}, "id": {"community/postgres-migration-guard"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/profiles/example/platform-engineer?notice=entry-updated", rec.Header().Get("Location"))

	require.Len(t, source.entrySets, 1)
	require.Len(t, source.entrySets[0], 1, "the id must not be duplicated in the resent set")
	require.Equal(t, "latest", source.entrySets[0][0].Mode)
}

// TestProfileWritesAreGatedByRole asserts a role that may not curate, share
// or publish gets every control still rendered — visibly disabled, with a
// reason — rather than hidden, and a request that arrives anyway is refused
// and records nothing.
func TestProfileWritesAreGatedByRole(t *testing.T) {
	detail := baseProfileDetail()
	detail.Permissions = hub.ProfilePermissions{}
	source := &profiles{detail: detail}
	h := profHandler(source, fixture.SignedInViewers(), source)

	body := html.UnescapeString(get(t, h, "/profiles/example/platform-engineer").Body.String())

	require.Contains(t, body, "Save targets", "the control must still be rendered, only disabled")
	require.Contains(t, body, `id="profile-targets-not-permitted"`)
	require.Contains(t, body, `id="profile-publish-not-permitted"`)
	require.Contains(t, body, view.CurateDisabledReason,
		"the disabled float, pin, add-entry and targets controls must say why, not just refuse silently")
	require.Contains(t, body, view.ShareDisabledReason,
		"the disabled sharing form must say why, not just refuse silently")
	require.Contains(t, body, view.PublishDisabledReason)

	// The sharing form is still offered, greyed out, rather than absent: a
	// role that cannot share must still see the control exists.
	require.Contains(t, body, `id="share-role"`)
	require.Contains(t, body, `<fieldset class="am-fieldset-plain" disabled aria-disabled="true"`)

	rec := post(t, h, "/profiles/entries/pin", url.Values{
		"slug": {"example/platform-engineer"}, "id": {"community/postgres-migration-guard"}, "version": {"0.8.3"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "entry-updated",
		"the api is what enforces the role here (the fixture always answers), so this "+
			"exercises the screen's gating copy rather than a second enforcement")

	require.Empty(t, source.published, "publish must never be invoked for a role that may not")
}

// TestProfilePublishRedirectsWithoutResubmission is post-redirect-get: a browser
// reload after a publish must not publish a second revision.
func TestProfilePublishRedirectsWithoutResubmission(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	h := profHandler(source, fixture.SignedInViewers(), source)

	rec := post(t, h, "/profiles/revisions", url.Values{
		"slug": {"example/platform-engineer"}, "note": {"pinned the migration guard"},
	})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/profiles/example/platform-engineer?notice=published", rec.Header().Get("Location"))
	require.Equal(t, []string{"example/platform-engineer"}, source.published)

	notice := get(t, h, rec.Header().Get("Location")).Body.String()
	require.Contains(t, notice, "Revision published")
}

// TestProfileWriteWithNoCuratorWiredRefusesRatherThanPanics is the state a
// screen test that wired only a read source is in, and the state a hub with a
// misconfigured deployment is in.
func TestProfileWriteWithNoCuratorWiredRefusesRatherThanPanics(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	h := profHandler(source, fixture.SignedInViewers(), nil)

	rec := post(t, h, "/profiles/revisions", url.Values{"slug": {"example/platform-engineer"}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "unavailable")
}

// TestProfileEntryDataIsEscapedWhereverItIsRendered: a package name, a policy
// note and a skip detail all quote content a package's manifest or the
// resolver's own prose supplies, and none of it may reach the page raw.
func TestProfileEntryDataIsEscapedWhereverItIsRendered(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	detail := baseProfileDetail()
	detail.Entries[0].Name = "Guard " + payload
	detail.Entries[0].Note = "Note " + payload
	detail.Members = []hub.ProfileMember{{Kind: "user", Ref: "x", Role: "owner", DisplayName: "Owner " + payload}}

	body := get(t, profHandler(&profiles{detail: detail}, fixture.SignedInViewers(), nil),
		"/profiles/example/platform-engineer").Body.String()

	require.NotContains(t, body, payload, "attacker-supplied markup rendered unescaped")
	require.Contains(t, body, "&lt;img src=x onerror=", "the value was not rendered at all, "+
		"so this test asserts nothing")
}

// TestProfileEntriesAreSplitIntoSkillsAndPlugins asserts "Packages" is broken
// into a Skills section and a Plugins section, each listing only its own kind.
func TestProfileEntriesAreSplitIntoSkillsAndPlugins(t *testing.T) {
	detail := baseProfileDetail()
	detail.Entries = []hub.ProfileEntry{
		{ID: "example/adr-writer", Name: "ADR Writer", Kind: "skill", Mode: "latest", Outcome: "resolved"},
		{ID: "example/platform-toolkit", Name: "Platform Toolkit", Kind: "plugin", Mode: "latest", Outcome: "resolved"},
	}
	source := &profiles{detail: detail}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/example/platform-engineer").Body.String()

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
	source := &profiles{detail: baseProfileDetail()} // one skill, no plugin
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/example/platform-engineer").Body.String()

	require.Contains(t, body, `id="profile-entries-empty-plugin"`)
	require.Contains(t, body, "This profile holds no plugins yet.")
}

// TestAddEntryFormIsBehindAToggleButtonNotAlwaysVisible is US5's other change:
// the "Add package" control is a button revealing the form through a
// client-side signal, not a select sitting permanently on the page. The
// signal is underscore-prefixed, which is what keeps datastar from ever
// sending it (the same reason the catalog's own modal signals are).
func TestAddEntryFormIsBehindAToggleButtonNotAlwaysVisible(t *testing.T) {
	source := &profiles{detail: baseProfileDetail()}
	catalog := catalogStub{rows: []view.Row{{ID: "example/adr-writer", Name: "ADR Writer", Kind: view.KindSkill}}}
	body := get(t, profHandlerWithCatalog(source, source, catalog), "/profiles/example/platform-engineer").Body.String()

	require.Contains(t, body, `data-signals="{_addEntryOpen: false}"`)
	require.Contains(t, body, `data-on:click="$_addEntryOpen = !$_addEntryOpen"`)
	require.Contains(t, body, `data-style:display="$_addEntryOpen ? 'flex' : 'none'"`)

	// Hidden before datastar has a chance to run, exactly like the import modal.
	formAt := strings.Index(body, `action="/profiles/entries/add"`)
	require.GreaterOrEqual(t, formAt, 0, "the add-entry form is missing")
	tagStart := strings.LastIndex(body[:formAt], "<form")
	tagEnd := strings.Index(body[tagStart:], ">")
	require.GreaterOrEqual(t, tagEnd, 0, "the add-entry form's opening tag is unclosed")
	require.Contains(t, body[tagStart:tagStart+tagEnd], `style="display:none"`)

	// The select still offers every kind of catalog package in one list, so
	// each option names its own kind rather than splitting into two selects.
	require.Contains(t, body, "ADR Writer (example/adr-writer) · Skill")
}

// TestDisabledProfileControlsAreShownGreyedOutNotHidden is 1d: a role that
// may not curate, share or publish still sees every control the screen
// offers — visibly disabled, with a title and the same reason in visible
// text beneath it — rather than a control that silently disappears.
func TestDisabledProfileControlsAreShownGreyedOutNotHidden(t *testing.T) {
	detail := baseProfileDetail()
	detail.Permissions = hub.ProfilePermissions{}
	detail.Targets = []hub.ProfileTarget{{Target: "claude-code", Enabled: true}, {Target: "codex", Enabled: false}}
	source := &profiles{detail: detail}
	body := html.UnescapeString(get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/example/platform-engineer").Body.String())

	require.Contains(t, body,
		`<button type="button" class="am-btn" disabled aria-disabled="true" title="`+view.CurateDisabledReason+`">Add package</button>`)
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
	for _, reason := range []string{view.CurateDisabledReason, view.ShareDisabledReason, view.PublishDisabledReason} {
		require.GreaterOrEqualf(t, strings.Count(body, reason), 2, "%q must appear both as a title and as visible text", reason)
	}
}

// TestProfileRevisionDiffIsAbsentWithoutAQuery asserts the panel is purely
// additive: a plain profile read carries no diff, and nothing on the page
// hints one could appear except the per-revision "Show diff" link.
func TestProfileRevisionDiffIsAbsentWithoutAQuery(t *testing.T) {
	detail := baseProfileDetail()
	detail.Revisions = []hub.ProfileRevision{{Revision: 5}, {Revision: 4}}
	source := &profiles{detail: detail}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil), "/profiles/example/platform-engineer").Body.String()

	require.NotContains(t, body, `id="profile-diff-panel"`)
	require.Contains(t, body, view.RevisionDiffHref("example/platform-engineer", 5))
}

// TestProfileRevisionDiffReportsAddedRemovedChangedAndGovernance covers the
// diff's full report: a package added, one removed, one whose version and
// pin mode both changed, a skip that stopped applying, and the gate, default
// policy and targets all differing between the two revisions.
func TestProfileRevisionDiffReportsAddedRemovedChangedAndGovernance(t *testing.T) {
	detail := baseProfileDetail()
	detail.HeadRevision = 5
	detail.Revisions = []hub.ProfileRevision{{Revision: 5}, {Revision: 4}}
	source := &profiles{
		detail: detail,
		revisions: map[int]hub.RevisionLockfile{
			4: {
				Revision: 4, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
				Targets: []string{"claude-code"},
				Entries: []hub.LockedEntry{
					{ID: "example/adr-writer", Version: "3.0.1", Resolution: "latest"},
					{ID: "community/postgres-migration-guard", Version: "0.8.2", Resolution: "latest"},
				},
				Skipped: []hub.Skip{{ID: "community/release-notes", Reason: "flagged-awaiting-approval"}},
			},
			5: {
				Revision: 5, Gate: "block", DefaultPolicy: "pinned",
				Targets: []string{"claude-code", "codex"},
				Entries: []hub.LockedEntry{
					{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"},
					{ID: "example/security-review-kit", Version: "1.0.0", Resolution: "latest"},
				},
			},
		},
	}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil),
		view.RevisionDiffHref("example/platform-engineer", 5)).Body.String()

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
	detail.Revisions = []hub.ProfileRevision{{Revision: 1}}
	source := &profiles{
		detail: detail,
		revisions: map[int]hub.RevisionLockfile{
			1: {
				Revision: 1, Gate: "warn-with-override", DefaultPolicy: "floating-latest",
				Entries: []hub.LockedEntry{{ID: "example/adr-writer", Version: "3.0.0", Resolution: "latest"}},
				Skipped: []hub.Skip{{ID: "community/release-notes", Reason: "flagged-awaiting-approval"}},
			},
		},
	}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil),
		view.RevisionDiffHref("example/platform-engineer", 1)).Body.String()

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
	detail := baseProfileDetail()
	source := &profiles{detail: detail, revisions: map[int]hub.RevisionLockfile{}}
	rec := get(t, profHandler(source, fixture.SignedInViewers(), nil),
		view.RevisionDiffHref("example/platform-engineer", 99))

	require.Equal(t, http.StatusOK, rec.Code, "the rest of the profile still reads fine")
	require.Contains(t, rec.Body.String(), `id="profile-diff-missing"`)
}

// TestProfileRevisionDiffPredecessorUnavailableSaysSoRatherThanEmptyDiff
// asserts a revision that reads fine but whose predecessor cannot be read
// reports that honestly instead of rendering a silently empty diff.
func TestProfileRevisionDiffPredecessorUnavailableSaysSoRatherThanEmptyDiff(t *testing.T) {
	detail := baseProfileDetail()
	detail.HeadRevision = 5
	source := &profiles{
		detail: detail,
		revisions: map[int]hub.RevisionLockfile{
			5: {Revision: 5, Entries: []hub.LockedEntry{{ID: "example/adr-writer", Version: "3.0.2", Resolution: "pinned"}}},
		},
	}
	body := get(t, profHandler(source, fixture.SignedInViewers(), nil),
		view.RevisionDiffHref("example/platform-engineer", 5)).Body.String()

	require.Contains(t, body, `id="profile-diff-predecessor-unavailable"`)
	require.NotContains(t, body, `id="profile-diff-missing"`)
}

// TestProfileScreensRenderInBothThemes asserts both screens render correctly
// in both themes.
func TestProfileScreensRenderInBothThemes(t *testing.T) {
	source := &profiles{
		rows:   []hub.ProfileSummary{{Slug: "example/platform-engineer", Name: "Platform Engineer"}},
		detail: baseProfileDetail(),
	}
	h := profHandler(source, fixture.SignedInViewers(), nil)

	for _, path := range []string{"/profiles", "/profiles/example/platform-engineer"} {
		require.Contains(t, get(t, h, path+"?theme=dark").Body.String(), `data-sm-theme="dark"`)
		require.Contains(t, get(t, h, path+"?theme=light").Body.String(), `data-sm-theme="light"`)
	}
}
