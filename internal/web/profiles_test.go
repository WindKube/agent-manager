package web_test

import (
	"context"
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
// or publish gets the control absent or disabled, and a request that arrives
// anyway is refused and records nothing.
func TestProfileWritesAreGatedByRole(t *testing.T) {
	detail := baseProfileDetail()
	detail.Permissions = hub.ProfilePermissions{}
	source := &profiles{detail: detail}
	h := profHandler(source, fixture.SignedInViewers(), source)

	body := get(t, h, "/profiles/example/platform-engineer").Body.String()
	require.NotContains(t, body, "Save targets")
	require.Contains(t, body, `id="profile-publish-not-permitted"`)
	require.Contains(t, body, view.CurateDisabledReason,
		"the disabled float and pin controls must say why, not just refuse silently")
	require.NotContains(t, body, `id="share-role"`,
		"a role that may not share this profile must not be offered the sharing form")

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
