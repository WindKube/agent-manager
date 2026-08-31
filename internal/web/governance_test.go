package web_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// T071-T075: the two governance screens.
//
// What these tests are about is the difference between a screen that shows what
// the hub knows and one that looks like it does. Three properties carry most of
// that weight and each has a test below it cannot pass by accident:
//
//   - Every check that ran is on the page, not only the failures (001 FR-025).
//   - The four states that are not a list of findings — signed out, refused,
//     unreachable, genuinely empty — are four screens and not one (FR-122).
//   - An action this viewer may not take is not offered (FR-126), and a post that
//     arrives anyway records nothing.

// governance is a ScannerSource, AuditSource, BadgeSource and Reviewer in one, so
// a test can state exactly what the api answers and then assert what reached the
// api. Every field is a knob some test turns; the zero value answers empties.
type governance struct {
	summary  hub.ScannerSummary
	findings []hub.Finding
	detail   hub.FindingDetail
	audit    []hub.AuditEntry
	badges   hub.Badges
	export   string
	err      error

	// accepted and rejected record what the reviewer was actually asked to do,
	// which is the only way to assert that a refusal refused BEFORE the call.
	accepted []acceptCall
	rejected []string
	decision hub.Decision
	decideBy error
}

type acceptCall struct {
	id, note string
	days     int
}

func (g *governance) Catalog(context.Context, view.CatalogQuery) (view.CatalogPage, error) {
	return view.CatalogPage{Query: view.CatalogQuery{}.Normalise(), Page: 1, PageSize: view.DefaultPageSize}, nil
}

func (g *governance) ScannerSummary(context.Context, int) (hub.ScannerSummary, error) {
	return g.summary, g.err
}

func (g *governance) Findings(context.Context, hub.FindingQuery) (hub.FindingsPage, error) {
	if g.err != nil {
		return hub.FindingsPage{}, g.err
	}
	return hub.FindingsPage{Findings: g.findings, Total: len(g.findings), Page: 1, PageSize: 20}, nil
}

func (g *governance) Finding(_ context.Context, id string) (hub.FindingDetail, error) {
	if g.err != nil {
		return hub.FindingDetail{}, g.err
	}
	if g.detail.ID != id {
		return hub.FindingDetail{}, view.ErrNotFound
	}
	return g.detail, nil
}

func (g *governance) AcceptFinding(_ context.Context, id, note string, days int) (hub.Decision, error) {
	g.accepted = append(g.accepted, acceptCall{id: id, note: note, days: days})
	return g.decision, g.decideBy
}

func (g *governance) RejectFinding(_ context.Context, id, _ string) (hub.Decision, error) {
	g.rejected = append(g.rejected, id)
	return g.decision, g.decideBy
}

func (g *governance) Audit(_ context.Context, page int) (hub.AuditPage, error) {
	if g.err != nil {
		return hub.AuditPage{}, g.err
	}
	return hub.AuditPage{Entries: g.audit, Total: len(g.audit), Page: page, PageSize: 50}, nil
}

func (g *governance) AuditExport(context.Context) (io.ReadCloser, string, error) {
	if g.err != nil {
		return nil, "", g.err
	}
	return io.NopCloser(strings.NewReader(g.export)), "application/x-ndjson", nil
}

func (g *governance) Badges(context.Context) (hub.Badges, error) { return g.badges, g.err }

// govHandler wires one governance source behind a viewer. reviewer is separate so
// a test can render the screen with the decision path absent, which is the state a
// hub with no reviewer wired is in.
func govHandler(source *governance, viewers web.ViewerSource, reviewer web.Reviewer) http.Handler {
	return web.New(web.Deps{
		Catalog: source, Scanner: source, Audit: source, Badges: source,
		Reviewer: reviewer, Viewers: viewers, Log: zerolog.Nop(),
	}, web.Options{}).Handler()
}

func post(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const govFindingID = "6f1c0a4e-9f4b-4f2a-9c1d-2f9b6a7e4d11"

func govFinding() hub.Finding {
	return hub.Finding{
		ID: govFindingID, RuleID: "SH-NET-002", Severity: "high", State: "open",
		Title:   "Script contacts a host the package does not declare",
		Subject: "community/slack-digest@0.5.1", PackageID: "community/slack-digest",
		Version: "0.5.1", Verdict: "flagged", RaisedAt: time.Now().Add(-time.Hour),
	}
}

// TestTheCheckMatrixShowsEveryCheckThatRanAndNotOnlyTheFailures is 001 FR-025.
//
// The requirement exists so that the absence of a finding is distinguishable from
// the absence of a check, which is a property only the PASSES carry: a pane
// listing one failed check is indistinguishable from a pane where that was the
// only check that ran.
func TestTheCheckMatrixShowsEveryCheckThatRanAndNotOnlyTheFailures(t *testing.T) {
	source := &governance{
		findings: []hub.Finding{govFinding()},
		detail: hub.FindingDetail{
			Finding: govFinding(),
			Checks: []hub.Check{
				{ID: "manifest-schema", Label: "Manifest schema", Result: "pass"},
				{ID: "network-allowlist", Label: "Network allowlist", Result: "fail"},
				{ID: "shell-audit", Label: "Shell command audit", Result: "warn", WarnCount: 2},
				{ID: "secret-exfiltration", Label: "Secret exfiltration", Result: "pass"},
			},
		},
	}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/scanner").Body.String()

	for _, label := range []string{"Manifest schema", "Network allowlist", "Shell command audit", "Secret exfiltration"} {
		require.Containsf(t, body, label, "the matrix dropped %q, so a check that ran is invisible", label)
	}
	require.Contains(t, body, "am-chk-mark-ok", "no pass is rendered, which is the half FR-025 is about")
	require.Contains(t, body, "am-chk-mark-dan")

	// The warn count is a blind-spot counter: files the check could not read. Shown
	// as a bare number beside a warning it reads as a number of problems, which is
	// its opposite.
	require.Contains(t, body, "2 files this check could not read")
	require.NotContains(t, body, "2 issues")
}

// TestScanEvidenceIsEscapedWhereverItIsRendered is FR-127 on the one screen whose
// whole subject is quoting a package somebody else wrote.
func TestScanEvidenceIsEscapedWhereverItIsRendered(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	hostile := govFinding()
	hostile.Title = "Title " + payload
	hostile.Subject = "community/x@1.0.0 " + payload

	source := &governance{
		findings: []hub.Finding{hostile},
		detail: hub.FindingDetail{
			Finding:     hostile,
			Explanation: "Detail " + payload,
			Evidence: []hub.Evidence{
				{Path: "scripts/" + payload + ".sh", Line: 41, Quote: payload, Role: "primary"},
				{Path: "second/" + payload, Quote: "supporting " + payload, Role: "supporting"},
			},
			Checks: []hub.Check{{ID: "shell-audit", Label: "Label " + payload, Result: "fail"}},
			Scan:   hub.Scan{PackVersion: "2026.08.31+" + payload},
			Override: &hub.Override{
				Reviewer: "reviewer " + payload, Note: "note " + payload, DecidedAt: time.Now(),
			},
		},
		audit: []hub.AuditEntry{{
			ID: "a1", OccurredAt: time.Now(), Actor: "actor " + payload,
			ActorKind: "identity", Kind: "scan", Text: "text " + payload, Source: "src " + payload,
		}},
	}
	h := govHandler(source, fixture.SignedInViewers(), nil)

	for _, target := range []string{"/scanner", "/audit"} {
		body := get(t, h, target).Body.String()
		require.NotContainsf(t, body, payload, "%s rendered attacker-supplied markup unescaped", target)
		require.Containsf(t, body, "&lt;img src=x onerror=", "%s did not render the value at all, "+
			"so this test is asserting nothing", target)
	}
}

// TestTheScannerTellsItsFourEmptyStatesApart is FR-122. Each of these is a
// different question with a different answer, and a screen that renders any two of
// them the same sends its reader somewhere useless.
func TestTheScannerTellsItsFourEmptyStatesApart(t *testing.T) {
	for _, state := range []struct {
		name   string
		source *governance
		view   web.ViewerSource
		id     string
		status int
	}{
		{
			name:   "genuinely empty",
			source: &governance{},
			view:   fixture.SignedInViewers(),
			id:     `id="scanner-empty"`,
			status: http.StatusOK,
		},
		{
			name:   "refused by role",
			source: &governance{err: hub.ErrForbidden},
			view:   fixture.SignedInViewers(),
			id:     `id="scanner-refused"`,
			status: http.StatusForbidden,
		},
		{
			name:   "the api did not answer",
			source: &governance{err: errBoom},
			view:   fixture.SignedInViewers(),
			id:     `id="scanner-unavailable"`,
			status: http.StatusBadGateway,
		},
		{
			name:   "no usable session",
			source: &governance{err: view.ErrSignedOut},
			view:   fixture.SignedInViewers(),
			id:     `id="scanner-signed-out"`,
			status: http.StatusOK,
		},
	} {
		t.Run(state.name, func(t *testing.T) {
			rec := get(t, govHandler(state.source, state.view, nil), "/scanner")
			require.Equal(t, state.status, rec.Code)
			body := rec.Body.String()
			require.Contains(t, body, state.id)

			for _, other := range []string{"scanner-empty", "scanner-refused", "scanner-unavailable", "scanner-signed-out"} {
				if strings.Contains(state.id, other) {
					continue
				}
				require.NotContainsf(t, body, `id="`+other+`"`, "this state also renders %q", other)
			}
		})
	}
}

// TestTheEmptyScannerSaysWhatWouldBeThereAndHowToGetIt is the other half of
// FR-122: an empty state that only says "nothing here" tells a reader nothing they
// did not already know.
func TestTheEmptyScannerSaysWhatWouldBeThereAndHowToGetIt(t *testing.T) {
	body := get(t, govHandler(&governance{}, fixture.SignedInViewers(), nil), "/scanner").Body.String()
	require.Contains(t, body, "register a package")
	require.Contains(t, body, "rule pack")

	audit := get(t, govHandler(&governance{}, fixture.SignedInViewers(), nil), "/audit").Body.String()
	require.Contains(t, audit, `id="audit-empty"`)
	require.Contains(t, audit, "state-changing action")
}

// TestAnActionAViewerMayNotTakeIsDisabledWithItsReason is FR-126.
func TestAnActionAViewerMayNotTakeIsDisabledWithItsReason(t *testing.T) {
	source := func() *governance {
		return &governance{findings: []hub.Finding{govFinding()}, detail: hub.FindingDetail{Finding: govFinding()}}
	}

	t.Run("a role that cannot decide gets the controls disabled and told why", func(t *testing.T) {
		body := get(t, govHandler(source(), readOnlyViewers(), &governance{}), "/scanner").Body.String()

		require.Contains(t, body, `id="review-not-permitted"`)
		require.Contains(t, body, "scanner reviewer")
		require.Contains(t, body, "disabled")
		// And no form, so there is nothing to submit even by hand-editing the page.
		require.NotContains(t, body, `class="am-review"`)
	})

	t.Run("a reviewer gets the real controls", func(t *testing.T) {
		body := get(t, govHandler(source(), fixture.SignedInViewers(), &governance{}), "/scanner").Body.String()

		require.Contains(t, body, `class="am-review"`)
		require.Contains(t, body, "/scanner/findings/"+govFindingID+"/accept")
		require.Contains(t, body, "/scanner/findings/"+govFindingID+"/reject")
		require.NotContains(t, body, `id="review-not-permitted"`)
	})

	t.Run("a hub with no reviewer wired offers nothing rather than something that fails", func(t *testing.T) {
		body := get(t, govHandler(source(), fixture.SignedInViewers(), nil), "/scanner").Body.String()
		require.Contains(t, body, `id="review-not-permitted"`)
		require.NotContains(t, body, `class="am-review"`)
	})
}

// TestADecisionFromAnIdentityWithoutTheRoleReachesNoApi is the other half of
// FR-126: disabling a control is presentation, and a post arrives anyway from an
// old page or a second tab.
func TestADecisionFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	reviewer := &governance{}
	h := govHandler(&governance{}, readOnlyViewers(), reviewer)

	rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"looks fine"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "decided=refused")
	require.Empty(t, reviewer.accepted, "the api was asked to record a decision this role may not take")
	require.Empty(t, reviewer.rejected)
}

// TestAnApproveWithNoNoteNeverReachesTheApi mirrors the api's own validation. It
// is a mirror and not the authority — the api still refuses a blank note — but a
// round trip spent learning what this side already knows is a round trip wasted.
func TestAnApproveWithNoNoteNeverReachesTheApi(t *testing.T) {
	reviewer := &governance{}
	h := govHandler(&governance{}, fixture.SignedInViewers(), reviewer)

	rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"   "}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "decided=note-required")
	require.Empty(t, reviewer.accepted)

	t.Run("but a rejection may carry none", func(t *testing.T) {
		rejected := post(t, h, "/scanner/findings/"+govFindingID+"/reject", url.Values{})
		require.Equal(t, http.StatusSeeOther, rejected.Code)
		require.Equal(t, []string{govFindingID}, reviewer.rejected)
	})
}

// TestAnAcceptSendsNoExpiryUnlessTheReviewerStatedOne. A lifetime this role
// invented would be a policy decision taken by a form field nobody filled in.
func TestAnAcceptSendsNoExpiryUnlessTheReviewerStatedOne(t *testing.T) {
	reviewer := &governance{}
	h := govHandler(&governance{}, fixture.SignedInViewers(), reviewer)

	post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"accepted"}})
	require.Equal(t, []acceptCall{{id: govFindingID, note: "accepted", days: 0}}, reviewer.accepted)

	reviewer.accepted = nil
	post(t, h, "/scanner/findings/"+govFindingID+"/accept",
		url.Values{"note": {"accepted"}, "expires": {"30"}})
	require.Equal(t, []acceptCall{{id: govFindingID, note: "accepted", days: 30}}, reviewer.accepted)

	t.Run("an expiry outside the api's range is refused here rather than there", func(t *testing.T) {
		reviewer.accepted = nil
		rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept",
			url.Values{"note": {"accepted"}, "expires": {"9999"}})
		require.Contains(t, rec.Header().Get("Location"), "decided=bad-expiry")
		require.Empty(t, reviewer.accepted)
	})
}

// TestApprovingNeverClaimsTheVersionBecameClean. An override is an accepted risk
// with a name against it; the version stays flagged, and a screen that said
// otherwise would be the dishonest surface this feature exists to delete.
func TestApprovingNeverClaimsTheVersionBecameClean(t *testing.T) {
	approved := govFinding()
	approved.State = "approved"
	approved.Verdict = "flagged"

	source := &governance{
		findings: []hub.Finding{approved},
		detail: hub.FindingDetail{
			Finding: approved,
			Override: &hub.Override{
				Reviewer: "a-reviewer", Note: "accepted for one quarter", DecidedAt: time.Now(),
			},
		},
	}
	body := get(t, govHandler(source, fixture.SignedInViewers(), &governance{}),
		"/scanner?finding="+govFindingID+"&decided=approved").Body.String()

	require.Contains(t, body, "Flagged", "the version's verdict is gone from the screen")
	require.Contains(t, body, "not a new verdict")
	require.Contains(t, body, `id="finding-override"`)
	require.NotContains(t, body, "Clean")
}

// TestAFindingWithNoRecordedEvidenceSaysSoRatherThanRenderingAnEmptyPanel. The
// seeded findings are all in this state, and an empty panel there reads as a
// rendering fault rather than as a fact about the scan.
func TestAFindingWithNoRecordedEvidenceSaysSoRatherThanRenderingAnEmptyPanel(t *testing.T) {
	source := &governance{
		findings: []hub.Finding{govFinding()},
		detail:   hub.FindingDetail{Finding: govFinding()},
	}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/scanner").Body.String()

	require.Contains(t, body, `id="finding-no-evidence"`)
	require.Contains(t, body, `id="finding-no-checks"`)
}

// TestThePrimaryEvidenceIsFoundByItsRoleAndNotByItsPosition. The api orders
// evidence by role and the hub promises nothing about position, so an index-based
// reader would promote a supporting location to the headline the day that changes.
func TestThePrimaryEvidenceIsFoundByItsRoleAndNotByItsPosition(t *testing.T) {
	source := &governance{
		findings: []hub.Finding{govFinding()},
		detail: hub.FindingDetail{
			Finding: govFinding(),
			Evidence: []hub.Evidence{
				{Path: "supporting.sh", Line: 9, Quote: "second", Role: "supporting"},
				{Path: "headline.sh", Line: 41, Quote: "first", Role: "primary"},
			},
		},
	}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/scanner").Body.String()

	headline := strings.Index(body, "headline.sh:41")
	supporting := strings.Index(body, "supporting.sh:9")
	require.Positive(t, headline)
	require.Positive(t, supporting)
	require.Less(t, headline, supporting, "the pane put a supporting location in the headline slot")
	require.Contains(t, body, `id="finding-evidence"`)
}

// TestAFindingIdThatNamesNothingIsItsOwnState, and it is the pane's state rather
// than the screen's: the list beside it read perfectly well.
func TestAFindingIdThatNamesNothingIsItsOwnState(t *testing.T) {
	source := &governance{findings: []hub.Finding{govFinding()}}
	rec := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/scanner?finding=not-a-uuid")

	require.Equal(t, http.StatusNotFound, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `id="scanner-missing"`)
	require.Contains(t, body, "Script contacts a host", "the findings list should still have rendered")
}

// TestTheAuditScreenNeverAttributesASystemRowToAPerson. `fetcher` and `scanner`
// are actors; a screen that let them read as usernames would put a machine's
// action against somebody with that name.
func TestTheAuditScreenNeverAttributesASystemRowToAPerson(t *testing.T) {
	source := &governance{audit: []hub.AuditEntry{
		{ID: "a1", OccurredAt: time.Now(), Actor: "scanner", ActorKind: "system", Kind: "scan", Text: "flagged x@1", Source: "system"},
		{ID: "a2", OccurredAt: time.Now(), Actor: "an-operator", ActorKind: "identity", Kind: "approve", Text: "override granted", Source: "web"},
	}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/audit").Body.String()

	require.Equal(t, 1, strings.Count(body, `class="am-audit-actor-kind"`),
		"exactly one of these two rows has a machine behind it")
	require.Contains(t, body, "am-pill-warn")
	require.Contains(t, body, "am-pill-ok")
}

// TestTheAuditExportStreamsThroughAndItsSentinelIsChecked is 001 FR-051 and the
// hub's own warning about it: a streamed response cannot change its status once it
// has started, so a truncated export arrives as a 200 whose last line is missing.
func TestTheAuditExportStreamsThroughAndItsSentinelIsChecked(t *testing.T) {
	complete := "{\"id\":\"a1\"}\n{\"complete\":true,\"rows\":1}\n"

	t.Run("a complete export is passed through byte for byte", func(t *testing.T) {
		var logged bytes.Buffer
		h := web.New(web.Deps{
			Catalog: &governance{}, Audit: &governance{export: complete},
			Viewers: fixture.SignedInViewers(), Log: zerolog.New(&logged),
		}, web.Options{}).Handler()

		rec := get(t, h, "/audit/export")

		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, complete, rec.Body.String())
		require.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
		require.Contains(t, rec.Header().Get("Content-Disposition"), `filename="audit-log.ndjson"`)
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		require.True(t, rec.Flushed, "the export was buffered rather than streamed")
		require.NotContains(t, logged.String(), "sentinel")
	})

	t.Run("a truncated export is still sent, and is reported as truncated", func(t *testing.T) {
		var logged bytes.Buffer
		h := web.New(web.Deps{
			Catalog: &governance{}, Audit: &governance{export: "{\"id\":\"a1\"}\n"},
			Viewers: fixture.SignedInViewers(), Log: zerolog.New(&logged),
		}, web.Options{}).Handler()

		rec := get(t, h, "/audit/export")

		// A 200 either way: the status went out with the first byte and cannot be
		// taken back. The log line is the only place this can be said.
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, logged.String(), "completeness sentinel")
	})

	t.Run("a row quoting the sentinel's own bytes is not mistaken for it", func(t *testing.T) {
		var logged bytes.Buffer
		h := web.New(web.Deps{
			Catalog: &governance{},
			Audit:   &governance{export: "{\"id\":\"a1\",\"text\":\"{\\\"complete\\\":true}\"}\n"},
			Viewers: fixture.SignedInViewers(), Log: zerolog.New(&logged),
		}, web.Options{}).Handler()

		get(t, h, "/audit/export")
		require.Contains(t, logged.String(), "completeness sentinel",
			"a text match on the sentinel's bytes would have called this export complete")
	})
}

// TestTheSidebarCountsAreTheApisAndAreAbsentRatherThanZero is FR-121 and research
// R5. The values this replaced were 10 / 4 / 4, compiled in, the same for every
// viewer of every deployment.
func TestTheSidebarCountsAreTheApisAndAreAbsentRatherThanZero(t *testing.T) {
	t.Run("the counts on the page are the ones the api answered", func(t *testing.T) {
		source := &governance{badges: hub.Badges{Packages: 7, Profiles: 3, OpenFindings: 11}}
		body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/catalog").Body.String()

		require.Contains(t, body, `<span class="am-nav-badge">7</span>`)
		require.Contains(t, body, `<span class="am-nav-badge">3</span>`)
		require.Contains(t, body, `<span class="am-nav-badge am-nav-badge-alert">11</span>`)
		for _, stale := range []string{">10<", ">4<"} {
			require.NotContainsf(t, body, `am-nav-badge">`+strings.Trim(stale, "<>"),
				"the design's seed value %q is still on the page", stale)
		}
	})

	t.Run("nothing to count renders no badge, not a zero", func(t *testing.T) {
		source := &governance{badges: hub.Badges{Packages: 2}}
		body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/catalog").Body.String()

		require.Contains(t, body, `<span class="am-nav-badge">2</span>`)
		require.NotContains(t, body, `>0</span>`, "a zero count was rendered as a badge")
	})

	t.Run("counts that could not be read render no badges at all", func(t *testing.T) {
		// Not three zeroes. "0 packages" beside a catalog full of them is the same
		// class of claim as the compiled-in values these replaced.
		source := &governance{err: errBoom}
		body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/catalog").Body.String()
		require.NotContains(t, body, "am-nav-badge")
	})
}

// TestNoRouteFromTheSidebarSaysItIsUnfinished is FR-120 for the two screens this
// layer takes off the placeholder list.
func TestNoRouteFromTheSidebarSaysItIsUnfinished(t *testing.T) {
	source := &governance{
		findings: []hub.Finding{govFinding()},
		detail:   hub.FindingDetail{Finding: govFinding()},
		audit:    []hub.AuditEntry{{ID: "a1", OccurredAt: time.Now(), Actor: "scanner", ActorKind: "system", Kind: "scan", Text: "flagged x@1"}},
	}
	h := govHandler(source, fixture.SignedInViewers(), &governance{})

	for _, target := range []string{"/scanner", "/audit"} {
		rec := get(t, h, target)
		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.NotContainsf(t, body, "am-placeholder", "%s still renders the placeholder card", target)
		require.NotContainsf(t, body, "not built yet", "%s still says it is unfinished", target)
	}
}

// TestFilteringAndPagingKeepTheRestOfTheScreensState. A filter that dropped the
// page or a page turn that dropped the filter is how a reviewer loses their place.
func TestFilteringAndPagingKeepTheRestOfTheScreensState(t *testing.T) {
	source := &governance{findings: []hub.Finding{govFinding()}, detail: hub.FindingDetail{Finding: govFinding()}}
	body := get(t, govHandler(source, fixture.SignedInViewers(), nil), "/scanner?state=open").Body.String()

	require.Contains(t, body, `href="/scanner?finding=`+govFindingID+`&amp;state=open"`,
		"selecting a finding dropped the filter")
	require.Contains(t, body, `<a class="am-chip am-chip-on" href="/scanner?state=open"`)
}

var errBoom = errorString("the api is not answering")

type errorString string

func (e errorString) Error() string { return string(e) }

// readOnlyViewers is somebody signed in, holding a role, whose role cannot decide
// a finding. It is a viewer of its own rather than the shared fixture with a field
// blanked, because "holds a role that cannot do this" and "holds no role" are two
// different screens.
func readOnlyViewers() web.ViewerSource {
	return fixture.Viewers{V: hub.Viewer{
		Subject: "read-only-subject", DisplayName: "readonly", Email: "readonly@fixture.invalid",
		Role: "read-only", HasRole: true, Groups: []string{"eng-all"},
	}}
}
