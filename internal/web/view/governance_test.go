package view_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/view"
)

func TestNoHeadlineFigureInventsAValueItWasNotGiven(t *testing.T) {
	t.Run("no scan finished in the window is not a median of zero", func(t *testing.T) {
		cards := view.ScannerSummary{PeriodDays: 30}.Cards()
		median := cardNamed(t, cards, "Median scan time")

		require.Equal(t, "—", median.Value)
		require.NotEqual(t, "0s", median.Value, "a scanner that answers instantly is not what this means")
		require.Contains(t, median.Note, "no scan finished")
	})

	t.Run("a measured median keeps its unit however small it is", func(t *testing.T) {
		cards := view.ScannerSummary{PeriodDays: 30, MedianScan: "0ms"}.Cards()
		require.Equal(t, "0ms", cardNamed(t, cards, "Median scan time").Value)
	})

	t.Run("no active override is not an override that never expires", func(t *testing.T) {
		none := cardNamed(t, view.ScannerSummary{}.Cards(), "Overrides active")
		require.Equal(t, "0", none.Value)
		require.Contains(t, none.Note, "no accepted risk")

		forever := cardNamed(t, view.ScannerSummary{OverridesActive: 2}.Cards(), "Overrides active")
		require.Contains(t, forever.Note, "none of them expires")

		lapsing := cardNamed(t, view.ScannerSummary{OverridesActive: 1, NearestExpiry: "in 12 days"}.Cards(),
			"Overrides active")
		require.Contains(t, lapsing.Note, "in 12 days")
	})

	t.Run("the window is the api's figure and never a caption", func(t *testing.T) {
		// The period must come from the api, never be hardcoded.
		require.Contains(t, cardNamed(t, view.ScannerSummary{PeriodDays: 7}.Cards(), "Versions scanned").Note,
			"last 7 days")
		require.Contains(t, cardNamed(t, view.ScannerSummary{}.Cards(), "Versions scanned").Note,
			"no window reported")
	})
}

func cardNamed(t *testing.T, cards []view.StatCard, label string) view.StatCard {
	t.Helper()
	for _, card := range cards {
		if card.Label == label {
			return card
		}
	}
	require.FailNowf(t, "no such card", "the summary has no %q card", label)
	return view.StatCard{}
}

func TestAWarnCountIsNeverRenderedAsANumberOfIssues(t *testing.T) {
	require.Empty(t, view.Check{Result: view.CheckWarn}.Note(),
		"zero is a genuine none and needs no sentence")

	note := view.Check{Result: view.CheckWarn, WarnCount: 2}.Note()
	require.Contains(t, note, "could not read")
	require.NotContains(t, strings.ToLower(note), "issue")
	require.NotContains(t, strings.ToLower(note), "problem")
	require.Contains(t, view.Check{Result: view.CheckWarn, WarnCount: 1}.Note(), "1 file ")
}

func TestAnApprovedFindingIsNeverPaintedAsAPass(t *testing.T) {
	require.Equal(t, "neutral", view.FindingApproved.Tone())
	require.Equal(t, "warn", view.FindingOpen.Tone())
	require.Equal(t, "dan", view.FindingRejected.Tone())

	// The catalog collapses rejected and flagged; this screen must not.
	require.NotEqual(t, view.VerdictFlagged.Label(), view.VerdictRejected.Label())
	require.Equal(t, "ok", view.VerdictClean.Tone())
	require.Equal(t, "warn", view.VerdictScanning.Tone())
}

func TestAnUnknownSeverityRendersAsItself(t *testing.T) {
	require.Equal(t, "critical", view.Severity("critical").Label())
	require.Equal(t, "neutral", view.Severity("critical").Tone())
	require.Equal(t, "Unrated", view.Severity("").Label())

	require.Equal(t, "triaged", view.FindingState("triaged").Label())
	require.Equal(t, "neutral", view.KindTone("some-kind-added-later"))
}

// TestOnlyTheRolesTheApiAcceptsMayDecideAFinding pins the mirror of internal/api/authz.go's decision roles.
func TestOnlyTheRolesTheApiAcceptsMayDecideAFinding(t *testing.T) {
	require.ElementsMatch(t, []string{"scanner-reviewer", "catalog-admin"}, view.ScannerDecisionRoles,
		"the api's scannerDecisionRoles and this mirror have drifted")

	for _, role := range view.ScannerDecisionRoles {
		review := view.ReviewFor(&view.Viewer{SignedIn: true, Role: role, HasRole: true})
		require.Truef(t, review.Allowed, "%s may decide a finding at the api and not here", role)
		require.Empty(t, review.Reason)
	}

	for _, role := range []string{"read-only", "profile-consumer"} {
		review := view.ReviewFor(&view.Viewer{SignedIn: true, Role: role, HasRole: true})
		require.Falsef(t, review.Allowed, "%s may not decide a finding", role)
		require.Containsf(t, review.Reason, "scanner reviewer",
			"the refusal has to name what the reader needs, not only that they lack it")
	}

	t.Run("nobody resolved may decide anything", func(t *testing.T) {
		// There is no default viewer; nil must never read as permitted.
		require.False(t, view.ReviewFor(nil).Allowed)
		require.NotEmpty(t, view.ReviewFor(nil).Reason)
	})

	t.Run("signed in with no role is its own refusal", func(t *testing.T) {
		review := view.ReviewFor(&view.Viewer{SignedIn: true})
		require.False(t, review.Allowed)
		require.Contains(t, review.Reason, "not mapped to a role")
	})
}

func TestDurationReadsTheWayTheDesignsFigureDoes(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{-time.Second, ""},
		{450 * time.Millisecond, "450ms"},
		{1500 * time.Millisecond, "1.5s"},
		{18 * time.Second, "18s"},
		{18500 * time.Millisecond, "19s"},
		{90 * time.Second, "1m 30s"},
		{2 * time.Minute, "2 minutes"},
	} {
		require.Equalf(t, tc.want, view.Duration(tc.in), "Duration(%s)", tc.in)
	}
}

func TestALapsedExpiryReadsAsExpiredRatherThanAsANegativeAge(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	require.Equal(t, "expired", view.Until(now.Add(-time.Hour), now))
	require.Equal(t, "expired", view.Until(now, now))
	require.Equal(t, "in 12 days", view.Until(now.Add(12*24*time.Hour), now))
	require.Equal(t, "in 30 minutes", view.Until(now.Add(30*time.Minute), now))
	require.Equal(t, "in 1 hour", view.Until(now.Add(time.Hour+time.Minute), now))
}

func TestTheScannerScreensLinksCarryTheRestOfItsState(t *testing.T) {
	q := view.ScannerQuery{State: "open", Page: 2, Selected: "abc"}.Normalise()

	require.Equal(t, "/scanner?finding=abc&page=3&state=open", q.PageHref(3))
	require.Equal(t, "/scanner?page=2&state=open", q.SelectHref(""))
	// A filter change drops the selection on purpose, since the new filter may exclude it.
	require.Equal(t, "/scanner?state=rejected", q.FilterHref("rejected"))
	require.Equal(t, "/scanner", q.FilterHref("all"))

	t.Run("an unknown filter is the unfiltered one", func(t *testing.T) {
		require.Equal(t, "all", view.ScannerQuery{State: "../../etc"}.Normalise().State)
		require.Equal(t, "open", view.ScannerQuery{State: "open"}.Normalise().APIState())
		require.Empty(t, view.ScannerQuery{}.Normalise().APIState())
	})

	t.Run("an unbounded id from the url is not echoed back into every link", func(t *testing.T) {
		long := view.ScannerQuery{Selected: strings.Repeat("a", 500)}.Normalise()
		require.Empty(t, long.Selected)
	})
}

// TestTheAuditPagerAndExportAddressWhatTheyClaimTo: the export is the full current scope, so it carries no page.
func TestTheAuditPagerAndExportAddressWhatTheyClaimTo(t *testing.T) {
	require.Equal(t, "/audit", view.AuditPageHref(1))
	require.Equal(t, "/audit", view.AuditPageHref(0))
	require.Equal(t, "/audit?page=4", view.AuditPageHref(4))
	require.NotContains(t, view.AuditExportHref, "page")
}

func TestAnAuditRowNeverLeavesACellSilentlyBlank(t *testing.T) {
	require.Equal(t, "—", view.AuditRow{}.SourceLabel())
	require.Equal(t, "web", view.AuditRow{Source: "web"}.SourceLabel())

	require.Equal(t, "system", view.AuditRow{System: true}.ActorNote())
	require.Empty(t, view.AuditRow{}.ActorNote(),
		"a person's row is annotated by nothing; the actor column is the statement")
}

func TestTheAuditDetailPanelNamesAnUnrecordedSourceRatherThanLeavingADash(t *testing.T) {
	require.Equal(t, "Not recorded", view.AuditRow{}.SourceDetail())
	require.Equal(t, "web", view.AuditRow{Source: "web"}.SourceDetail())
}

func TestTheAuditScreensLinksCarryTheRestOfItsState(t *testing.T) {
	q := view.AuditQuery{Page: 2, Selected: "abc"}.Normalise()

	require.Equal(t, "/audit?entry=e1", view.AuditQuery{Page: 1}.EntryHref("e1"))
	require.Equal(t, "/audit?entry=e1&page=2", q.EntryHref("e1"))
	require.Equal(t, "/audit?page=2", q.CloseHref())
	require.Equal(t, "/audit", view.AuditQuery{Page: 1}.CloseHref())

	t.Run("the filter rides every link, and a bare id or unknown kind is dropped", func(t *testing.T) {
		f := view.AuditQuery{Page: 3, Filter: view.AuditFilter{SubjectKind: "version", SubjectID: "a/b@1.0.0"}}.Normalise()
		require.Equal(t, "/audit?page=2&subjectId=a%2Fb%401.0.0&subjectKind=version", f.PageHref(2))
		require.Equal(t, "/audit/export?subjectId=a%2Fb%401.0.0&subjectKind=version", f.ExportHref())
		require.Equal(t, "/audit/export", q.ExportHref())

		bare := view.AuditQuery{Filter: view.AuditFilter{SubjectID: "x", Namespace: "community"}}.Normalise()
		require.Equal(t, view.AuditFilter{Namespace: "community"}, bare.Filter)
		unknown := view.AuditQuery{Filter: view.AuditFilter{SubjectKind: "spaceship", SubjectID: "x"}}.Normalise()
		require.False(t, unknown.Filter.Active())
	})

	t.Run("an unbounded id from the url is not echoed back into every row's link", func(t *testing.T) {
		long := view.AuditQuery{Selected: strings.Repeat("a", 500)}.Normalise()
		require.Empty(t, long.Selected)
	})
}

func TestNeitherScreenCountsWhatItCouldNotRead(t *testing.T) {
	require.Equal(t, "0 findings", view.Scanner{}.Count())
	require.Empty(t, view.Scanner{GovernanceState: view.GovernanceState{Unavailable: true}}.Count())
	require.Empty(t, view.Scanner{GovernanceState: view.GovernanceState{Refused: true}}.Count())
	require.Empty(t, view.Scanner{GovernanceState: view.GovernanceState{SignedOut: true}}.Count())
	require.Equal(t, "1 finding", view.Scanner{Total: 1}.Count())

	require.Equal(t, "0 events", view.Audit{}.Count())
	require.Empty(t, view.Audit{GovernanceState: view.GovernanceState{Unavailable: true}}.Count())
	require.Equal(t, "1 event", view.Audit{Total: 1}.Count())
}

func TestEvidenceWithNoLineDoesNotRenderATrailingColon(t *testing.T) {
	require.Equal(t, "plugin.json", view.Evidence{Path: "plugin.json"}.Location())
	require.Equal(t, "scripts/digest.sh:41", view.Evidence{Path: "scripts/digest.sh", Line: 41}.Location())
}

func TestLapseWarnsWithinTheNoticeWindow(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	require.Equal(t, "expired", view.Lapse(now, now))
	require.Equal(t, "soon", view.Lapse(now.Add(7*24*time.Hour), now))
	require.Empty(t, view.Lapse(now.Add(8*24*time.Hour), now))
}
