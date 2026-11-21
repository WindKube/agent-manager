package web_test

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/hub"
)

const govFindingID = "6f1c0a4e-9f4b-4f2a-9c1d-2f9b6a7e4d11"

func govFinding() apiclient.FindingSummary {
	return apiclient.FindingSummary{
		Id: uuid.MustParse(govFindingID), RuleId: "SH-NET-002",
		Severity: apiclient.FindingSummarySeverityHigh, State: apiclient.FindingSummaryStateOpen,
		Title:     "Script contacts a host the package does not declare",
		PackageId: "community/slack-digest", Version: "0.5.1",
		Verdict: apiclient.FindingSummaryVerdictFlagged, RaisedAt: time.Now().Add(-time.Hour),
	}
}

func govDetail(f apiclient.FindingSummary) apiclient.FindingDetail {
	return apiclient.FindingDetail{
		Id: f.Id, RuleId: f.RuleId, Detail: f.Detail, Title: f.Title,
		Severity: apiclient.FindingDetailSeverity(f.Severity), State: apiclient.FindingDetailState(f.State),
		Verdict:   apiclient.FindingDetailVerdict(f.Verdict),
		PackageId: f.PackageId, Version: f.Version, RaisedAt: f.RaisedAt,
	}
}

func oneFinding(api *fakeapi.API, f apiclient.FindingSummary, detail apiclient.FindingDetail) {
	api.Data.Findings = []apiclient.FindingSummary{f}
	api.Data.FindingDetails = map[string]apiclient.FindingDetail{f.Id.String(): detail}
}

const auditID = "a0000000-0000-4000-8000-0000000000a1"

func auditEntry(actor string, kind apiclient.AuditEntryKind, text, source string) apiclient.AuditEntry {
	entry := apiclient.AuditEntry{
		Id: uuid.MustParse(auditID), OccurredAt: time.Now(), Actor: actor,
		ActorKind: apiclient.AuditEntryActorKindIdentity, Kind: kind, Text: text,
	}
	if source != "" {
		entry.Source = &source
	}
	return entry
}

func ptrTo[T any](v T) *T { return &v }

// Only the passes distinguish "no finding" from "no check ran".
func TestTheCheckMatrixShowsEveryCheckThatRanAndNotOnlyTheFailures(t *testing.T) {
	api, h := newServer(t)
	detail := govDetail(govFinding())
	detail.Checks = []apiclient.FindingCheck{
		{CheckId: "manifest-schema", Label: "Manifest schema", Result: apiclient.Pass},
		{CheckId: "network-allowlist", Label: "Network allowlist", Result: apiclient.Fail},
		{CheckId: "shell-audit", Label: "Shell command audit", Result: apiclient.Warn, WarnCount: 2},
		{CheckId: "secret-exfiltration", Label: "Secret exfiltration", Result: apiclient.Pass},
	}
	oneFinding(api, govFinding(), detail)
	body := get(t, h, "/scanner").Body.String()

	for _, label := range []string{"Manifest schema", "Network allowlist", "Shell command audit", "Secret exfiltration"} {
		require.Containsf(t, body, label, "the matrix dropped %q, so a check that ran is invisible", label)
	}
	require.Contains(t, body, "am-chk-mark-ok", "no pass is rendered")
	require.Contains(t, body, "am-chk-mark-dan")

	// The warn count is files the check could not read, not a number of problems.
	require.Contains(t, body, "2 files this check could not read")
	require.NotContains(t, body, "2 issues")
}

// A title tooltip for mouse users, and the same words via aria-describedby for
// screen readers.
func TestACheckAndARuleIdExplainThemselvesOnHoverAndWithoutOne(t *testing.T) {
	api, h := newServer(t)
	finding := govFinding()
	finding.Detail = ptrTo("Why SH-NET-002 fires, for the list row.")
	pane := govDetail(finding)
	pane.Detail = ptrTo("Why SH-NET-002 fires, for the pane.")
	pane.Checks = []apiclient.FindingCheck{{
		CheckId: "network-allowlist", Label: "Network allowlist",
		Explain: "What the network allowlist check looks for.", Result: apiclient.Fail,
	}}
	oneFinding(api, finding, pane)
	body := get(t, h, "/scanner").Body.String()

	require.Contains(t, body, `title="Why SH-NET-002 fires, for the list row."`)
	require.Contains(t, body, "Why SH-NET-002 fires, for the list row.")

	// The pane uses the detail call's explanation, not the list row's.
	require.Contains(t, body, `title="Why SH-NET-002 fires, for the pane."`)

	require.Contains(t, body, `title="What the network allowlist check looks for."`)
	require.Contains(t, body, "What the network allowlist check looks for.")

	for _, match := range regexp.MustCompile(`aria-describedby="([^"]+)"`).FindAllStringSubmatch(body, -1) {
		require.Containsf(t, body, `id="`+match[1]+`"`, "aria-describedby names %s, which nothing on the page carries as an id", match[1])
	}
}

func TestScanEvidenceIsEscapedWhereverItIsRendered(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	api, h := newServer(t)
	hostile := govFinding()
	hostile.Title = "Title " + payload
	hostile.PackageId = "community/x"
	hostile.Version = "1.0.0 " + payload
	pane := govDetail(hostile)
	pane.Detail = ptrTo("Detail " + payload)
	pane.Evidence = []apiclient.FindingEvidence{
		{Path: "scripts/" + payload + ".sh", Line: ptrTo(int64(41)), Quote: ptrTo(payload), Role: apiclient.Primary},
		{Path: "second/" + payload, Quote: ptrTo("supporting " + payload), Role: apiclient.Supporting},
	}
	pane.Checks = []apiclient.FindingCheck{{CheckId: "shell-audit", Label: "Label " + payload, Result: apiclient.Fail}}
	pane.Scan = apiclient.FindingScan{PackVersion: "2026.08.31+" + payload}
	pane.Override = &apiclient.FindingOverride{
		Reviewer: "reviewer " + payload, Note: ptrTo("note " + payload), DecidedAt: time.Now(),
	}
	oneFinding(api, hostile, pane)
	api.Data.Audit = []apiclient.AuditEntry{
		auditEntry("actor "+payload, apiclient.AuditEntryKindScan, "text "+payload, "src "+payload),
	}

	for _, target := range []string{"/scanner", "/audit"} {
		body := get(t, h, target).Body.String()
		require.NotContainsf(t, body, payload, "%s rendered attacker-supplied markup unescaped", target)
		require.Containsf(t, body, "&lt;img src=x onerror=", "%s did not render the value at all, "+
			"so this test is asserting nothing", target)
	}
}

func TestTheScannerTellsItsFourEmptyStatesApart(t *testing.T) {
	for _, state := range []struct {
		name   string
		failAs int
		id     string
		status int
	}{
		{name: "genuinely empty", id: `id="scanner-empty"`, status: http.StatusOK},
		{name: "refused by role", failAs: http.StatusForbidden, id: `id="scanner-refused"`, status: http.StatusForbidden},
		{
			name: "the api did not answer", failAs: http.StatusServiceUnavailable,
			id: `id="scanner-unavailable"`, status: http.StatusBadGateway,
		},
		{name: "no usable session", failAs: http.StatusUnauthorized, id: `id="scanner-signed-out"`, status: http.StatusOK},
	} {
		t.Run(state.name, func(t *testing.T) {
			api, h := newServer(t)
			api.Data.Findings = nil
			api.Data.ScannerSummary = apiclient.ScannerSummary{}
			if state.failAs != 0 {
				api.Fail("scannerSummary", state.failAs)
			}
			rec := get(t, h, "/scanner")
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

func TestTheEmptyScannerSaysWhatWouldBeThereAndHowToGetIt(t *testing.T) {
	api, h := newServer(t)
	api.Data.Findings = nil
	api.Data.ScannerSummary = apiclient.ScannerSummary{}
	api.Data.Audit = nil
	body := get(t, h, "/scanner").Body.String()
	require.Contains(t, body, "register a package")
	require.Contains(t, body, "rule pack")

	audit := get(t, h, "/audit").Body.String()
	require.Contains(t, audit, `id="audit-empty"`)
	require.Contains(t, audit, "state-changing action")
}

func TestAnActionAViewerMayNotTakeIsDisabledWithItsReason(t *testing.T) {
	server := func(t *testing.T) (*fakeapi.API, http.Handler) {
		api, h := newServer(t)
		oneFinding(api, govFinding(), govDetail(govFinding()))
		return api, h
	}

	t.Run("a role that cannot decide gets the controls disabled and told why", func(t *testing.T) {
		api, h := server(t)
		api.Data.As(apiclient.ViewerRoleReadOnly)
		body := get(t, h, "/scanner").Body.String()

		require.Contains(t, body, `id="review-not-permitted"`)
		require.Contains(t, body, "scanner reviewer")
		require.Contains(t, body, "disabled")
		require.NotContains(t, body, `class="am-review"`)
	})

	t.Run("a reviewer gets the real controls", func(t *testing.T) {
		_, h := server(t)
		body := get(t, h, "/scanner").Body.String()

		require.Contains(t, body, `class="am-review"`)
		require.Contains(t, body, "/scanner/findings/"+govFindingID+"/accept")
		require.Contains(t, body, "/scanner/findings/"+govFindingID+"/reject")
		require.NotContains(t, body, `id="review-not-permitted"`)
	})
}

// Disabling a control is presentation; a post can still arrive from an old page
// or a second tab.
func TestADecisionFromAnIdentityWithoutTheRoleReachesNoApi(t *testing.T) {
	api, h := newServer(t)
	api.Data.As(apiclient.ViewerRoleReadOnly)

	rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"looks fine"}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "decided=refused")
	require.Empty(t, api.Calls("acceptFinding"), "the api was asked to record a decision this role may not take")
	require.Empty(t, api.Calls("rejectFinding"))
}

// Mirrors the api's validation to save a round trip; the api remains the authority.
func TestAnApproveWithNoNoteNeverReachesTheApi(t *testing.T) {
	api, h := newServer(t)

	rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"   "}})

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "decided=note-required")
	require.Empty(t, api.Calls("acceptFinding"))

	t.Run("but a rejection may carry none", func(t *testing.T) {
		rejected := post(t, h, "/scanner/findings/"+govFindingID+"/reject", url.Values{})
		require.Equal(t, http.StatusSeeOther, rejected.Code)
		calls := api.Calls("rejectFinding")
		require.Len(t, calls, 1)
		require.Equal(t, "/v1/findings/"+govFindingID+"/reject", calls[0].Path)
	})
}

// A default lifetime would be a policy decision taken by a form field nobody filled in.
func TestAnAcceptSendsNoExpiryUnlessTheReviewerStatedOne(t *testing.T) {
	api, h := newServer(t)
	accepted := func() []apiclient.FindingApproval {
		var out []apiclient.FindingApproval
		for _, call := range api.Calls("acceptFinding") {
			require.Equal(t, "/v1/findings/"+govFindingID+"/accept", call.Path)
			var body apiclient.FindingApproval
			call.Decode(t, &body)
			out = append(out, body)
		}
		return out
	}

	post(t, h, "/scanner/findings/"+govFindingID+"/accept", url.Values{"note": {"accepted"}})
	require.Equal(t, []apiclient.FindingApproval{{Note: "accepted"}}, accepted())

	post(t, h, "/scanner/findings/"+govFindingID+"/accept",
		url.Values{"note": {"accepted"}, "expires": {"30"}})
	require.Equal(t, []apiclient.FindingApproval{
		{Note: "accepted"}, {Note: "accepted", ExpiresInDays: ptrTo(int64(30))},
	}, accepted())

	t.Run("an expiry outside the api's range is refused here rather than there", func(t *testing.T) {
		rec := post(t, h, "/scanner/findings/"+govFindingID+"/accept",
			url.Values{"note": {"accepted"}, "expires": {"9999"}})
		require.Contains(t, rec.Header().Get("Location"), "decided=bad-expiry")
		require.Len(t, accepted(), 2)
	})
}

// An override is an accepted risk; the version stays flagged.
func TestApprovingNeverClaimsTheVersionBecameClean(t *testing.T) {
	api, h := newServer(t)
	approved := govFinding()
	approved.State = apiclient.FindingSummaryStateApproved
	approved.Verdict = apiclient.FindingSummaryVerdictFlagged
	detail := govDetail(approved)
	detail.Override = &apiclient.FindingOverride{
		Reviewer: "a-reviewer", Note: ptrTo("accepted for one quarter"), DecidedAt: time.Now(),
	}
	oneFinding(api, approved, detail)
	body := get(t, h, "/scanner?finding="+govFindingID+"&decided=approved").Body.String()

	require.Contains(t, body, "Flagged", "the version's verdict is gone from the screen")
	require.Contains(t, body, "not a new verdict")
	require.Contains(t, body, `id="finding-override"`)
	require.NotContains(t, body, "Clean")
}

func TestAFindingWithNoRecordedEvidenceSaysSoRatherThanRenderingAnEmptyPanel(t *testing.T) {
	api, h := newServer(t)
	oneFinding(api, govFinding(), govDetail(govFinding()))
	body := get(t, h, "/scanner").Body.String()

	require.Contains(t, body, `id="finding-no-evidence"`)
	require.Contains(t, body, `id="finding-no-checks"`)
}

// The hub promises nothing about evidence order, so position must not decide the headline.
func TestThePrimaryEvidenceIsFoundByItsRoleAndNotByItsPosition(t *testing.T) {
	api, h := newServer(t)
	pane := govDetail(govFinding())
	pane.Evidence = []apiclient.FindingEvidence{
		{Path: "supporting.sh", Line: ptrTo(int64(9)), Quote: ptrTo("second"), Role: apiclient.Supporting},
		{Path: "headline.sh", Line: ptrTo(int64(41)), Quote: ptrTo("first"), Role: apiclient.Primary},
	}
	oneFinding(api, govFinding(), pane)
	body := get(t, h, "/scanner").Body.String()

	headline := strings.Index(body, "headline.sh:41")
	supporting := strings.Index(body, "supporting.sh:9")
	require.Positive(t, headline)
	require.Positive(t, supporting)
	require.Less(t, headline, supporting, "the pane put a supporting location in the headline slot")
	require.Contains(t, body, `id="finding-evidence"`)
}

// A missing finding is the pane's state, not the screen's: the list still renders.
func TestAFindingIdThatNamesNothingIsItsOwnState(t *testing.T) {
	api, h := newServer(t)
	oneFinding(api, govFinding(), govDetail(govFinding()))
	rec := get(t, h, "/scanner?finding=not-a-uuid")

	require.Equal(t, http.StatusNotFound, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `id="scanner-missing"`)
	require.Contains(t, body, "Script contacts a host", "the findings list should still have rendered")
}

// System actors like `scanner` must not read as usernames.
func TestTheAuditScreenNeverAttributesASystemRowToAPerson(t *testing.T) {
	api, h := newServer(t)
	system := auditEntry("scanner", apiclient.AuditEntryKindScan, "flagged x@1", "system")
	system.ActorKind = apiclient.AuditEntryActorKindSystem
	person := auditEntry("an-operator", apiclient.AuditEntryKindApprove, "override granted", "web")
	person.Id = uuid.MustParse("a0000000-0000-4000-8000-0000000000a2")
	api.Data.Audit = []apiclient.AuditEntry{system, person}
	body := get(t, h, "/audit").Body.String()

	require.Equal(t, 1, strings.Count(body, `class="am-audit-actor-kind"`),
		"exactly one of these two rows has a machine behind it")
	require.Contains(t, body, "am-pill-warn")
	require.Contains(t, body, "am-pill-ok")
}

func TestEveryAuditRowIsAKeyboardReachableLinkToItsOwnDetail(t *testing.T) {
	api, h := newServer(t)
	api.Data.Audit = []apiclient.AuditEntry{auditEntry("an-operator", apiclient.AuditEntryKindApprove, "override granted", "web")}
	body := get(t, h, "/audit").Body.String()

	require.Contains(t, body, `<a class="am-audit-row" href="/audit?entry=`+auditID+`">`,
		"the row is not a real, keyboard-focusable link to its own detail")
}

// The row clips its message with an ellipsis; the panel must show it in full.
func TestClickingAnAuditRowOpensAPanelWithTheWholeUntruncatedMessage(t *testing.T) {
	message := `failed to fetch community/skills@1.2.3 from git https://github.com/mattpocock/skills@v1.2.3 ` +
		`(skills/engineering/code-review): archive member rejected: symlink (member "mattpocock-skills-835450e/AGENTS.md")`
	api, h := newServer(t)
	entry := auditEntry("fetcher", apiclient.AuditEntryKindFetch, message, "")
	entry.ActorKind = apiclient.AuditEntryActorKindSystem
	api.Data.Audit = []apiclient.AuditEntry{entry}
	body := get(t, h, "/audit?entry="+auditID).Body.String()

	require.Contains(t, body, `class="am-audit-panel"`, "no detail panel was rendered for the selected row")
	require.Contains(t, body, `class="am-audit-detail-message"`)
	// The escaped quote proves templ escaping, not a raw (stored-XSS) copy.
	require.Contains(t, body, "archive member rejected: symlink (member &#34;mattpocock-skills-835450e/AGENTS.md&#34;)")
	require.Contains(t, body, "https://github.com/mattpocock/skills@v1.2.3")
	// The id the row itself never shows.
	require.Contains(t, body, auditID)
}

func TestAnAuditEntryNotOnThePageIsNamedMissingRatherThanRenderingNothing(t *testing.T) {
	api, h := newServer(t)
	api.Data.Audit = []apiclient.AuditEntry{auditEntry("an-operator", apiclient.AuditEntryKindApprove, "override granted", "")}
	body := get(t, h, "/audit?entry=does-not-exist").Body.String()

	require.Contains(t, body, `id="audit-entry-missing"`)
}

func TestTheAuditPanelSaysSoRatherThanLeavingAnEmptySourceCell(t *testing.T) {
	api, h := newServer(t)
	api.Data.Audit = []apiclient.AuditEntry{auditEntry("an-operator", apiclient.AuditEntryKindApprove, "override granted", "")}
	body := get(t, h, "/audit?entry="+auditID).Body.String()

	require.Contains(t, body, "Not recorded")
}

// A streamed response cannot change its status once started, so a truncated
// export arrives as a 200 missing its sentinel line and can only be logged.
func TestTheAuditExportStreamsThroughAndItsSentinelIsChecked(t *testing.T) {
	complete := "{\"id\":\"a1\"}\n{\"complete\":true,\"rows\":1}\n"

	t.Run("a complete export is passed through byte for byte", func(t *testing.T) {
		h, logged := exportServer(t, complete)

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
		h, logged := exportServer(t, "{\"id\":\"a1\"}\n")

		rec := get(t, h, "/audit/export")

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, logged.String(), "completeness sentinel")
	})

	t.Run("a row quoting the sentinel's own bytes is not mistaken for it", func(t *testing.T) {
		h, logged := exportServer(t, "{\"id\":\"a1\",\"text\":\"{\\\"complete\\\":true}\"}\n")

		get(t, h, "/audit/export")
		require.Contains(t, logged.String(), "completeness sentinel",
			"a text match on the sentinel's bytes would have called this export complete")
	})
}

// exportServer is newServer with its log captured.
func exportServer(t *testing.T, export string) (http.Handler, *bytes.Buffer) {
	t.Helper()
	api := fakeapi.New(t)
	api.Data.AuditExport = export
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	var logged bytes.Buffer
	return web.New(web.Deps{Hub: client, Log: zerolog.New(&logged)}, web.Options{}).Handler(), &logged
}

func TestTheSidebarCountsAreTheApisAndAreAbsentRatherThanZero(t *testing.T) {
	t.Run("the counts on the page are the ones the api answered", func(t *testing.T) {
		api, h := newServer(t)
		api.Data.Badges = apiclient.Badges{Packages: 7, Profiles: 3, OpenFindings: 11}
		body := get(t, h, "/catalog").Body.String()

		require.Contains(t, body, `<span class="am-nav-badge">7</span>`)
		require.Contains(t, body, `<span class="am-nav-badge">3</span>`)
		require.Contains(t, body, `<span class="am-nav-badge am-nav-badge-alert">11</span>`)
		for _, stale := range []string{">10<", ">4<"} {
			require.NotContainsf(t, body, `am-nav-badge">`+strings.Trim(stale, "<>"),
				"the design's seed value %q is still on the page", stale)
		}
	})

	t.Run("nothing to count renders no badge, not a zero", func(t *testing.T) {
		api, h := newServer(t)
		api.Data.Badges = apiclient.Badges{Packages: 2}
		body := get(t, h, "/catalog").Body.String()

		require.Contains(t, body, `<span class="am-nav-badge">2</span>`)
		require.NotContains(t, body, `>0</span>`, "a zero count was rendered as a badge")
	})

	t.Run("counts that could not be read render no badges at all", func(t *testing.T) {
		// Not zeroes: "0 packages" beside a full catalog would be a false claim.
		api, h := newServer(t)
		api.Fail("getBadges", http.StatusServiceUnavailable)
		body := get(t, h, "/catalog").Body.String()
		require.NotContains(t, body, "am-nav-badge")
	})
}

func TestNoRouteFromTheSidebarSaysItIsUnfinished(t *testing.T) {
	_, h := newServer(t)

	for _, target := range []string{"/scanner", "/audit"} {
		rec := get(t, h, target)
		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.NotContainsf(t, body, "am-placeholder", "%s still renders the placeholder card", target)
		require.NotContainsf(t, body, "not built yet", "%s still says it is unfinished", target)
	}
}

func TestFilteringAndPagingKeepTheRestOfTheScreensState(t *testing.T) {
	api, h := newServer(t)
	oneFinding(api, govFinding(), govDetail(govFinding()))
	body := get(t, h, "/scanner?state=open").Body.String()

	require.Contains(t, body, `href="/scanner?finding=`+govFindingID+`&amp;state=open"`,
		"selecting a finding dropped the filter")
	require.Contains(t, body, `<a class="am-chip am-chip-on" href="/scanner?state=open"`)
}

// The package page's History link lands here.
func TestTheAuditScreenHonoursASubjectFilter(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/audit?subjectKind=package&subjectId=community/slack-digest").Body.String()

	require.Contains(t, body, `id="audit-filter"`)
	require.Contains(t, body, "package community/slack-digest")
	require.Contains(t, body, `<a class="am-chip" href="/audit">Clear filter</a>`)
	require.Contains(t, body, "flagged community/slack-digest@0.5.1")
	require.NotContains(t, body, "stored example/terraform-module-review@2.4.1",
		"a row about another package leaked through the filter")
	require.Contains(t, body, "1 event")
	require.Contains(t, body, `href="/audit/export?subjectId=community%2Fslack-digest&amp;subjectKind=package"`,
		"the export must be the filtered scope, not the whole log")
	require.Contains(t, body, "entry=a0000000-0000-4000-8000-000000000002&amp;subjectId=community%2Fslack-digest&amp;subjectKind=package",
		"opening a row must not drop the filter")
}

func TestTheUnfilteredAuditScreenOffersNoFilterChip(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/audit?subjectKind=spaceship&subjectId=x").Body.String()

	require.NotContains(t, body, `id="audit-filter"`, "an unknown subject kind is dropped, not sent on")
	require.Contains(t, body, "stored example/terraform-module-review@2.4.1")
}

func TestAnAuditEntryAboutAVersionLinksToItsPackage(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/audit?entry=a0000000-0000-4000-8000-000000000002").Body.String()

	require.Contains(t, body, "version community/slack-digest@0.5.1")
	require.Contains(t, body, `<a id="audit-entry-package" href="/packages/community/slack-digest">`)

	login := get(t, h, "/audit?entry=a0000000-0000-4000-8000-000000000007").Body.String()
	require.Contains(t, login, "device d0000000-0000-4000-8000-000000000001")
	require.NotContains(t, login, `id="audit-entry-package"`, "a row about a device has no package to open")
}

func TestTheAuditExportForwardsTheFilter(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/audit/export?subjectKind=package&subjectId=community/slack-digest").Body.String()

	lines := strings.Split(strings.TrimSpace(body), "\n")
	require.Len(t, lines, 2, "one matching row and the completeness sentinel")
	require.Contains(t, lines[0], `"subjectId":"community/slack-digest@0.5.1"`)
	require.Contains(t, lines[1], `"complete":true`)
}

func TestAWaiverCloseToItsExpiryOrPastItSaysSo(t *testing.T) {
	for _, tc := range []struct {
		in       time.Duration
		want     string
		wantPill bool
	}{
		{in: 3 * 24 * time.Hour, want: "waiver expires soon", wantPill: true},
		{in: -time.Hour, want: "waiver expired", wantPill: true},
		{in: 40 * 24 * time.Hour},
	} {
		api, h := newServer(t)
		approved := govFinding()
		approved.State = apiclient.FindingSummaryStateApproved
		detail := govDetail(approved)
		detail.Override = &apiclient.FindingOverride{
			Reviewer: "a-reviewer", Note: ptrTo("accepted"), DecidedAt: time.Now(), ExpiresAt: ptrTo(time.Now().Add(tc.in)),
		}
		oneFinding(api, approved, detail)
		body := get(t, h, "/scanner?finding="+govFindingID).Body.String()

		if !tc.wantPill {
			require.NotContains(t, body, `id="finding-override-lapse"`)
			continue
		}
		require.Contains(t, body, `id="finding-override-lapse"`)
		require.Contains(t, body, tc.want)
	}
}
