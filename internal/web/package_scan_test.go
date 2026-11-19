package web_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/fakeapi"
)

// The package detail screen's security section: a collapsible panel showing
// the latest version's scan result, its findings and any reviewer decision,
// collapsed by default (owner request). It reuses the Scanner screen's own
// renderers, so the tests here are about what THIS screen adds — the panel
// itself, its default-collapsed toggle and its four states — not a repeat of
// scanner escaping or check-matrix coverage.

const scanPackage = "example/adr-writer"

// scanServer is a server whose api answers scanPackage's scan with scan.
func scanServer(t *testing.T, scan apiclient.PackageScan) http.Handler {
	t.Helper()
	api, h := newServer(t)
	api.Data.Scans[scanPackage] = scan
	return h
}

func flaggedScan(verdict apiclient.FindingScanVerdict, findings ...apiclient.PackageScanFinding) apiclient.PackageScan {
	return apiclient.PackageScan{
		Scanned:  true,
		Version:  "1.0.0",
		Scan:     apiclient.FindingScan{PackVersion: "1.0.0+abc", StartedAt: time.Now(), Verdict: verdict},
		Checks:   []apiclient.FindingCheck{},
		Findings: findings,
	}
}

func scanFinding(ruleID, title string, severity apiclient.PackageScanFindingSeverity, state apiclient.PackageScanFindingState) apiclient.PackageScanFinding {
	return apiclient.PackageScanFinding{
		Id: uuid.New(), RuleId: ruleID, Title: title, Severity: severity, State: state,
		RaisedAt: time.Now(), Evidence: []apiclient.FindingEvidence{},
	}
}

func TestPackageScanPanelIsCollapsedByDefaultAndCostsNoRoundTrip(t *testing.T) {
	h := scanServer(t, flaggedScan(apiclient.FindingScanVerdictFlagged,
		scanFinding("SH-NET-002", "Undeclared network egress",
			apiclient.PackageScanFindingSeverityHigh, apiclient.PackageScanFindingStateOpen)))
	body := get(t, h, "/packages/"+scanPackage).Body.String()

	// Collapsed before the script runs: the same inline display:none idiom
	// the catalog's own overlays use (import.templ, catalog.templ), not a
	// state datastar has to reach first.
	require.Contains(t, body, `id="scan-panel-body" style="display:none" data-show="$_scanOpen"`)
	require.Contains(t, body, `data-signals="{_scanOpen: false}"`)
	require.Contains(t, body, `data-on:click="$_scanOpen = !$_scanOpen"`)

	// The finding is already in the document — expanding the section is a
	// local signal flip, not a fetch. If this were an on-demand read the
	// content would be absent until a click, which is exactly what the two
	// lines above rule out.
	require.Contains(t, body, "SH-NET-002", "the finding did not render at all, so this proves nothing")
	require.Contains(t, body, "Undeclared network egress")

	// No request is wired to the toggle: neither datastar action appears
	// anywhere near it, so R7's budget (internal/web/web_test.go,
	// import_test.go) gains no new counted round trip from this section.
	require.NotContains(t, body, "@get(")
	require.NotContains(t, body, "@post(")
}

func TestPackageScanShowsTheApprovalAndTheReviewersComment(t *testing.T) {
	expires := time.Now().Add(48 * time.Hour)
	note := "Scoped to the cache directory only."
	finding := scanFinding("SH-FS-007", "Filesystem write outside declared scope",
		apiclient.PackageScanFindingSeverityLow, apiclient.PackageScanFindingStateApproved)
	finding.Override = &apiclient.FindingOverride{
		Reviewer: "reviewer@example.com", Note: &note, ExpiresAt: &expires, DecidedAt: time.Now(),
	}
	h := scanServer(t, flaggedScan(apiclient.FindingScanVerdictFlagged, finding))
	body := get(t, h, "/packages/"+scanPackage).Body.String()

	require.Contains(t, body, "reviewer@example.com", "the reviewer is missing from the panel")
	require.Contains(t, body, "Scoped to the cache directory only.", "the reviewer's comment is missing")
	require.Contains(t, body, "Override on record")
}

func TestPackageScanTellsARejectedFindingApartFromAnAcceptedOne(t *testing.T) {
	h := scanServer(t, flaggedScan(apiclient.FindingScanVerdictRejected,
		scanFinding("SH-INJ-011", "Prompt injection pattern",
			apiclient.PackageScanFindingSeverityHigh, apiclient.PackageScanFindingStateRejected)))
	body := get(t, h, "/packages/"+scanPackage).Body.String()

	require.Contains(t, body, `id="scan-finding-rejected"`)
	require.NotContains(t, body, `id="finding-override"`,
		"a rejection writes no override row, so this panel must not invent one")
}

func TestPackageScanTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(api *fakeapi.API)
		want  string
	}{
		{"never scanned", func(api *fakeapi.API) {
			api.Data.Scans[scanPackage] = apiclient.PackageScan{Version: "1.0.0"}
		}, "scan-unscanned"},
		{"scanned clean, no findings", func(api *fakeapi.API) {
			api.Data.Scans[scanPackage] = flaggedScan(apiclient.FindingScanVerdictClean)
		}, "scan-no-findings"},
		{"rejected version", func(api *fakeapi.API) {
			api.Fail("getPackageScan", http.StatusForbidden)
		}, "scan-rejected"},
		{"read failed", func(api *fakeapi.API) {
			api.Fail("getPackageScan", http.StatusServiceUnavailable)
		}, "scan-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, h := newServer(t)
			tc.setup(api)
			body := get(t, h, "/packages/"+scanPackage).Body.String()
			require.Contains(t, body, `id="`+tc.want+`"`)

			for _, other := range []string{"scan-unscanned", "scan-no-findings", "scan-rejected", "scan-unavailable"} {
				if other == tc.want {
					continue
				}
				require.NotContains(t, body, `id="`+other+`"`)
			}
		})
	}
}

// TestPackageScanIsEscapedWhereverItIsRendered is FR-055/FR-127 on the one
// panel this screen adds that renders bundle-adjacent and reviewer-supplied
// text a second time, outside the Scanner screen.
func TestPackageScanIsEscapedWhereverItIsRendered(t *testing.T) {
	const payload = `<img src=x onerror="alert(1)">`

	detail, quote, note := "Detail "+payload, payload, "note "+payload
	line := int64(41)
	finding := scanFinding("SH-NET-002", "Title "+payload,
		apiclient.PackageScanFindingSeverityHigh, apiclient.PackageScanFindingStateOpen)
	finding.Detail = &detail
	finding.Evidence = []apiclient.FindingEvidence{{
		Path: "scripts/" + payload + ".sh", Line: &line, Quote: &quote, Role: apiclient.Primary,
	}}
	finding.Override = &apiclient.FindingOverride{Reviewer: "reviewer " + payload, Note: &note, DecidedAt: time.Now()}
	scan := flaggedScan(apiclient.FindingScanVerdictFlagged, finding)
	scan.Scan.PackVersion = "1.0.0+" + payload
	scan.Checks = []apiclient.FindingCheck{{CheckId: "shell-audit", Label: "Label " + payload, Result: apiclient.Fail}}
	body := get(t, scanServer(t, scan), "/packages/"+scanPackage).Body.String()

	require.NotContains(t, body, payload, "the package screen rendered attacker-supplied markup unescaped")
	require.Truef(t, strings.Contains(body, "&lt;img src=x onerror="),
		"the payload did not render at all, so this test asserts nothing:\n%s", body)
}

func TestThePackagePageLinksToItsAuditHistory(t *testing.T) {
	_, h := newServer(t)
	body := get(t, h, "/packages/"+scanPackage).Body.String()

	require.Contains(t, body, `<a id="package-history" href="/audit?subjectId=example%2Fadr-writer&amp;subjectKind=package">History</a>`)
}
