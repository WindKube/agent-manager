package web_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The package detail screen's security section: a collapsible panel showing
// the latest version's scan result, its findings and any reviewer decision,
// collapsed by default (owner request). It reuses the Scanner screen's own
// renderers, so the tests here are about what THIS screen adds — the panel
// itself, its default-collapsed toggle and its four states — not a repeat of
// scanner escaping or check-matrix coverage.

// packageScanFixture answers PackageSource with one fixed package and
// PackageScanSource with whatever a test sets, so the panel renders in
// isolation from the rest of the detail screen's reads.
type packageScanFixture struct {
	pkg  view.Package
	scan hub.PackageScanDetail
	err  error
}

// Catalog is never exercised by these tests; it exists only because handler()
// requires a web.CatalogSource to route anything at all.
func (packageScanFixture) Catalog(_ context.Context, _ view.CatalogQuery) (view.CatalogPage, error) {
	return view.CatalogPage{}, nil
}

func (s packageScanFixture) Package(_ context.Context, _, _ string) (view.Package, error) {
	return s.pkg, nil
}

func (s packageScanFixture) PackageScan(_ context.Context, _, _ string) (hub.PackageScanDetail, error) {
	return s.scan, s.err
}

func testPackage() view.Package {
	return view.Package{ID: "example/thing", Name: "thing", Kind: view.KindSkill}
}

func TestPackageScanPanelIsCollapsedByDefaultAndCostsNoRoundTrip(t *testing.T) {
	source := packageScanFixture{pkg: testPackage(), scan: hub.PackageScanDetail{
		Scanned: true,
		Scan:    hub.Scan{PackVersion: "1.0.0+abc", StartedAt: time.Now(), Verdict: "flagged"},
		Findings: []hub.FindingDetail{{
			Finding: hub.Finding{ID: "f1", RuleID: "SH-NET-002", Severity: "high", State: "open",
				Title: "Undeclared network egress"},
		}},
	}}
	body := get(t, handler(t, source), "/packages/example/thing").Body.String()

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
	source := packageScanFixture{pkg: testPackage(), scan: hub.PackageScanDetail{
		Scanned: true,
		Scan:    hub.Scan{PackVersion: "1.0.0+abc", StartedAt: time.Now(), Verdict: "flagged"},
		Findings: []hub.FindingDetail{{
			Finding: hub.Finding{ID: "f1", RuleID: "SH-FS-007", Severity: "low", State: "approved",
				Title: "Filesystem write outside declared scope"},
			Override: &hub.Override{
				Reviewer: "reviewer@example.com", Note: "Scoped to the cache directory only.",
				ExpiresAt: &expires, DecidedAt: time.Now(),
			},
		}},
	}}
	body := get(t, handler(t, source), "/packages/example/thing").Body.String()

	require.Contains(t, body, "reviewer@example.com", "the reviewer is missing from the panel")
	require.Contains(t, body, "Scoped to the cache directory only.", "the reviewer's comment is missing")
	require.Contains(t, body, "Override on record")
}

func TestPackageScanTellsARejectedFindingApartFromAnAcceptedOne(t *testing.T) {
	source := packageScanFixture{pkg: testPackage(), scan: hub.PackageScanDetail{
		Scanned: true,
		Scan:    hub.Scan{PackVersion: "1.0.0+abc", StartedAt: time.Now(), Verdict: "rejected"},
		Findings: []hub.FindingDetail{{
			Finding: hub.Finding{ID: "f1", RuleID: "SH-INJ-011", Severity: "high", State: "rejected",
				Title: "Prompt injection pattern"},
		}},
	}}
	body := get(t, handler(t, source), "/packages/example/thing").Body.String()

	require.Contains(t, body, `id="scan-finding-rejected"`)
	require.NotContains(t, body, `id="finding-override"`,
		"a rejection writes no override row, so this panel must not invent one")
}

func TestPackageScanTellsItsFourStatesApart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source packageScanFixture
		want   string
	}{
		{"never scanned", packageScanFixture{pkg: testPackage()}, "scan-unscanned"},
		{"scanned clean, no findings", packageScanFixture{pkg: testPackage(),
			scan: hub.PackageScanDetail{Scanned: true, Scan: hub.Scan{Verdict: "clean"}}}, "scan-no-findings"},
		{"rejected version", packageScanFixture{pkg: testPackage(),
			scan: hub.PackageScanDetail{Rejected: true}}, "scan-rejected"},
		{"read failed", packageScanFixture{pkg: testPackage(), err: errors.New("boom")}, "scan-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := get(t, handler(t, tc.source), "/packages/example/thing").Body.String()
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

	source := packageScanFixture{pkg: testPackage(), scan: hub.PackageScanDetail{
		Scanned: true,
		Scan:    hub.Scan{PackVersion: "1.0.0+" + payload, StartedAt: time.Now(), Verdict: "flagged"},
		Checks:  []hub.Check{{ID: "shell-audit", Label: "Label " + payload, Result: "fail"}},
		Findings: []hub.FindingDetail{{
			Finding: hub.Finding{ID: "f1", RuleID: "SH-NET-002", Severity: "high", State: "open",
				Title: "Title " + payload},
			Explanation: "Detail " + payload,
			Evidence: []hub.Evidence{
				{Path: "scripts/" + payload + ".sh", Line: 41, Quote: payload, Role: "primary"},
			},
			Override: &hub.Override{Reviewer: "reviewer " + payload, Note: "note " + payload, DecidedAt: time.Now()},
		}},
	}}
	body := get(t, handler(t, source), "/packages/example/thing").Body.String()

	require.NotContains(t, body, payload, "the package screen rendered attacker-supplied markup unescaped")
	require.Truef(t, strings.Contains(body, "&lt;img src=x onerror="),
		"the payload did not render at all, so this test asserts nothing:\n%s", body)
}
