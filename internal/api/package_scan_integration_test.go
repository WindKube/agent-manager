//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// GET /v1/packages/{namespace}/{name}/scan — the package detail screen's
// security section, read against a real Postgres. It is the same rows
// /v1/findings and /v1/findings/{id} read (queries/package_scan.go mirrors
// findings.go's own SQL), so what is asserted here is the part a
// handler-shaped test with a fake store cannot see: that the SUPERSEDED
// version's finding never leaks in through the wrong join, that a clean
// scan with no check matrix answers with an empty list rather than an
// error, that an override's reviewer and note actually come back, and that
// a rejected version is refused here exactly as getBundle refuses it.

func packageScan(t *testing.T, handler http.Handler, path string) contract.PackageScan {
	t.Helper()
	return getJSON[contract.PackageScan](t, handler, kw.token, path)
}

func TestPackageScanCarriesTheFullMatrixAndOnlyTheLatestVersionsFinding(t *testing.T) {
	fixture := seedGovernance(t)
	handler := liveHandler(t)

	scan := packageScan(t, handler, "/v1/packages/gov/risky-digest/scan")

	require.True(t, scan.Scanned)
	require.Equal(t, "1.0.0", scan.Version)
	require.Len(t, scan.Checks, 5, "the check matrix must carry every check, passes included")

	require.Len(t, scan.Findings, 1, "the superseded version's finding must not leak into the latest version's scan")
	require.Equal(t, fixture.openFinding.String(), scan.Findings[0].ID)
	require.Equal(t, "GOV-NET-001", scan.Findings[0].RuleID)
	require.Len(t, scan.Findings[0].Evidence, 3, "cause and both consequences must all come back")
	require.Nil(t, scan.Findings[0].Override)
}

func TestPackageScanAnswersAnEmptyCheckListRatherThanAnErrorWhenNoneWereRecorded(t *testing.T) {
	seedGovernance(t)
	handler := liveHandler(t)

	scan := packageScan(t, handler, "/v1/packages/gov/tidy-report/scan")

	require.True(t, scan.Scanned)
	require.NotNil(t, scan.Checks)
	require.Empty(t, scan.Checks, "this scan recorded no matrix, which is not the same as it being unreadable")
}

func TestPackageScanNamesTheReviewerAndTheirNoteOnAnApprovedFinding(t *testing.T) {
	seedGovernance(t)
	handler := liveHandler(t)

	scan := packageScan(t, handler, "/v1/packages/gov/tidy-report/scan")

	require.Len(t, scan.Findings, 1)
	require.Equal(t, "GOV-FS-007", scan.Findings[0].RuleID)
	require.Equal(t, "approved", scan.Findings[0].State)
	require.NotNil(t, scan.Findings[0].Override, "an accepted finding must carry its override")
	require.Equal(t, "Report output is redirected by the caller.", scan.Findings[0].Override.Note)
	require.NotEmpty(t, scan.Findings[0].Override.Reviewer)
}

// TestPackageScanTellsNeverScannedApartFromScannedClean is FR-025's other
// half: designPackages seeds ten packages with no scan row at all, and the
// screen's "not scanned yet" state must not be confused with "scanned, no
// findings" — the two answer the same shape (Scanned/Checks/Findings) but
// the boolean has to be the only thing telling them apart.
func TestPackageScanTellsNeverScannedApartFromScannedClean(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	scan := packageScan(t, handler, "/v1/packages/community/release-toolkit/scan")

	require.False(t, scan.Scanned)
	require.Empty(t, scan.Checks)
	require.Empty(t, scan.Findings)
}

// TestPackageScanRefusesARejectedVersionsScan is FR-029 at this door: a
// rejected version's scan detail is refused exactly as getBundle refuses
// its bytes and the files operations refuse its tree.
func TestPackageScanRefusesARejectedVersionsScan(t *testing.T) {
	seedPackageWithBundle(t, "pkgscantest", "rejected-latest", models.VerdictRejected,
		"skills/pkgscantest/rejected-latest/1.0.0/bundle.tar.zst")
	handler := liveHandler(t)

	rec := request(t, handler, http.MethodGet, "/v1/packages/pkgscantest/rejected-latest/scan", kw.token, "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}

func TestPackageScanOfAnUnknownPackageIsAFourOhFour(t *testing.T) {
	handler := liveHandler(t)

	rec := request(t, handler, http.MethodGet, "/v1/packages/no-such-namespace/no-such-package/scan", kw.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	var body contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
}
