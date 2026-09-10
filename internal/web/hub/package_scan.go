package hub

import (
	"context"
	"fmt"
	"net/http"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The package detail screen's security section (US3 extension): the latest
// visible version's scan, its findings and any reviewer decision. It reuses
// the Scanner screen's own Scan, Check and FindingDetail shapes
// (governance.go) rather than a second copy of them, so the package screen
// and the Scanner screen cannot render two different ideas of a finding.

// PackageScanDetail is GET /v1/packages/{namespace}/{name}/scan, decoded.
type PackageScanDetail struct {
	// Scanned distinguishes a version scanned clean from one never scanned,
	// exactly as Package's own Capabilities.Scanned does: both produce an
	// empty Findings slice.
	Scanned bool
	// Rejected mirrors FilesUnavailable/FilesRejected's own split (US3/US5):
	// a rejected version's scan detail is refused, which is not a read
	// failure and must not be reported as one.
	Scan     Scan
	Checks   []Check
	Findings []FindingDetail
	Rejected bool
}

// PackageScan reads GET /v1/packages/{namespace}/{name}/scan. A 404 becomes
// view.ErrNotFound, the same answer Package gives for a package this
// identity may not read.
func (c *Client) PackageScan(ctx context.Context, namespace, name string) (PackageScanDetail, error) {
	resp, err := c.api.GetPackageScanWithResponse(ctx, namespace, name)
	if err != nil {
		return PackageScanDetail{}, fmt.Errorf("read the scan for %s/%s: %w", namespace, name, err)
	}
	switch {
	case resp.JSON200 != nil:
		return packageScanDetail(resp.JSON200, namespace, name), nil
	case resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusForbidden:
		return PackageScanDetail{Rejected: true}, nil
	case resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound:
		return PackageScanDetail{}, view.ErrNotFound
	default:
		return PackageScanDetail{}, statusError(resp.HTTPResponse, resp.Body)
	}
}

func packageScanDetail(body *apiclient.PackageScan, namespace, name string) PackageScanDetail {
	out := PackageScanDetail{
		Scanned: body.Scanned,
		Scan: Scan{
			PackVersion: body.Scan.PackVersion,
			StartedAt:   body.Scan.StartedAt,
			FinishedAt:  body.Scan.FinishedAt,
			Verdict:     string(body.Scan.Verdict),
			TimedOut:    body.Scan.TimedOut,
		},
	}
	for _, check := range body.Checks {
		out.Checks = append(out.Checks, Check{
			ID: check.CheckId, Engine: check.Engine, Label: check.Label,
			Result: string(check.Result), WarnCount: int(check.WarnCount),
		})
	}

	// The subject line every finding row renders (findingRow, scanner.templ):
	// this operation is already scoped to one package and version, so it is
	// built once here rather than carried by every row on the wire.
	packageID := namespace + "/" + name
	subject := packageID + "@" + body.Version
	for _, finding := range body.Findings {
		out.Findings = append(out.Findings, packageScanFinding(finding, packageID, subject, string(body.Scan.Verdict)))
	}
	return out
}

func packageScanFinding(from apiclient.PackageScanFinding, packageID, subject, verdict string) FindingDetail {
	out := FindingDetail{
		Finding: Finding{
			ID: from.Id.String(), RuleID: from.RuleId, Engine: from.Engine,
			Severity: string(from.Severity), State: string(from.State), Title: from.Title,
			Subject: subject, PackageID: packageID, Verdict: verdict, RaisedAt: from.RaisedAt,
		},
		Explanation: deref(from.Detail),
		Evidence:    make([]Evidence, 0, len(from.Evidence)),
	}
	for _, item := range from.Evidence {
		out.Evidence = append(out.Evidence, Evidence{
			Path: item.Path, Line: int(derefInt(item.Line)), Quote: deref(item.Quote), Role: string(item.Role),
		})
	}
	if from.Override != nil {
		out.Override = &Override{
			Reviewer: from.Override.Reviewer, Note: deref(from.Override.Note),
			ExpiresAt: from.Override.ExpiresAt, DecidedAt: from.Override.DecidedAt,
		}
	}
	return out
}
