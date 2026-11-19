package hub

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The package detail screen's security section: the latest visible version's
// scan, its findings and any reviewer decision, mapped through the Scanner
// screen's own helpers so the two cannot render one finding two ways.

// PackageScan reads GET /v1/packages/{namespace}/{name}/scan. A 404 becomes
// view.ErrNotFound, the same answer Package gives for a package this
// identity may not read; a 403 is a rejected version, not a read failure.
func (c *Client) PackageScan(ctx context.Context, namespace, name string) (view.PackageScan, error) {
	resp, err := c.api.GetPackageScanWithResponse(ctx, namespace, name)
	if err != nil {
		return view.PackageScan{}, fmt.Errorf("read the scan for %s/%s: %w", namespace, name, err)
	}
	switch {
	case resp.JSON200 != nil:
		return packageScan(resp.JSON200, namespace, name, c.now()), nil
	case resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusForbidden:
		return view.PackageScan{Rejected: true}, nil
	case resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound:
		return view.PackageScan{}, view.ErrNotFound
	default:
		return view.PackageScan{}, statusError(resp.HTTPResponse, resp.Body)
	}
}

func packageScan(body *apiclient.PackageScan, namespace, name string, now time.Time) view.PackageScan {
	out := view.PackageScan{Scanned: body.Scanned, Scan: scanMeta(body.Scan)}
	out.Verdict = out.Scan.Verdict

	for _, check := range body.Checks {
		out.Checks = append(out.Checks, view.Check{
			ID: check.CheckId, Engine: check.Engine, Label: check.Label,
			Result: view.CheckResult(check.Result), WarnCount: int(check.WarnCount),
		})
	}

	packageID := namespace + "/" + name
	subject := packageID + "@" + body.Version
	for i := range body.Findings {
		from := &body.Findings[i]
		finding := view.FindingDetail{
			FindingRow: view.FindingRow{
				ID: from.Id.String(), RuleID: from.RuleId, Engine: from.Engine, Title: from.Title,
				Explanation: deref(from.Detail), Subject: subject, PackageID: packageID,
				Severity: view.Severity(from.Severity), State: view.FindingState(from.State),
				Verdict: out.Scan.Verdict, Raised: view.Relative(from.RaisedAt, now),
			},
		}
		for _, item := range from.Evidence {
			addEvidence(&finding, item)
		}
		finding.Override = findingOverride(from.Override, now)
		out.Findings = append(out.Findings, finding)
	}
	return out
}
