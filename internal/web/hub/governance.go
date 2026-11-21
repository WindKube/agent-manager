package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// ErrForbidden is the api refusing an action this identity's role lacks. It is a
// screen state, not a failure, and means the screen offered something it should not have.
var ErrForbidden = errors.New("this identity may not take that action")

// ScannerSummary reads the scanner summary; days of 0 takes the api's window.
func (c *Client) ScannerSummary(ctx context.Context, days int) (view.ScannerSummary, error) {
	params := &apiclient.ScannerSummaryParams{}
	if days > 0 {
		params.Days = ptr(int64(days))
	}

	resp, err := c.api.ScannerSummaryWithResponse(ctx, params)
	if err != nil {
		return view.ScannerSummary{}, fmt.Errorf("read the scanner summary: %w", err)
	}
	if resp.JSON200 == nil {
		return view.ScannerSummary{}, fmt.Errorf("read the scanner summary: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := view.ScannerSummary{
		PeriodDays:      int(body.PeriodDays),
		VersionsScanned: int(body.VersionsScanned),
		Quarantined:     int(body.Quarantined),
		OverridesActive: int(body.OverridesActive),
	}
	if body.NearestOverrideExpiry != nil {
		out.NearestExpiry = view.Until(*body.NearestOverrideExpiry, c.now())
	}
	if body.MedianScanSeconds != nil {
		// nil stays empty; a median that rounds to nothing is still a measurement.
		out.MedianScan = view.Duration(time.Duration(*body.MedianScanSeconds * float64(time.Second)))
		if out.MedianScan == "" {
			out.MedianScan = "0ms"
		}
	}
	return out, nil
}

// FindingQuery is the findings filter in the api's vocabulary; empty means `all`.
type FindingQuery struct {
	State    string
	Severity string
	Page     int
}

func (c *Client) Findings(ctx context.Context, q FindingQuery) (view.FindingsPage, error) {
	params := &apiclient.ListFindingsParams{}
	if q.State != "" {
		params.State = ptr(apiclient.ListFindingsParamsState(q.State))
	}
	if q.Severity != "" {
		params.Severity = ptr(apiclient.ListFindingsParamsSeverity(q.Severity))
	}
	if q.Page > 0 {
		params.Page = ptr(int64(q.Page))
	}

	resp, err := c.api.ListFindingsWithResponse(ctx, params)
	if err != nil {
		return view.FindingsPage{}, fmt.Errorf("list findings: %w", err)
	}
	if resp.JSON200 == nil {
		return view.FindingsPage{}, fmt.Errorf("list findings: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	page := view.FindingsPage{
		Rows:     make([]view.FindingRow, 0, len(body.Findings)),
		Total:    int(body.Total),
		Page:     int(body.Page),
		PageSize: int(body.PageSize),
	}
	now := c.now()
	for i := range body.Findings {
		page.Rows = append(page.Rows, findingRow(&body.Findings[i], now))
	}
	return page, nil
}

// Finding maps a 404, and an id that is not a uuid, to view.ErrNotFound: the id
// comes from an editable URL.
func (c *Client) Finding(ctx context.Context, id string) (view.FindingDetail, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.FindingDetail{}, view.ErrNotFound
	}

	resp, err := c.api.GetFindingWithResponse(ctx, parsed)
	if err != nil {
		return view.FindingDetail{}, fmt.Errorf("get finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound {
			return view.FindingDetail{}, view.ErrNotFound
		}
		return view.FindingDetail{}, fmt.Errorf("get finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	now := c.now()
	out := view.FindingDetail{
		FindingRow: view.FindingRow{
			ID:          body.Id.String(),
			RuleID:      body.RuleId,
			Engine:      body.Engine,
			Title:       body.Title,
			Explanation: deref(body.Detail),
			Subject:     body.PackageId + "@" + body.Version,
			PackageID:   body.PackageId,
			Version:     body.Version,
			Severity:    view.Severity(body.Severity),
			State:       view.FindingState(body.State),
			Verdict:     view.Verdict(body.Verdict),
			Raised:      view.Relative(body.RaisedAt, now),
		},
		Scan: scanMeta(body.Scan),
	}
	for _, item := range body.Evidence {
		addEvidence(&out, item)
	}
	for _, check := range body.Checks {
		out.Checks = append(out.Checks, view.Check{
			ID: check.CheckId, Engine: check.Engine, Label: check.Label, Explain: check.Explain,
			Result: view.CheckResult(check.Result), WarnCount: int(check.WarnCount),
		})
	}
	out.Override = findingOverride(body.Override, now)
	return out, nil
}

// AcceptFinding accepts a finding; days of 0 lets the api apply its policy default.
func (c *Client) AcceptFinding(ctx context.Context, id, note string, days int) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.ErrNotFound
	}

	body := apiclient.AcceptFindingJSONRequestBody{Note: note}
	if days > 0 {
		body.ExpiresInDays = ptr(int64(days))
	}

	resp, err := c.api.AcceptFindingWithResponse(ctx, parsed, body)
	if err != nil {
		return fmt.Errorf("accept finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("accept finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return nil
}

// RejectFinding rejects a finding. Rejection is terminal, so there is no expiry.
func (c *Client) RejectFinding(ctx context.Context, id, note string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return view.ErrNotFound
	}

	body := apiclient.RejectFindingJSONRequestBody{}
	if note != "" {
		body.Note = &note
	}

	resp, err := c.api.RejectFindingWithResponse(ctx, parsed, body)
	if err != nil {
		return fmt.Errorf("reject finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("reject finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return nil
}

func (c *Client) Audit(ctx context.Context, page int, filter view.AuditFilter) (view.AuditPage, error) {
	params := &apiclient.ListAuditParams{
		SubjectId: optional(filter.SubjectID),
		Namespace: optional(filter.Namespace),
	}
	if filter.SubjectKind != "" {
		params.SubjectKind = ptr(apiclient.ListAuditParamsSubjectKind(filter.SubjectKind))
	}
	if page > 0 {
		params.Page = ptr(int64(page))
	}

	resp, err := c.api.ListAuditWithResponse(ctx, params)
	if err != nil {
		return view.AuditPage{}, fmt.Errorf("read the audit log: %w", err)
	}
	if resp.JSON200 == nil {
		return view.AuditPage{}, fmt.Errorf("read the audit log: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := view.AuditPage{
		Rows:     make([]view.AuditRow, 0, len(body.Entries)),
		Total:    int(body.Total),
		Page:     int(body.Page),
		PageSize: int(body.PageSize),
	}
	for i := range body.Entries {
		out.Rows = append(out.Rows, auditRow(&body.Entries[i]))
	}
	return out, nil
}

func auditRow(entry *apiclient.AuditEntry) view.AuditRow {
	row := view.AuditRow{
		ID:        entry.Id.String(),
		At:        view.Timestamp(entry.OccurredAt),
		Actor:     entry.Actor,
		System:    string(entry.ActorKind) == view.ActorKindSystem,
		Kind:      string(entry.Kind),
		Text:      entry.Text,
		Source:    deref(entry.Source),
		SubjectID: deref(entry.SubjectId),
		Namespace: deref(entry.Namespace),
	}
	if entry.SubjectKind != nil {
		row.SubjectKind = string(*entry.SubjectKind)
	}
	switch row.SubjectKind {
	case "package":
		row.Package = row.SubjectID
	case "version", "finding":
		if entry.Data != nil {
			row.Package, _ = (*entry.Data)["package"].(string)
		}
	}
	return row
}

// AuditExport streams the export through the raw client, because the generated
// WithResponse wrapper buffers the whole body. The caller closes the reader, and a
// truncated export arrives as a short 200 without the api's completeness sentinel.
func (c *Client) AuditExport(ctx context.Context, filter view.AuditFilter) (io.ReadCloser, string, error) {
	params := &apiclient.ExportAuditParams{
		SubjectId: optional(filter.SubjectID),
		Namespace: optional(filter.Namespace),
	}
	if filter.SubjectKind != "" {
		params.SubjectKind = ptr(apiclient.ExportAuditParamsSubjectKind(filter.SubjectKind))
	}
	resp, err := c.api.ExportAudit(ctx, params)
	if err != nil {
		return nil, "", fmt.Errorf("export the audit log: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// An error response is a problem document, not an export.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("export the audit log: %w", governanceError(resp, nil))
	}
	return resp.Body, resp.Header.Get("Content-Type"), nil
}

// Badges reads the shell's counts, one call per page render.
func (c *Client) Badges(ctx context.Context) (view.Badges, error) {
	resp, err := c.api.GetBadgesWithResponse(ctx)
	if err != nil {
		return view.Badges{}, fmt.Errorf("read the badge counts: %w", err)
	}
	if resp.JSON200 == nil {
		return view.Badges{}, fmt.Errorf("read the badge counts: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return view.Badges{
		Packages:     int(resp.JSON200.Packages),
		Profiles:     int(resp.JSON200.Profiles),
		OpenFindings: int(resp.JSON200.OpenFindings),
	}, nil
}

func findingRow(from *apiclient.FindingSummary, now time.Time) view.FindingRow {
	row := view.FindingRow{
		ID:          from.Id.String(),
		RuleID:      from.RuleId,
		Engine:      from.Engine,
		Title:       from.Title,
		Explanation: deref(from.Detail),
		Subject:     from.PackageId + "@" + from.Version,
		PackageID:   from.PackageId,
		Version:     from.Version,
		Severity:    view.Severity(from.Severity),
		State:       view.FindingState(from.State),
		Verdict:     view.Verdict(from.Verdict),
		Raised:      view.Relative(from.RaisedAt, now),
	}
	if from.EvidencePath != nil {
		row.Primary = &view.Evidence{Path: *from.EvidencePath, Line: int(derefInt(from.EvidenceLine))}
	}
	return row
}

func scanMeta(from apiclient.FindingScan) view.ScanMeta {
	out := view.ScanMeta{
		PackVersion: from.PackVersion,
		Started:     view.Timestamp(from.StartedAt),
		Verdict:     view.Verdict(from.Verdict),
		TimedOut:    from.TimedOut,
	}
	if from.FinishedAt != nil {
		out.Finished = view.Timestamp(*from.FinishedAt)
	}
	return out
}

// addEvidence finds the primary location by role: the api promises no order.
func addEvidence(out *view.FindingDetail, item apiclient.FindingEvidence) {
	evidence := view.Evidence{Path: item.Path, Line: int(derefInt(item.Line)), Quote: deref(item.Quote)}
	if string(item.Role) == evidencePrimary && out.Primary == nil {
		out.Primary = &evidence
		return
	}
	out.Supporting = append(out.Supporting, evidence)
}

const evidencePrimary = "primary"

func findingOverride(from *apiclient.FindingOverride, now time.Time) *view.Override {
	if from == nil {
		return nil
	}
	out := &view.Override{
		Reviewer: from.Reviewer,
		Note:     deref(from.Note),
		Decided:  view.Timestamp(from.DecidedAt),
	}
	if from.ExpiresAt != nil {
		out.Expires = view.Until(*from.ExpiresAt, now)
		out.Lapse = view.Lapse(*from.ExpiresAt, now)
	}
	return out
}

// governanceError adds 403 to statusError. Treating a 403 as a 401 would loop a
// person through sign-in, which never grants a role.
func governanceError(resp *http.Response, body []byte) error {
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	return statusError(resp, body)
}
