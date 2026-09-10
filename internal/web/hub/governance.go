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

// The two governance screens' door to the api, through the generated client
// and nothing else. The shapes below live in THIS package rather than
// internal/web/view: they are what the api answers, mapped once into Go the
// screen can use, and the screen owns its own view models.
//
// Nothing here renders: instants, counts and canonical vocabulary, so the
// screen can render them against its own clock and its own copy.

// ErrForbidden is the api refusing an action this identity's role does not
// carry. A sentinel of its own, not folded into the generic error path: it
// is a screen state rather than a failure, and its arrival also means the
// screen offered something it should not have.
var ErrForbidden = errors.New("this identity may not take that action")

// ScannerSummary is the Scanner screen's headline card.
type ScannerSummary struct {
	// PeriodDays is the window the two period figures cover, from the api
	// rather than a caption — never a figure that is a constant in the product.
	PeriodDays      int
	VersionsScanned int
	Quarantined     int
	OverridesActive int
	// NearestExpiry is when the first active override lapses, nil when none active.
	NearestExpiry *time.Time
	// MedianScan is nil when no scan finished in the period, distinct from a
	// median of zero, and must not render as "0s".
	MedianScan *time.Duration
}

// Finding is one row of the findings list.
type Finding struct {
	// ID is the api's uuid as a string, since it goes straight back into a URL.
	ID       string
	RuleID   string
	Severity string
	State    string
	Title    string
	// Subject is `community/slack-digest@0.5.1`, assembled here rather than
	// by the api to avoid repeating it in four places.
	Subject   string
	PackageID string
	Version   string
	// Verdict is the SUBJECT VERSION's verdict, carried raw and NOT collapsed
	// onto view.Scan's three pills: on this screen, awaiting a decision vs.
	// having had one is the entire subject of the page.
	Verdict  string
	RaisedAt time.Time
	// EvidencePath/Line are the PRIMARY location only. Line is 0 when the
	// finding names a file without one; line numbers are 1-based, so 0 is
	// unambiguous and saves a pointer.
	EvidencePath string
	EvidenceLine int
}

// FindingsPage is one page of findings.
type FindingsPage struct {
	Findings []Finding
	Total    int
	Page     int
	PageSize int
}

// FindingDetail is the detail pane: the finding, all of its evidence, and
// every check that ran.
type FindingDetail struct {
	Finding
	// Explanation is the rule pack's prose, bundle-adjacent text rendered escaped.
	Explanation string
	Evidence    []Evidence
	// Checks is every check the scan ran, passes included: a pane showing
	// only failures could not be told apart from one where nothing else ran.
	Checks   []Check
	Scan     Scan
	Override *Override
}

// Evidence is one location a finding points at. Path and Quote are
// attacker-controlled bundle content: escaped on render, always.
type Evidence struct {
	Path  string
	Line  int
	Quote string
	Role  string
}

// Check is one check the scan ran.
type Check struct {
	ID    string
	Label string
	// Result is pass, fail or warn, canonical and unrendered.
	Result    string
	WarnCount int
}

// Scan is the scan that raised the finding.
type Scan struct {
	PackVersion string
	StartedAt   time.Time
	// FinishedAt is nil while the scan is in flight.
	FinishedAt *time.Time
	Verdict    string
	// TimedOut: a scan that ran out of budget, whose verdict must never be
	// presented as a clean bill of health.
	TimedOut bool
}

// Override is the recorded acceptance of a finding.
type Override struct {
	Reviewer  string
	Note      string
	ExpiresAt *time.Time
	DecidedAt time.Time
}

// Decision is what an accept or a reject answers with.
type Decision struct {
	ID    string
	State string
	// Verdict is the subject version's verdict AFTER the decision: an accept
	// leaves it flagged, only a reject makes it rejected.
	Verdict   string
	ExpiresAt *time.Time
}

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID         string
	OccurredAt time.Time
	Actor      string
	// ActorKind is identity or system, carried rather than inferred from
	// Actor: a screen must not attribute a system row to a person.
	ActorKind string
	Kind      string
	// Text quotes package, profile and host names a publisher chose. Escaped
	// on render, always.
	Text   string
	Source string
}

// AuditPage is one page of the audit log.
type AuditPage struct {
	Entries  []AuditEntry
	Total    int
	Page     int
	PageSize int
}

// Badges is the shell's three counts.
type Badges struct {
	Packages     int
	Profiles     int
	OpenFindings int
}

// ScannerSummary reads GET /v1/scanner/summary. days of 0 takes the api's own
// window rather than asserting one from this side.
func (c *Client) ScannerSummary(ctx context.Context, days int) (ScannerSummary, error) {
	params := &apiclient.ScannerSummaryParams{}
	if days > 0 {
		params.Days = ptr(int64(days))
	}

	resp, err := c.api.ScannerSummaryWithResponse(ctx, params)
	if err != nil {
		return ScannerSummary{}, fmt.Errorf("read the scanner summary: %w", err)
	}
	if resp.JSON200 == nil {
		return ScannerSummary{}, fmt.Errorf("read the scanner summary: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := ScannerSummary{
		PeriodDays:      int(body.PeriodDays),
		VersionsScanned: int(body.VersionsScanned),
		Quarantined:     int(body.Quarantined),
		OverridesActive: int(body.OverridesActive),
		NearestExpiry:   body.NearestOverrideExpiry,
	}
	if body.MedianScanSeconds != nil {
		median := time.Duration(*body.MedianScanSeconds * float64(time.Second))
		out.MedianScan = &median
	}
	return out, nil
}

// FindingQuery is the findings list's filter, in the api's vocabulary. Empty
// strings mean no filter, which is what the api's `all` is.
type FindingQuery struct {
	State    string
	Severity string
	Page     int
}

// Findings reads GET /v1/findings.
func (c *Client) Findings(ctx context.Context, q FindingQuery) (FindingsPage, error) {
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
		return FindingsPage{}, fmt.Errorf("list findings: %w", err)
	}
	if resp.JSON200 == nil {
		return FindingsPage{}, fmt.Errorf("list findings: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	page := FindingsPage{
		Findings: make([]Finding, 0, len(body.Findings)),
		Total:    int(body.Total),
		Page:     int(body.Page),
		PageSize: int(body.PageSize),
	}
	for i := range body.Findings {
		page.Findings = append(page.Findings, finding(&body.Findings[i]))
	}
	return page, nil
}

// Finding reads GET /v1/findings/{id}. A 404 becomes view.ErrNotFound, and so
// does an id that is not a uuid: the id reaches this method out of a URL a
// person can edit, so "no such finding" is the honest answer to a malformed one.
func (c *Client) Finding(ctx context.Context, id string) (FindingDetail, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return FindingDetail{}, view.ErrNotFound
	}

	resp, err := c.api.GetFindingWithResponse(ctx, parsed)
	if err != nil {
		return FindingDetail{}, fmt.Errorf("get finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound {
			return FindingDetail{}, view.ErrNotFound
		}
		return FindingDetail{}, fmt.Errorf("get finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := FindingDetail{
		Finding: Finding{
			ID:        body.Id.String(),
			RuleID:    body.RuleId,
			Severity:  string(body.Severity),
			State:     string(body.State),
			Title:     body.Title,
			Subject:   body.PackageId + "@" + body.Version,
			PackageID: body.PackageId,
			Version:   body.Version,
			Verdict:   string(body.Verdict),
			RaisedAt:  body.RaisedAt,
		},
		Explanation: deref(body.Detail),
		Evidence:    make([]Evidence, 0, len(body.Evidence)),
		Checks:      make([]Check, 0, len(body.Checks)),
		Scan: Scan{
			PackVersion: body.Scan.PackVersion,
			StartedAt:   body.Scan.StartedAt,
			FinishedAt:  body.Scan.FinishedAt,
			Verdict:     string(body.Scan.Verdict),
			TimedOut:    body.Scan.TimedOut,
		},
	}
	// The primary location is taken from the evidence rows rather than
	// duplicated by the api: reading it off the row whose role says
	// `primary` keeps one source of it here.
	for _, item := range body.Evidence {
		out.Evidence = append(out.Evidence, Evidence{
			Path:  item.Path,
			Line:  int(derefInt(item.Line)),
			Quote: deref(item.Quote),
			Role:  string(item.Role),
		})
		if string(item.Role) == evidenceRolePrimary && out.EvidencePath == "" {
			out.EvidencePath = item.Path
			out.EvidenceLine = int(derefInt(item.Line))
		}
	}
	for _, check := range body.Checks {
		out.Checks = append(out.Checks, Check{
			ID: check.CheckId, Label: check.Label,
			Result: string(check.Result), WarnCount: int(check.WarnCount),
		})
	}
	if body.Override != nil {
		out.Override = &Override{
			Reviewer:  body.Override.Reviewer,
			Note:      deref(body.Override.Note),
			ExpiresAt: body.Override.ExpiresAt,
			DecidedAt: body.Override.DecidedAt,
		}
	}
	return out, nil
}

const evidenceRolePrimary = "primary"

// AcceptFinding posts POST /v1/findings/{id}/accept. days of 0 lets the api
// apply its own default: an override's lifetime is policy, and policy lives
// on the side that owns the row.
func (c *Client) AcceptFinding(ctx context.Context, id, note string, days int) (Decision, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return Decision{}, view.ErrNotFound
	}

	body := apiclient.AcceptFindingJSONRequestBody{Note: note}
	if days > 0 {
		body.ExpiresInDays = ptr(int64(days))
	}

	resp, err := c.api.AcceptFindingWithResponse(ctx, parsed, body)
	if err != nil {
		return Decision{}, fmt.Errorf("accept finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		return Decision{}, fmt.Errorf("accept finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return decision(resp.JSON200), nil
}

// RejectFinding posts POST /v1/findings/{id}/reject. There is no expiry to pass:
// rejection is terminal.
func (c *Client) RejectFinding(ctx context.Context, id, note string) (Decision, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return Decision{}, view.ErrNotFound
	}

	body := apiclient.RejectFindingJSONRequestBody{}
	if note != "" {
		body.Note = &note
	}

	resp, err := c.api.RejectFindingWithResponse(ctx, parsed, body)
	if err != nil {
		return Decision{}, fmt.Errorf("reject finding %s: %w", id, err)
	}
	if resp.JSON200 == nil {
		return Decision{}, fmt.Errorf("reject finding %s: %w", id,
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return decision(resp.JSON200), nil
}

// Audit reads GET /v1/audit.
func (c *Client) Audit(ctx context.Context, page int) (AuditPage, error) {
	params := &apiclient.ListAuditParams{}
	if page > 0 {
		params.Page = ptr(int64(page))
	}

	resp, err := c.api.ListAuditWithResponse(ctx, params)
	if err != nil {
		return AuditPage{}, fmt.Errorf("read the audit log: %w", err)
	}
	if resp.JSON200 == nil {
		return AuditPage{}, fmt.Errorf("read the audit log: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	out := AuditPage{
		Entries:  make([]AuditEntry, 0, len(body.Entries)),
		Total:    int(body.Total),
		Page:     int(body.Page),
		PageSize: int(body.PageSize),
	}
	for _, entry := range body.Entries {
		out.Entries = append(out.Entries, AuditEntry{
			ID:         entry.Id.String(),
			OccurredAt: entry.OccurredAt,
			Actor:      entry.Actor,
			ActorKind:  string(entry.ActorKind),
			Kind:       string(entry.Kind),
			Text:       entry.Text,
			Source:     deref(entry.Source),
		})
	}
	return out, nil
}

// AuditExport is the streamed export, the ONE method here that does not
// decode a body: it calls the raw client rather than ExportAuditWithResponse,
// whose generated wrapper reads the entire body into memory first —
// undoing the api's own streaming. The reader is the CALLER's to close, and
// the caller must expect a stream that stops early: a truncated export
// arrives as a short 200 whose last line is not the api's completeness sentinel.
func (c *Client) AuditExport(ctx context.Context) (io.ReadCloser, string, error) {
	resp, err := c.api.ExportAudit(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("export the audit log: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Drained and closed rather than handed back: an error response is a
		// problem document, not an export.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("export the audit log: %w", governanceError(resp, nil))
	}
	return resp.Body, resp.Header.Get("Content-Type"), nil
}

// Badges reads GET /v1/badges — the shell's counts, one call per page render.
func (c *Client) Badges(ctx context.Context) (Badges, error) {
	resp, err := c.api.GetBadgesWithResponse(ctx)
	if err != nil {
		return Badges{}, fmt.Errorf("read the badge counts: %w", err)
	}
	if resp.JSON200 == nil {
		return Badges{}, fmt.Errorf("read the badge counts: %w",
			governanceError(resp.HTTPResponse, resp.Body))
	}
	return Badges{
		Packages:     int(resp.JSON200.Packages),
		Profiles:     int(resp.JSON200.Profiles),
		OpenFindings: int(resp.JSON200.OpenFindings),
	}, nil
}

func finding(from *apiclient.FindingSummary) Finding {
	return Finding{
		ID:           from.Id.String(),
		RuleID:       from.RuleId,
		Severity:     string(from.Severity),
		State:        string(from.State),
		Title:        from.Title,
		Subject:      from.PackageId + "@" + from.Version,
		PackageID:    from.PackageId,
		Version:      from.Version,
		Verdict:      string(from.Verdict),
		RaisedAt:     from.RaisedAt,
		EvidencePath: deref(from.EvidencePath),
		EvidenceLine: int(derefInt(from.EvidenceLine)),
	}
}

func decision(from *apiclient.FindingDecision) Decision {
	return Decision{
		ID:        from.Id.String(),
		State:     string(from.State),
		Verdict:   string(from.Verdict),
		ExpiresAt: from.ExpiresAt,
	}
}

// governanceError adds the 403 branch to statusError. The two refusals must
// not collapse into one another: signing in again does not acquire a role,
// so treating a 403 as a 401 sends a person round a loop that cannot end.
func governanceError(resp *http.Response, body []byte) error {
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	return statusError(resp, body)
}
