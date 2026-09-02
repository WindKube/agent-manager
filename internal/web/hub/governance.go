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

// The two governance screens' door to the api (US4), through the generated
// client and nothing else.
//
// The shapes below live in THIS package rather than in internal/web/view, which
// is the same choice auth.go made for Session and Viewer. The reason is the same:
// they are what the api answers, mapped once into Go the screen can use, and the
// screen owns its own view models. A hub type that was also the view model would
// make every rendering decision here, one layer too early — and this package is
// deliberately the one that decides nothing about what the catalog or the scanner
// MEANS.
//
// Nothing here renders. No relative dates, no collapsed verdict pills, no
// formatted durations: instants, counts and canonical vocabulary, so the screen
// can render them against its own clock and its own copy.

// ErrForbidden is the api refusing an action this identity's role does not carry.
//
// It is a sentinel of its own and not folded into the generic error path, because
// it is a screen state rather than a failure: FR-126 requires an impermissible
// action to be absent or disabled WITH ITS REASON, so a handler that gets this
// back has been told the reason and must say it — not log a bad gateway. Its
// arrival also means the screen offered something it should not have, which is
// worth noticing rather than swallowing.
var ErrForbidden = errors.New("this identity may not take that action")

// ScannerSummary is the Scanner screen's headline card.
type ScannerSummary struct {
	// PeriodDays is the window the two period figures cover, from the api rather
	// than from a caption: FR-121 forbids a figure that is a constant in the
	// product, and "last 30 days" is a figure.
	PeriodDays      int
	VersionsScanned int
	Quarantined     int
	OverridesActive int
	// NearestExpiry is when the first active override lapses, nil when none is
	// active. The design's "expires in 12 days" is this instant against the
	// reader's clock, computed in the screen.
	NearestExpiry *time.Time
	// MedianScan is nil when no scan finished in the period, which is not the same
	// as a median of zero and must not render as "0s".
	MedianScan *time.Duration
}

// Finding is one row of the findings list.
type Finding struct {
	// ID is the api's uuid as a string, because it goes straight back into a URL.
	ID       string
	RuleID   string
	Severity string
	State    string
	Title    string
	// Subject is the design's `community/slack-digest@0.5.1`. It is assembled here
	// rather than by the api — which returns the two parts — because it is the one
	// piece of rendering the screen would otherwise repeat in four places, and
	// PackageID is kept beside it for the link.
	Subject   string
	PackageID string
	Version   string
	// Verdict is the SUBJECT VERSION's verdict, carried raw and NOT collapsed onto
	// view.Scan's three pills. scanOf renders `rejected` as Flagged, which is right
	// in the catalog — "do not adopt this without reading the finding" — and wrong
	// here: on this screen the difference between awaiting a decision and having had
	// one is the entire subject of the page.
	Verdict  string
	RaisedAt time.Time
	// EvidencePath and EvidenceLine are the PRIMARY location only. Line is 0 when
	// the finding names a file without a line; line numbers are 1-based, so 0 is
	// unambiguous and saves the screen a pointer.
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

// FindingDetail is the detail pane: the finding, all of its evidence, and every
// check that ran.
type FindingDetail struct {
	Finding
	// Explanation is the rule pack's prose. It is bundle-adjacent text and is
	// rendered escaped, like everything else on this page (FR-055).
	Explanation string
	Evidence    []Evidence
	// Checks is every check the scan ran, passes included. A pane that showed only
	// the failures could not be told apart from one where nothing else ran, which
	// is the distinction the matrix exists for — so a screen must render this whole
	// slice, not filter it.
	Checks   []Check
	Scan     Scan
	Override *Override
}

// Evidence is one location a finding points at. Path and Quote are
// attacker-controlled bundle content: escaped on render, always (FR-055).
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
	// TimedOut is FR-031: a scan that ran out of budget, whose verdict a screen
	// must never present as a clean bill of health.
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
	// Verdict is the subject version's verdict AFTER the decision. An accept
	// leaves it flagged; only a reject makes it rejected.
	Verdict   string
	ExpiresAt *time.Time
}

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID         string
	OccurredAt time.Time
	Actor      string
	// ActorKind is identity or system. A screen must not attribute a system row to
	// a person, which is why this is carried rather than inferred from Actor.
	ActorKind string
	Kind      string
	// Text quotes package, profile and host names a publisher chose. Escaped on
	// render, always (FR-055).
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

// Finding reads GET /v1/findings/{id}.
//
// A 404 becomes view.ErrNotFound, the state the screen renders as a real screen
// rather than as a failure — and so does an id that is not a uuid. The id reaches
// this method out of a URL a person can edit, so "no such finding" is the honest
// answer to a malformed one; sending it to the api to be told the same thing
// would be a round trip to learn what is already known here.
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
	// The primary location, taken from the evidence rows rather than duplicated by
	// the api onto the detail body: the list view needs it flat and the detail view
	// already has every row, so reading it off the row whose role says `primary`
	// keeps one source of it here.
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

// AcceptFinding posts POST /v1/findings/{id}/accept.
//
// days of 0 lets the api apply its own default rather than this role inventing
// one: an override's lifetime is policy, and policy lives on the side that owns
// the row.
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

// AuditExport is the streamed export (FR-051), and it is the ONE method here that
// does not decode a body.
//
// It calls the raw client rather than ExportAuditWithResponse, and that is the
// whole point of the method. The generated `WithResponse` wrapper reads the entire
// body into a `[]byte` field before returning, so using it would materialise the
// complete audit log in this role's heap — exactly what the api went to the
// trouble of streaming to avoid, undone one layer later. The raw call hands back
// the live body and the caller copies it to the browser.
//
// The reader is the CALLER's to close, and the caller must also expect a stream
// that stops early: the api cannot change its status once the first row is out, so
// a truncated export arrives as a short 200 whose last line is not the api's
// completeness sentinel. A handler that copies this to a response without looking
// for that line will hand somebody an incomplete audit log that looks whole.
func (c *Client) AuditExport(ctx context.Context) (io.ReadCloser, string, error) {
	resp, err := c.api.ExportAudit(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("export the audit log: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is drained and closed rather than handed back: an error response
		// is a problem document, not an export, and a caller that treated it as one
		// would write it into the operator's file.
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

// governanceError adds the 403 branch to statusError.
//
// statusError already turns a 401 into view.ErrSignedOut, which is the signed-out
// screen. A 403 is the other refusal a screen has to render rather than log — the
// viewer is signed in and their role does not permit this — and the two must not
// collapse into one another: signing in again does not acquire a role, and being
// told to sign in when the real answer is "your role cannot do this" sends a
// person round a loop that cannot end.
func governanceError(resp *http.Response, body []byte) error {
	if resp != nil && resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	return statusError(resp, body)
}
