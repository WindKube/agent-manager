package view

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// A finding's State (has a reviewer decided) and its version's Verdict (what the scan concluded) are never
// collapsed: accepting a finding records an exception and leaves the version flagged.

// Severity is a finding's severity as the rule pack states it. The constants are not exhaustive: a pack can
// add a value, which renders as itself rather than vanishing.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

func (s Severity) Label() string {
	switch s {
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	case "":
		return "Unrated"
	default:
		return string(s)
	}
}

func (s Severity) Tone() string {
	switch s {
	case SeverityHigh:
		return "dan"
	case SeverityMedium:
		return "warn"
	default:
		return "neutral"
	}
}

// FindingState is whether a reviewer has decided this finding.
type FindingState string

const (
	FindingOpen     FindingState = "open"
	FindingApproved FindingState = "approved"
	FindingRejected FindingState = "rejected"
)

func (s FindingState) Label() string {
	switch s {
	case FindingOpen:
		return "Open"
	case FindingApproved:
		return "Approved"
	case FindingRejected:
		return "Rejected"
	case "":
		return "Unknown"
	default:
		return string(s)
	}
}

// Tone does not paint an approved finding green: an override is a recorded exception, not a clean bill of health.
func (s FindingState) Tone() string {
	switch s {
	case FindingOpen:
		return "warn"
	case FindingRejected:
		return "dan"
	default:
		return "neutral"
	}
}

// Verdict is the subject version's verdict, carried whole rather than collapsed onto Scan's pills.
type Verdict string

const (
	VerdictClean    Verdict = "clean"
	VerdictFlagged  Verdict = "flagged"
	VerdictRejected Verdict = "rejected"
	VerdictScanning Verdict = "scanning"
)

func (v Verdict) Label() string {
	switch v {
	case VerdictClean:
		return "Clean"
	case VerdictFlagged:
		return "Flagged"
	case VerdictRejected:
		return "Rejected"
	case VerdictScanning:
		return "Scanning"
	case "":
		return "No verdict"
	default:
		return string(v)
	}
}

func (v Verdict) Tone() string {
	switch v {
	case VerdictClean:
		return "ok"
	case VerdictFlagged, VerdictRejected:
		return "dan"
	default:
		return "warn"
	}
}

// CheckResult is one row of the check matrix.
type CheckResult string

const (
	CheckPass CheckResult = "pass"
	CheckWarn CheckResult = "warn"
	CheckFail CheckResult = "fail"
)

func (r CheckResult) Label() string {
	switch r {
	case CheckPass:
		return "pass"
	case CheckWarn:
		return "warn"
	case CheckFail:
		return "fail"
	default:
		return string(r)
	}
}

// Mark carries the result on its own, so the matrix is readable without colour.
func (r CheckResult) Mark() string {
	switch r {
	case CheckPass:
		return "✓"
	case CheckFail:
		return "✕"
	case CheckWarn:
		return "!"
	default:
		return "·"
	}
}

func (r CheckResult) Tone() string {
	switch r {
	case CheckPass:
		return "ok"
	case CheckFail:
		return "dan"
	case CheckWarn:
		return "warn"
	default:
		return "neutral"
	}
}

// Check is one check the scan ran, pass or fail. Render the whole slice, never just failures, so a missing
// finding is distinguishable from a missing check.
type Check struct {
	ID      string
	Engine  string
	Label   string
	Explain string
	Result  CheckResult
	// WarnCount is not a finding counter; see Note.
	WarnCount int
}

// Note explains a non-zero WarnCount. The rule pack's counts files it could not read; other engines mix
// sub-threshold findings with skipped analyses, so no cause is claimed.
func (c Check) Note() string {
	if c.WarnCount == 0 {
		return ""
	}
	if c.Engine != "" && c.Engine != RulepackEngine {
		return plural(c.WarnCount, "warning")
	}
	return plural(c.WarnCount, "file") + " this check could not read"
}

// RulepackEngine is the rule pack's analyser id.
const RulepackEngine = "rulepack"

func EngineLabel(engine string) string {
	switch engine {
	case "", RulepackEngine:
		return "Rule pack"
	case "skill-scanner":
		return "Skill scanner"
	default:
		return engine
	}
}

// Evidence is one location a finding points at. Path and Quote are untrusted package bytes.
type Evidence struct {
	Path string
	// Line is 0 when the evidence names no line; lines are 1-based.
	Line  int
	Quote string
}

// Location is "path:line", or just the path when there is no line.
func (e Evidence) Location() string {
	if e.Line <= 0 {
		return e.Path
	}
	return e.Path + ":" + strconv.Itoa(e.Line)
}

// FindingRow is one row of the findings list.
type FindingRow struct {
	ID     string
	RuleID string
	// Engine plus RuleID identifies a finding, since two engines may share a rule id.
	Engine      string
	Title       string
	Subject     string
	Severity    Severity
	State       FindingState
	Verdict     Verdict
	Raised      string
	Explanation string
	PackageID   string
	Version     string
	// Primary is nil when the scan recorded no location.
	Primary *Evidence
}

// FindingsPage is one page of the findings list.
type FindingsPage struct {
	Rows     []FindingRow
	Total    int
	Page     int
	PageSize int
}

// ScanMeta is the scan that raised the finding.
type ScanMeta struct {
	// PackVersion is opaque; nothing splits or parses it.
	PackVersion string
	Started     string
	Finished    string
	Verdict     Verdict
	// TimedOut means the scan reached no judgement; never present it as clean.
	TimedOut bool
}

// Override is the recorded acceptance of a finding.
type Override struct {
	Reviewer string
	Note     string
	Decided  string
	// Expires is always set by this hub; "" means a row this hub did not write, not "never expires".
	Expires string
	// Lapse is "expired", "soon" within WaiverNoticeDays of the expiry, or "".
	Lapse string
}

// WaiverNoticeDays mirrors the notifier's default waiver.expiring notice.
const WaiverNoticeDays = 7

// Lapse classifies an expiry for the warning beside it.
func Lapse(at, now time.Time) string {
	switch {
	case !at.After(now):
		return "expired"
	case at.Sub(now) <= WaiverNoticeDays*24*time.Hour:
		return "soon"
	default:
		return ""
	}
}

// FindingDetail is the detail pane.
type FindingDetail struct {
	FindingRow
	// Supporting excludes the primary location so it is not shown twice.
	Supporting []Evidence
	Checks     []Check
	Scan       ScanMeta
	Override   *Override
	// Affected is the machines holding this version; nil when not countable.
	Affected *AffectedMachines
}

// CanAccept is read against the finding rather than the viewer: a rejected finding is terminal.
func (d FindingDetail) CanAccept() bool { return d.State != FindingRejected }

func (d FindingDetail) CanReject() bool { return d.State != FindingRejected }

// TerminalNote is why neither control is offered, when neither is.
func (d FindingDetail) TerminalNote() string {
	if d.CanAccept() || d.CanReject() {
		return ""
	}
	return "This finding has been rejected. The version is quarantined for good and no " +
		"profile can resolve it, so there is nothing left to decide."
}

// Review is what this viewer may do on this screen, and why not. Allowed is decided from the viewer's
// resolved role, not from a previous refusal.
type Review struct {
	Allowed bool
	Reason  string
}

// ScannerDecisionRoles mirrors internal/api's scannerDecisionRoles, which web may not import. The api stays
// authoritative, so drift can only disable a control that would have worked.
var ScannerDecisionRoles = []string{"scanner-reviewer", "catalog-admin"}

// ReviewFor decides what the viewer may do; an unresolved viewer may decide nothing.
func ReviewFor(viewer *Viewer) Review {
	if viewer == nil || !viewer.SignedIn {
		return Review{Reason: "Sign in to review findings."}
	}
	if !viewer.HasRole {
		return Review{Reason: "Your identity is not mapped to a role yet, so it can read " +
			"findings but not decide them."}
	}
	for _, role := range ScannerDecisionRoles {
		if viewer.Role == role {
			return Review{Allowed: true}
		}
	}
	return Review{Reason: "Your role, " + viewer.RoleLabel() + ", cannot decide findings. " +
		"Approving or rejecting a finding needs the scanner reviewer or the catalog admin role."}
}

// StatCard is one of the four headline figures.
type StatCard struct {
	Label string
	Value string
	Note  string
	// Tone is "" for the ordinary ramp, or ok/warn/dan.
	Tone string
}

// ScannerSummary is the headline card row, with its nullable figures already rendered by the caller.
type ScannerSummary struct {
	PeriodDays      int
	VersionsScanned int
	Quarantined     int
	OverridesActive int
	// NearestExpiry is "" when no active override lapses.
	NearestExpiry string
	// MedianScan is "" when nothing finished in the window, which must never render as zero.
	MedianScan string
}

func (s ScannerSummary) Cards() []StatCard {
	window := "no window reported"
	if s.PeriodDays > 0 {
		window = "last " + plural(s.PeriodDays, "day")
	}

	scanned := StatCard{Label: "Versions scanned", Value: strconv.Itoa(s.VersionsScanned), Note: window}

	quarantined := StatCard{
		Label: "Quarantined",
		Value: strconv.Itoa(s.Quarantined),
		Note:  "blocked from publish",
	}
	if s.Quarantined > 0 {
		quarantined.Tone = "dan"
	}

	overrides := StatCard{
		Label: "Overrides active",
		Value: strconv.Itoa(s.OverridesActive),
		Note:  "none expiring",
	}
	switch {
	case s.OverridesActive == 0:
		overrides.Note = "no accepted risk on record"
	case s.NearestExpiry != "":
		overrides.Tone = "warn"
		overrides.Note = "first lapses " + s.NearestExpiry
	default:
		overrides.Tone = "warn"
		overrides.Note = "none of them expires"
	}

	median := StatCard{Label: "Median scan time", Value: s.MedianScan, Note: "fetch to verdict"}
	if s.MedianScan == "" {
		// Not "0s": that would read as a scanner that answers instantly.
		median.Value = "—"
		median.Note = "no scan finished in this window"
	}

	return []StatCard{scanned, quarantined, overrides, median}
}

// Finding state filters are a closed set, unlike severity, which a rule pack can extend.
const (
	FindingFilterAll      = "all"
	FindingFilterOpen     = "open"
	FindingFilterApproved = "approved"
	FindingFilterRejected = "rejected"
)

var FindingFilters = []string{
	FindingFilterAll, FindingFilterOpen, FindingFilterApproved, FindingFilterRejected,
}

func FindingFilterLabel(state string) string {
	switch state {
	case FindingFilterOpen:
		return "Open"
	case FindingFilterApproved:
		return "Approved"
	case FindingFilterRejected:
		return "Rejected"
	default:
		return "All"
	}
}

// ScannerQuery is one request for the screen: filter, page, and the finding open in the detail pane.
type ScannerQuery struct {
	State string
	Page  int
	// Selected is untrusted URL text, only ever used as a query value, so it is escaped rather than validated.
	Selected string
}

func (q ScannerQuery) Normalise() ScannerQuery {
	if !contains(FindingFilters, q.State) {
		q.State = FindingFilterAll
	}
	if q.Page < 1 {
		q.Page = 1
	}
	q.Selected = strings.TrimSpace(q.Selected)
	if len(q.Selected) > maxFindingIDLength {
		q.Selected = ""
	}
	return q
}

// maxFindingIDLength bounds what is echoed back into every link on the page.
const maxFindingIDLength = 64

func (q ScannerQuery) APIState() string {
	if q.State == FindingFilterAll {
		return ""
	}
	return q.State
}

func (q ScannerQuery) Href(state string, page int, selected string) string {
	values := url.Values{}
	if state != FindingFilterAll && state != "" {
		values.Set("state", state)
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if selected != "" {
		values.Set("finding", selected)
	}
	if len(values) == 0 {
		return "/scanner"
	}
	return "/scanner?" + values.Encode()
}

// FilterHref resets the page and drops the selection, which the new filter may exclude.
func (q ScannerQuery) FilterHref(state string) string { return q.Href(state, 1, "") }

func (q ScannerQuery) SelectHref(id string) string { return q.Href(q.State, q.Page, id) }

// PageHref keeps the selection, which is addressed by id and so survives a page turn.
func (q ScannerQuery) PageHref(page int) string { return q.Href(q.State, page, q.Selected) }

func (q ScannerQuery) DecideHref(id, action string) string {
	if id == "" {
		return "/scanner"
	}
	return "/scanner/findings/" + url.PathEscape(id) + "/" + action
}

// Notice is a write's outcome shown at the top of a screen. Tone is "ok", "warn" or "dan".
type Notice struct {
	Tone string
	Text string
}

// Scanner is the whole screen. There is deliberately no severity filter: severities come from the rule pack,
// so chips derived from the page would change as a reader paged.
type Scanner struct {
	Query    ScannerQuery
	Summary  ScannerSummary
	Findings []FindingRow
	Total    int
	Page     int
	PageSize int
	Selected *FindingDetail
	Review   Review
	Notice   *Notice

	GovernanceState

	// Missing is a selected finding id that names nothing readable; it affects the pane only.
	Missing bool
}

// GovernanceState is the ways a governance screen ends up with no rows; each asks the reader for something
// different, and only SignedOut is fixed by signing in again.
type GovernanceState struct {
	SignedOut bool
	// Refused must never collapse onto SignedOut: signing in again does not acquire a role.
	Refused     bool
	Unavailable bool
}

// Readable reports whether anything could be read at all.
func (g GovernanceState) Readable() bool {
	return !g.SignedOut && !g.Refused && !g.Unavailable
}

// DefaultFindingsPageSize mirrors the api's default.
const DefaultFindingsPageSize = 20

func (s Scanner) Pages() int {
	size := s.PageSize
	if size < 1 {
		size = DefaultFindingsPageSize
	}
	if s.Total <= 0 {
		return 1
	}
	return (s.Total + size - 1) / size
}

func (s Scanner) CurrentPage() int {
	if s.Page < 1 {
		return 1
	}
	return s.Page
}

// Count is empty when nothing was readable, rather than claiming "0 findings".
func (s Scanner) Count() string {
	switch {
	case !s.Readable():
		return ""
	case s.Total == 1:
		return "1 finding"
	default:
		return strconv.Itoa(s.Total) + " findings"
	}
}

// Filtered separates "this hub has no findings" from "this filter has none".
func (s Scanner) Filtered() bool { return s.Query.State != FindingFilterAll }

func (s Scanner) Empty() bool { return len(s.Findings) == 0 }

// Duration renders a scan time.
func Duration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Second:
		return strconv.Itoa(int(d.Round(time.Millisecond)/time.Millisecond)) + "ms"
	case d < time.Minute:
		seconds := d.Seconds()
		if seconds < 10 {
			return strconv.FormatFloat(float64(int(seconds*10+0.5))/10, 'f', -1, 64) + "s"
		}
		return strconv.Itoa(int(seconds+0.5)) + "s"
	default:
		minutes := int(d / time.Minute)
		seconds := int((d % time.Minute).Seconds())
		if seconds == 0 {
			return plural(minutes, "minute")
		}
		return strconv.Itoa(minutes) + "m " + strconv.Itoa(seconds) + "s"
	}
}

// Until is Relative's other direction; a lapsed instant reads as "expired".
func Until(at, now time.Time) string {
	if !at.After(now) {
		return "expired"
	}
	switch remaining := at.Sub(now); {
	case remaining < time.Hour:
		return "in " + plural(int(remaining.Minutes()), "minute")
	case remaining < 24*time.Hour:
		return "in " + plural(int(remaining.Hours()), "hour")
	case remaining < 30*24*time.Hour:
		return "in " + plural(int(remaining.Hours()/24), "day")
	case remaining < 365*24*time.Hour:
		return "in " + plural(int(remaining.Hours()/(24*30)), "month")
	default:
		return "in " + plural(int(remaining.Hours()/(24*365)), "year")
	}
}

// Timestamp is an absolute instant, for screens where reconstructing what happened needs a fixed point.
func Timestamp(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format("2006-01-02 15:04 UTC")
}

// DefaultOverrideDays mirrors commands.DefaultOverrideDays; the api is the authority.
const DefaultOverrideDays = 30

// MaxOverrideDays mirrors commands.MaxOverrideDays.
const MaxOverrideDays = 365

func DefaultOverrideDaysText() string { return strconv.Itoa(DefaultOverrideDays) }

// MaxReviewNote mirrors the api's cap; the api remains the authority.
const MaxReviewNote = 2000
