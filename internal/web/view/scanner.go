package view

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The Scanner screen's view models (US4; 001 FR-025 through FR-030).
//
// Everything the api returns as data becomes a sentence here and nowhere else.
// The hub hands over instants, counts and canonical vocabulary on purpose, so the
// relative dates, the formatted median and the pill tones are decided in this
// file against the reader's clock rather than baked into a response.
//
// Two vocabularies on this screen are NOT the same and are never collapsed: a
// finding's State — has a reviewer decided this — and the subject version's
// Verdict — what the scan concluded. An accept records an exception and leaves the
// version flagged, so a screen that showed one pill would tell a reader the
// package had become clean.

// Severity is a finding's severity as the rule pack states it.
//
// The three constants are what the pack can emit today. They are not an
// exhaustive enumeration and must not become one: rule ids and their severities
// are data the pack owns, a future pack can add either, and an unknown value
// renders as itself under the neutral tone rather than vanishing. That is also
// why this screen offers no severity filter — see Scanner.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Label is the pill's text. An unrecognised severity is shown under its own name:
// telling a reviewer a finding has a severity they have not seen before beats
// showing them a blank pill.
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

// FindingState is whether a reviewer has decided this finding. The scanner only
// ever writes `open`; the other two are written by the accept and reject paths.
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

// Tone deliberately does not paint an approved finding green. An override is a
// recorded exception with a reviewer's name on it, not a clean bill of health,
// and --ok on this pill is exactly the claim FR-124 and 001 FR-028 are about.
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

// Verdict is the SUBJECT VERSION's verdict, carried whole rather than collapsed
// onto Scan's three pills.
//
// Scan renders `rejected` as Flagged, which is right in the catalog — "do not
// adopt this without reading the finding" — and wrong here: on this screen the
// difference between a version awaiting a decision and one that has had a
// terminal one is the entire subject of the page.
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

// Mark is the glyph in the matrix's first column. It carries the result on its
// own, so the matrix is readable without relying on colour.
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

// Check is one check the scan ran, pass or fail.
//
// 001 FR-025: every check that ran is recorded so the absence of a finding is
// distinguishable from the absence of a check. The scanner writes a row for all
// seven on every scan, so this slice is the whole matrix and a screen renders it
// whole — filtering it to the failures produces a pane that cannot be told apart
// from one where nothing else ran, which is the distinction the matrix exists for.
type Check struct {
	ID     string
	Label  string
	Result CheckResult
	// WarnCount is a BLIND-SPOT counter, not a finding counter: today only the
	// shell audit sets it, to the number of scripts its parser could not read. See
	// Note for why it is never rendered as a number of issues.
	WarnCount int
}

// Note says what a non-zero WarnCount means, in words, because the number alone
// reads as "2 problems" and it is the opposite — two places the scan could not
// look. Zero is a genuine none and gets no note.
func (c Check) Note() string {
	if c.WarnCount == 0 {
		return ""
	}
	return plural(c.WarnCount, "file") + " this check could not read"
}

// Evidence is one location a finding points at.
//
// Path and Quote are bytes out of a package somebody else wrote. They are
// interpolated into the page and therefore escaped by templ, and nothing under
// internal/web may call templ.Raw (001 FR-055, enforced by internal/archcheck).
type Evidence struct {
	Path string
	// Line is 0 when the evidence names no line — a manifest-pointer hit. Line
	// numbers are 1-based, so 0 is unambiguous and saves a pointer.
	Line  int
	Quote string
}

// Location is the design's `scripts/digest.sh:41`, without the colon when there
// is no line to put after it.
func (e Evidence) Location() string {
	if e.Line <= 0 {
		return e.Path
	}
	return e.Path + ":" + strconv.Itoa(e.Line)
}

// FindingRow is one row of the findings list.
type FindingRow struct {
	ID       string
	RuleID   string
	Title    string
	Subject  string
	Severity Severity
	State    FindingState
	Verdict  Verdict
	// Raised is the relative phrase, rendered against the reader's clock.
	Raised string
}

// ScanMeta is the scan that raised the finding.
type ScanMeta struct {
	// PackVersion is `<declared>+<12 hex>` and is opaque: any rule edit moves the
	// suffix, which is why it is recorded per scan and shown here. Nothing splits
	// or parses it.
	PackVersion string
	Started     string
	Finished    string
	Verdict     Verdict
	// TimedOut is 001 FR-031. A scan that ran out of budget reached no judgement,
	// and its verdict must never be presented as a clean bill of health.
	TimedOut bool
}

// Override is the recorded acceptance of a finding.
type Override struct {
	Reviewer string
	Note     string
	Decided  string
	// Expires is "" when the override does not expire, which is a real state: the
	// api sends no expiry unless the reviewer stated one.
	Expires string
}

// FindingDetail is the detail pane.
type FindingDetail struct {
	FindingRow
	// Explanation is the rule pack's prose, and it ends with a sentence the scanner
	// assembled out of matched text. Bundle-adjacent, escaped like everything else.
	Explanation string
	// Primary is the finding's own denormalised location, rendered as the headline.
	// Nil when the scan recorded none — which the seed's findings all are, and which
	// is a state the pane says out loud rather than rendering as a blank panel.
	Primary *Evidence
	// Supporting are the remaining locations. The primary is deliberately not among
	// them: it is duplicated between the finding row and an evidence row, and a pane
	// that rendered both would show the first location twice.
	Supporting []Evidence
	Checks     []Check
	Scan       ScanMeta
	Override   *Override
	// Package links the subject back to the catalog.
	PackageID string
}

// CanAccept is FR-126 read against the finding rather than the viewer: a rejected
// finding is terminal, the api answers 409, and no audit row is written. Offering
// the control and then being refused is precisely what that requirement forbids.
func (d FindingDetail) CanAccept() bool { return d.State != FindingRejected }

// CanReject reports whether rejecting would change anything. A finding already
// rejected is not rejected twice.
func (d FindingDetail) CanReject() bool { return d.State != FindingRejected }

// TerminalNote is why neither control is offered, when neither is.
func (d FindingDetail) TerminalNote() string {
	if d.CanAccept() || d.CanReject() {
		return ""
	}
	return "This finding has been rejected. The version is quarantined for good and no " +
		"profile can resolve it, so there is nothing left to decide."
}

// Review is what this viewer may do on this screen, and why not when they may not.
//
// FR-126 wants the reason on the screen, so it is carried as text rather than as a
// boolean the component would have to invent copy for. Allowed is decided from the
// viewer's own resolved role and NOT from a previous refusal: a control that
// appears until the api says no has already been offered and refused.
type Review struct {
	Allowed bool
	Reason  string
}

// ScannerDecisionRoles are the roles that may accept or reject a finding.
//
// This MIRRORS internal/api/authz.go's scannerDecisionRoles, and the duplication
// is deliberate rather than careless: FR-126 requires the screen to know before it
// offers, and the web role may not import the api (internal/archcheck's allowlist,
// constitution principle II). The api stays authoritative — a refusal it sends is
// rendered as a refusal — so the worst a drift here can do is disable a control
// that would have worked, never offer one that would not.
//
// catalog-admin is here beside scanner-reviewer for the reason the api gives: role
// precedence puts catalog-admin above scanner-reviewer, and an ordering in which
// the higher role cannot do what the lower one can is not an ordering.
var ScannerDecisionRoles = []string{"scanner-reviewer", "catalog-admin"}

// ReviewFor decides what the viewer may do. There is no default viewer and there
// must not be one (FR-116): nobody resolved means nobody may decide.
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
	// Tone colours the figure: "" for the ordinary ramp, or ok/warn/dan.
	Tone string
}

// ScannerSummary is the headline card row, with its two nullable figures already
// rendered by the caller against the reader's clock.
type ScannerSummary struct {
	// PeriodDays comes from the api and is rendered rather than captioned: "last 30
	// days" written into the product would be exactly the constant FR-121 forbids.
	PeriodDays      int
	VersionsScanned int
	Quarantined     int
	OverridesActive int
	// NearestExpiry is the phrase for when the first active override lapses, and ""
	// when none does. An override with no expiry is a real state and reads as such.
	NearestExpiry string
	// MedianScan is "" when nothing finished in the window. That is NOT a median of
	// zero and must never render as one.
	MedianScan string
}

// Cards is the four figures the design's header row shows.
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
		// Not "0s". Nothing finishing in the window is a fact about the window, and a
		// zero here would read as a scanner that answers instantly.
		median.Value = "—"
		median.Note = "no scan finished in this window"
	}

	return []StatCard{scanned, quarantined, overrides, median}
}

// Finding state filters. The vocabulary is the api's own and is closed, which is
// what makes it safe to write as chips — unlike severity, whose values come from
// a rule pack that can add one.
const (
	FindingFilterAll      = "all"
	FindingFilterOpen     = "open"
	FindingFilterApproved = "approved"
	FindingFilterRejected = "rejected"
)

// FindingFilters is the chip row, in the order the design reads.
var FindingFilters = []string{
	FindingFilterAll, FindingFilterOpen, FindingFilterApproved, FindingFilterRejected,
}

// FindingFilterLabel is a filter as a person reads it.
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

// ScannerQuery is one request for the screen: which findings, which page, and
// which of them is open in the detail pane.
type ScannerQuery struct {
	State string
	Page  int
	// Selected is the finding id from the URL. It is untrusted text — a person can
	// edit it — and it is never used to build a path, only a query value, so it is
	// escaped rather than validated here. The hub turns a non-uuid into ErrNotFound
	// without a round trip.
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

// maxFindingIDLength bounds what is echoed back into a link. A uuid is 36
// characters; anything longer is not one, and carrying an unbounded string from a
// URL into every anchor on the page is how a query string becomes a payload.
const maxFindingIDLength = 64

// APIState is the filter in the api's vocabulary, where "" means no filter.
func (q ScannerQuery) APIState() string {
	if q.State == FindingFilterAll {
		return ""
	}
	return q.State
}

// Href is this screen at some other state, page or selection. Every link on the
// screen is built from the current query so that filtering does not silently drop
// the open finding and paging does not drop the filter.
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

// FilterHref is a chip's target: the filter changes, the page resets, and the
// selection is dropped because a finding excluded by the new filter is not on the
// list the pane sits beside.
func (q ScannerQuery) FilterHref(state string) string { return q.Href(state, 1, "") }

// SelectHref opens one finding without disturbing the list around it.
func (q ScannerQuery) SelectHref(id string) string { return q.Href(q.State, q.Page, id) }

// PageHref moves the list. The selection is kept: it is addressed by id, not by
// position, so it survives a page turn.
func (q ScannerQuery) PageHref(page int) string { return q.Href(q.State, page, q.Selected) }

// DecideHref is the form target for a decision on one finding, and the path it
// returns to afterwards.
func (q ScannerQuery) DecideHref(id, action string) string {
	if id == "" {
		return "/scanner"
	}
	return "/scanner/findings/" + url.PathEscape(id) + "/" + action
}

// Notice is the outcome of a decision, or a refusal, said once at the top of the
// screen. Tone is "ok", "warn" or "dan".
type Notice struct {
	Tone string
	Text string
}

// Scanner is the whole screen.
//
// There is no severity filter on it, and its absence is a decision rather than an
// omission. Severity values come from the rule pack: the pack ships no `low`
// today, a future one can add a value nothing here has seen, and the only thing
// this screen can observe is the severities on the page in front of it. A chip row
// derived from that would appear and disappear as a reader paged, and a fixed one
// would offer a filter that always yields nothing. Severity is shown on every row
// and in the pane instead.
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

	// Missing is a finding id in the URL that names nothing readable. It belongs to
	// the PANE rather than to the screen: the list beside it read perfectly well,
	// which is why it is not one of the three above.
	Missing bool
}

// GovernanceState is the three ways a governance screen ends up with no rows, and
// it is embedded in both of them so neither can grow a fourth spelling of one.
//
// Three booleans rather than one enum, because they are answers to three different
// questions and a screen that could only be in one of them would have to pick which
// truth to tell. FR-122 turns on their staying apart: an empty list, an
// authorisation refusal and an unreachable api ask their reader for completely
// different things, and only one of the three is fixed by signing in again.
type GovernanceState struct {
	// SignedOut is no usable session. It is a screen rather than a failure: the
	// screen is not the secret, only the rows are.
	SignedOut bool
	// Refused is the api declining to show THIS identity these rows. Signing in
	// again does not acquire a role, so this must never collapse onto SignedOut.
	Refused bool
	// Unavailable is the api not answering. It is not an empty hub, and rendering it
	// as one would present an outage as a system with nothing in it.
	Unavailable bool
}

// Readable reports whether anything could be read at all, which is what separates
// a count worth printing from a claim about the hub.
func (g GovernanceState) Readable() bool {
	return !g.SignedOut && !g.Refused && !g.Unavailable
}

// DefaultFindingsPageSize mirrors the api's own default, used only to keep the
// pager honest before the first answer arrives.
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

// CurrentPage is the page the api reported, defaulting to the first so the pager
// always has one.
func (s Scanner) CurrentPage() int {
	if s.Page < 1 {
		return 1
	}
	return s.Page
}

// Count is the list header's figure. Signed out it counts nothing rather than
// saying "0 findings", which would be a claim about the hub.
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

// Filtered reports whether the list is narrowed, which is what separates "this hub
// has no findings" from "this filter has none".
func (s Scanner) Filtered() bool { return s.Query.State != FindingFilterAll }

// Empty is the list having nothing in it, whatever the reason.
func (s Scanner) Empty() bool { return len(s.Findings) == 0 }

// Duration renders a scan time the way the design's figure reads. The wire carries
// fractional seconds, so this is the only place that decides how many of them a
// person sees.
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

// Until is Relative's other direction: how long until an instant, for an expiry.
//
// A lapsed expiry reads as "expired", not as a negative age. An override whose
// expiry is in the past is no longer an override, and rendering it as "in -2 days"
// would leave a reviewer working out the sign for themselves.
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

// Timestamp is an absolute instant as the audit log and the scan panel show one.
//
// Absolute, not relative, and in UTC: these two panels are what somebody reads
// when reconstructing what happened, and "2 days ago" cannot be lined up against
// anything. The catalog's Updated column is the opposite case and uses Relative.
func Timestamp(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format("2006-01-02 15:04 UTC")
}

// MaxReviewNote mirrors the api's own cap. The screen states it and enforces it so
// a reviewer is not told to rewrite a note after they have written it, but the api
// remains the thing that decides: a note that gets past this is still refused
// there, and this side never widens it.
const MaxReviewNote = 2000
