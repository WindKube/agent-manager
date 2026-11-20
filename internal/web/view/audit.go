package view

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The audit log screen's view models (US4; 001 FR-050 through FR-052).
//
// One row per state-changing action, append-only, and the export is the whole
// current scope rather than the visible page. Nothing here paginates or filters in
// Go: the api does both, and a second implementation of either is how a screen and
// an export start disagreeing about what "the current scope" was.

// ActorKindSystem is the value the api sends for a row nobody signed in for. The
// two system actors are `fetcher` and `scanner` (001 FR-050).
const ActorKindSystem = "system"

// AuditRow is one entry.
type AuditRow struct {
	ID string
	// At is the absolute instant, formatted. Absolute rather than relative: this is
	// the screen somebody reads when reconstructing an incident, and two rows an
	// hour apart both reading "yesterday" is exactly the wrong answer there.
	At    string
	Actor string
	// System is whether the actor is a process rather than a person. Carried from
	// the api's actor_kind rather than inferred from the name, because a screen that
	// guessed would sooner or later attribute a machine's action to somebody.
	System bool
	Kind   string
	// Text quotes package, profile and host names a publisher chose, so it is
	// escaped on render like everything else (001 FR-055).
	Text   string
	Source string

	// The subject, empty on rows written before the api recorded one.
	SubjectKind string
	SubjectID   string
	Namespace   string
	// Package is the namespace/name a package, version or finding row is about.
	Package string
}

// PackageHref links a row about a package, or one of its versions or
// findings, to that package's page; empty for any other row.
func (r AuditRow) PackageHref() string {
	if _, _, ok := SplitPackageID(r.Package); !ok {
		return ""
	}
	return PackageHref(r.Package)
}

// SubjectLabel names the row's subject for the detail panel.
func (r AuditRow) SubjectLabel() string {
	if r.SubjectKind == "" {
		return "Not recorded"
	}
	return r.SubjectKind + " " + r.SubjectID
}

// AuditPage is one page of the audit log.
type AuditPage struct {
	Rows     []AuditRow
	Total    int
	Page     int
	PageSize int
}

// ActorNote labels a machine actor. A person's row gets nothing: the actor column
// carrying a name IS the statement, and annotating it would be noise on every row.
func (r AuditRow) ActorNote() string {
	if r.System {
		return "system"
	}
	return ""
}

// SourceLabel keeps the column honest when the api recorded no source. An em dash
// says "not recorded"; an empty cell reads as a rendering bug.
func (r AuditRow) SourceLabel() string {
	if r.Source == "" {
		return "—"
	}
	return r.Source
}

// SourceDetail spells out what SourceLabel leaves as a dash: alone in a panel a
// dash reads as a rendering bug rather than as "not recorded".
func (r AuditRow) SourceDetail() string {
	if r.Source == "" {
		return "Not recorded"
	}
	return r.Source
}

// KindTone colours the badge. The vocabulary is the api's and it grows, so
// anything unrecognised gets the neutral badge rather than no badge — a kind this
// screen has not been taught is still a kind, and hiding it would hide the row's
// whole subject.
func KindTone(kind string) string {
	switch kind {
	case "approve":
		return "ok"
	case "scan", "fetch":
		return "warn"
	case "reject":
		return "dan"
	default:
		return "neutral"
	}
}

func (r AuditRow) KindTone() string { return KindTone(r.Kind) }

// DefaultAuditPageSize mirrors the api's own default, used only to keep the pager
// honest before the first answer arrives.
const DefaultAuditPageSize = 50

// AuditFilter narrows the log to one subject or one package namespace. The
// api applies it; the screen only carries it from link to link.
type AuditFilter struct {
	SubjectKind string
	SubjectID   string
	Namespace   string
}

// auditSubjectKinds is the api's vocabulary; anything else off a URL is dropped
// rather than sent on to be refused.
var auditSubjectKinds = []string{
	"package", "version", "finding", "profile", "revision",
	"category", "mapping", "policy", "identity", "device", "service-token",
}

// maxAuditFilterLength mirrors the api's own bound on subjectId and namespace.
const maxAuditFilterLength = 200

func (f AuditFilter) normalise() AuditFilter {
	f.SubjectKind = strings.TrimSpace(f.SubjectKind)
	f.SubjectID = strings.TrimSpace(f.SubjectID)
	f.Namespace = strings.TrimSpace(f.Namespace)
	if !slices.Contains(auditSubjectKinds, f.SubjectKind) {
		f.SubjectKind = ""
	}
	if f.SubjectKind == "" || len(f.SubjectID) > maxAuditFilterLength {
		f.SubjectID = ""
	}
	if len(f.Namespace) > maxAuditFilterLength {
		f.Namespace = ""
	}
	return f
}

func (f AuditFilter) Active() bool { return f.SubjectKind != "" || f.Namespace != "" }

// Label is the filter chip's text.
func (f AuditFilter) Label() string {
	var parts []string
	if f.SubjectKind != "" {
		parts = append(parts, strings.TrimSpace(f.SubjectKind+" "+f.SubjectID))
	}
	if f.Namespace != "" {
		parts = append(parts, "namespace "+f.Namespace)
	}
	return strings.Join(parts, ", ")
}

func (f AuditFilter) values() url.Values {
	values := url.Values{}
	if f.SubjectKind != "" {
		values.Set("subjectKind", f.SubjectKind)
	}
	if f.SubjectID != "" {
		values.Set("subjectId", f.SubjectID)
	}
	if f.Namespace != "" {
		values.Set("namespace", f.Namespace)
	}
	return values
}

// AuditHistoryHref is one package's history: its own rows and those about its
// versions and findings.
func AuditHistoryHref(packageID string) string {
	return "/audit?" + AuditFilter{SubjectKind: "package", SubjectID: packageID}.values().Encode()
}

// AuditQuery is one request for the screen: which page, which filter, and
// which of its rows is open in the detail panel.
type AuditQuery struct {
	Page   int
	Filter AuditFilter
	// Selected is a row id off the URL: untrusted text, only ever a query
	// value and never used to build a path, so bounded rather than validated.
	Selected string
}

// maxAuditIDLength bounds what a URL can push back into every row's href.
const maxAuditIDLength = 64

func (q AuditQuery) Normalise() AuditQuery {
	if q.Page < 1 {
		q.Page = 1
	}
	q.Selected = strings.TrimSpace(q.Selected)
	if len(q.Selected) > maxAuditIDLength {
		q.Selected = ""
	}
	q.Filter = q.Filter.normalise()
	return q
}

func (q AuditQuery) href(page int, entry string) string {
	values := q.Filter.values()
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if entry != "" {
		values.Set("entry", entry)
	}
	if len(values) == 0 {
		return "/audit"
	}
	return "/audit?" + values.Encode()
}

// EntryHref opens one row's detail panel without disturbing the page.
func (q AuditQuery) EntryHref(id string) string { return q.href(q.Page, id) }

// CloseHref is the page with no row open — the pager's own target, since
// closing the panel and turning the page land on the same place.
func (q AuditQuery) CloseHref() string { return q.href(q.Page, "") }

// PageHref is the pager's target, keeping the filter.
func (q AuditQuery) PageHref(page int) string { return q.href(page, "") }

// ExportHref is the export of the current scope: the filter, never the page.
func (q AuditQuery) ExportHref() string {
	values := q.Filter.values()
	if len(values) == 0 {
		return AuditExportHref
	}
	return AuditExportHref + "?" + values.Encode()
}

// Audit is the whole screen.
type Audit struct {
	Query    AuditQuery
	Rows     []AuditRow
	Total    int
	Page     int
	PageSize int

	// Selected is found on the page already read: AuditRow carries every field
	// the api's AuditEntry does. Missing is set when the id names no row here.
	Selected *AuditRow
	Missing  bool

	// The three states that are not a page of rows, each with its own copy and its
	// own markup id (FR-122). 001 FR-052 makes the last of them matter more here
	// than anywhere else: this table is append-only, so an audit log rendered as
	// empty is a claim that nothing has ever happened in this hub.
	GovernanceState

	// ExportAvailable is whether the screen may offer the download at all: only
	// beside rows that could be read, rather than offered and broken.
	ExportAvailable bool
}

func (a Audit) Pages() int {
	size := a.PageSize
	if size < 1 {
		size = DefaultAuditPageSize
	}
	if a.Total <= 0 {
		return 1
	}
	return (a.Total + size - 1) / size
}

func (a Audit) CurrentPage() int {
	if a.Page < 1 {
		return 1
	}
	return a.Page
}

func (a Audit) Empty() bool { return len(a.Rows) == 0 }

// Count is the header's figure, and it counts nothing at all when the rows could
// not be read: "0 events" on an unreachable api is a claim about the hub.
func (a Audit) Count() string {
	switch {
	case !a.Readable():
		return ""
	case a.Total == 1:
		return "1 event"
	default:
		return strconv.Itoa(a.Total) + " events"
	}
}

// AuditPageHref is the pager's target.
func AuditPageHref(page int) string {
	if page <= 1 {
		return "/audit"
	}
	return "/audit?" + url.Values{"page": []string{strconv.Itoa(page)}}.Encode()
}

// AuditExportHref is the streamed export of 001 FR-051.
//
// It takes no page, and that is the requirement rather than a simplification:
// the export is the full current scope, so a link carrying the visible page's
// number would quietly export a screenful. AuditQuery.ExportHref adds the filter.
const AuditExportHref = "/audit/export"
