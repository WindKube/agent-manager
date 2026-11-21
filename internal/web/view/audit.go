package view

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The api paginates and filters the audit log; doing either here too would let the screen and the export
// disagree about the current scope.

// ActorKindSystem is the actor kind for a row written by a process rather than a person.
const ActorKindSystem = "system"

// AuditRow is one entry.
type AuditRow struct {
	ID string
	// At is absolute rather than relative, since this screen is read to reconstruct incidents.
	At    string
	Actor string
	// System comes from the api's actor_kind, never inferred from the name.
	System bool
	Kind   string
	Text   string
	Source string

	// SubjectKind and SubjectID are empty on rows written before the api recorded a subject.
	SubjectKind string
	SubjectID   string
	Namespace   string
	// Package is the namespace/name a package, version or finding row is about.
	Package string
}

// PackageHref links a row about a package, version or finding to the package's page.
func (r AuditRow) PackageHref() string {
	if _, _, ok := SplitPackageID(r.Package); !ok {
		return ""
	}
	return PackageHref(r.Package)
}

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

func (r AuditRow) ActorNote() string {
	if r.System {
		return "system"
	}
	return ""
}

func (r AuditRow) SourceLabel() string {
	if r.Source == "" {
		return "—"
	}
	return r.Source
}

func (r AuditRow) SourceDetail() string {
	if r.Source == "" {
		return "Not recorded"
	}
	return r.Source
}

// KindTone colours the badge; an unrecognised kind gets the neutral badge rather than none.
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

// DefaultAuditPageSize mirrors the api's default.
const DefaultAuditPageSize = 50

// AuditFilter narrows the log to one subject or package namespace; the api applies it.
type AuditFilter struct {
	SubjectKind string
	SubjectID   string
	Namespace   string
}

// auditSubjectKinds is the api's vocabulary; anything else off a URL is dropped.
var auditSubjectKinds = []string{
	"package", "version", "finding", "profile", "revision",
	"category", "mapping", "policy", "identity", "device", "service-token", "machine", "webhook",
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

// AuditHistoryHref is one package's history, including its versions and findings.
func AuditHistoryHref(packageID string) string {
	return "/audit?" + AuditFilter{SubjectKind: "package", SubjectID: packageID}.values().Encode()
}

// AuditQuery is one request for the screen: page, filter, and the row open in the detail panel.
type AuditQuery struct {
	Page   int
	Filter AuditFilter
	// Selected is untrusted URL text, only ever used as a query value, so it is bounded rather than validated.
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

func (q AuditQuery) EntryHref(id string) string { return q.href(q.Page, id) }

func (q AuditQuery) CloseHref() string { return q.href(q.Page, "") }

func (q AuditQuery) PageHref(page int) string { return q.href(page, "") }

// ExportHref exports the current scope: the filter, never the page.
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

	// Selected is looked up on the page already read; Missing is set when the id names no row here.
	Selected *AuditRow
	Missing  bool

	// GovernanceState matters most here: the log is append-only, so rendering an unreadable log as empty
	// would claim nothing ever happened.
	GovernanceState

	// ExportAvailable offers the download only beside rows that could be read.
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

// Count is empty when the rows could not be read, rather than claiming "0 events".
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

func AuditPageHref(page int) string {
	if page <= 1 {
		return "/audit"
	}
	return "/audit?" + url.Values{"page": []string{strconv.Itoa(page)}}.Encode()
}

// AuditExportHref is the streamed export. It deliberately takes no page: the export is the full current scope.
const AuditExportHref = "/audit/export"
