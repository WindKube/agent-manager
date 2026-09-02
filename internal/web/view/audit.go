package view

import (
	"net/url"
	"strconv"
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

// Audit is the whole screen.
type Audit struct {
	Rows     []AuditRow
	Total    int
	Page     int
	PageSize int

	// The three states that are not a page of rows, each with its own copy and its
	// own markup id (FR-122). 001 FR-052 makes the last of them matter more here
	// than anywhere else: this table is append-only, so an audit log rendered as
	// empty is a claim that nothing has ever happened in this hub.
	GovernanceState

	// ExportAvailable is whether the screen may offer the download at all. False is
	// a hub with no audit source wired, which is a deployment fault rather than a
	// permission, and the action is then absent rather than offered and broken.
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
// It takes no page and no filter, and that is the requirement rather than a
// simplification: the export is the full current scope, so a link carrying the
// visible page's number would quietly export a screenful.
const AuditExportHref = "/audit/export"
