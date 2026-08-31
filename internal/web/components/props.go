// Package components holds the templ components of the web role.
//
// FR-055 lives here by construction: templ escapes every interpolated value, and
// nothing in this package calls templ.Raw. Package-derived text — a name, an id,
// a manifest keyword rendered as a tag — reaches the page only through templ's
// escaping, and internal/archcheck fails the build if templ.Raw appears under
// internal/web at all.
package components

import (
	"encoding/json"
	"strconv"

	"agent-manager/internal/web/view"
)

// NavItem is one sidebar entry.
//
// It carries no count. The counts are per-viewer and per-request and live on the
// Shell, because a badge on a package-level var is a badge that is the same number
// for everybody who ever loads the page — which is what FR-121 is about, and what
// the design's compiled-in 10 / 4 / 4 were.
type NavItem struct {
	ID    string
	Label string
	Href  string
	// Alert renders the badge in --dan. The scanner's open-findings count is the
	// only badge the design colours.
	Alert bool
}

// NavGroup is one labelled block of sidebar entries.
type NavGroup struct {
	Label string
	Items []NavItem
}

// Nav is the design's sidebar (docs/design/agent-manager.dc.html lines 938-943),
// and it is the STRUCTURE only. What each entry counts is Shell.Badge's answer for
// that entry's id, resolved per request from the api.
var Nav = []NavGroup{
	{Label: "Workspace", Items: []NavItem{
		{ID: "catalog", Label: "Catalog", Href: "/catalog"},
		{ID: "profiles", Label: "Profiles", Href: "/profiles"},
	}},
	{Label: "Security", Items: []NavItem{
		{ID: "scanner", Label: "Scanner", Href: "/scanner", Alert: true},
		{ID: "audit", Label: "Audit log", Href: "/audit"},
	}},
	{Label: "Administration", Items: []NavItem{
		{ID: "storage", Label: "Storage", Href: "/storage"},
		{ID: "org", Label: "Organization", Href: "/org"},
	}},
	{Label: "Onboarding", Items: []NavItem{
		{ID: "cli", Label: "Connect the CLI", Href: "/cli"},
	}},
}

// ProductName is what this product calls itself.
//
// A constant because two surfaces render it — the sidebar's brand and the sign-in
// screen — and because the identity sweep next to internal/web's contrast test
// has to exempt exactly one pair of capitalised words from "that is a person's
// name". An exemption that is a constant is one identifier; an exemption that is
// a spelling is a place for a second one to be added quietly.
const ProductName = "Agent Manager"

// Shell is everything the layout needs that is not the screen itself.
type Shell struct {
	Title string
	// Theme is "light" or "dark" and is written to data-sm-theme on <html>, read
	// server-side so the first paint is already the right theme (FR-054).
	Theme string
	// Next is the theme a click on the toggle selects.
	Next string
	// Active is the NavItem.ID of the current screen.
	Active string
	// Return is the path the theme form comes back to. It is validated as a local
	// path before it reaches here.
	Return string
	// AppCSS, AppJS and VendorJS are content-addressed URLs, so the far-future
	// cache headers on /static are safe.
	AppCSS   string
	AppJS    string
	VendorJS string
	// Viewer is who this request resolved as, or nil when it resolved nobody.
	//
	// A pointer, with no default and no fallback (FR-116). The alternative — a
	// Viewer value — has a zero form that renders a chip with an empty name over an
	// empty role, which is the compiled-in chip again with its literals deleted:
	// still an identity no screen verified. nil renders no chip at all, so a caller
	// that forgets to resolve a viewer produces a page that is visibly missing
	// something rather than a page that is quietly lying.
	Viewer *view.Viewer
	// Badges are the sidebar's three counts as this request read them, or nil when
	// it could not. Nil renders no badges rather than three zeroes: a count of zero
	// is a fact about the hub and must be earned (FR-121).
	Badges *view.Badges
}

// Badge is the count beside one nav entry, and "" when there is none to show.
//
// Absent rather than zero, in both directions: nil badges are a request that could
// not read the counts, and a genuine zero is nothing worth a badge. The design
// draws a badge on three entries and the other four never had one.
func (s Shell) Badge(id string) string {
	if s.Badges == nil {
		return ""
	}
	var count int
	switch id {
	case "catalog":
		count = s.Badges.Packages
	case "profiles":
		count = s.Badges.Profiles
	case "scanner":
		count = s.Badges.OpenFindings
	default:
		return ""
	}
	if count <= 0 {
		return ""
	}
	return strconv.Itoa(count)
}

func (s Shell) ToggleIcon() string {
	if s.Theme == "dark" {
		return "☀"
	}
	return "☾"
}

// Facet is one multi-select facet menu.
type Facet struct {
	// Name is the URL and DOM identifier: "category" or "tag".
	Name string
	// Label is the trigger's text.
	Label string
	// Signal is the datastar signal holding the selection as a JSON array in a
	// string. Signal names without a leading underscore are sent to the server;
	// the filter text signals are underscored and never are, which is what makes
	// typing free.
	Signal string
	// QuerySignal is the client-only filter text signal.
	QuerySignal string
	Placeholder string
	// Mono renders option labels in IBM Plex Mono, as the design does for tags.
	Mono     bool
	Options  []view.FacetOption
	Selected []string
}

func (f Facet) OptionsID() string { return "facet-" + f.Name + "-options" }

func (f Facet) OptionsURL() string { return "/catalog/facet/" + f.Name }

func (f Facet) LabelClass() string {
	if f.Mono {
		return "am-opt-label am-mono"
	}
	return "am-opt-label"
}

// Catalog is the catalog screen's props.
type Catalog struct {
	Page     view.CatalogPage
	Category Facet
	Tags     Facet
	Import   Import
}

// Signals is the initial datastar signal state, JSON so it is both a valid
// datastar expression and safe: encoding/json escapes whatever arrived in the
// query string, and templ escapes the attribute around it.
func (c Catalog) Signals() string {
	q := c.Page.Query
	state := map[string]any{
		"q":      q.Text,
		"kind":   q.Kind,
		"status": q.Status,
		"cats":   jsonList(q.Categories),
		"tags":   jsonList(q.Tags),
		"sort":   string(q.Sort),
		"dir":    string(q.Dir),
		"page":   c.Page.Page,
		"menu":   "",
		// Client-only: the underscore prefix is datastar's convention for a signal
		// that is never sent to the server, which is the whole point of the facet
		// filter box.
		"_catQuery": "",
		"_tagQuery": "",
		// The registration modal's whole state, for the same reason: opening it,
		// switching tabs and attaching a file are client-side, so none of it is ever
		// sent and none of it can trigger the debounced round trip.
		"_importOpen":      false,
		"_importTab":       string(view.ImportUpload),
		"_importFile":      "",
		"_importURL":       "",
		"_importRef":       "",
		"_importSubdir":    "",
		"_importPublisher": "",
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func jsonList(values []string) string {
	if values == nil {
		values = []string{}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// The expressions below are built in Go rather than written inline so a facet's
// signal name appears once.

func (f Facet) ToggleMenuExpr() string {
	return "$menu = ($menu === '" + f.Name + "' ? '' : '" + f.Name + "'); $" + f.QuerySignal +
		" = ''; if ($menu === '" + f.Name + "') @get('" + f.OptionsURL() + "')"
}

func (f Facet) OpenExpr() string { return "$menu === '" + f.Name + "'" }

func (f Facet) ExpandedExpr() string {
	return "$menu === '" + f.Name + "' ? 'true' : 'false'"
}

// BindQuery is the signal name data-bind takes, unprefixed.
func (f Facet) BindQuery() string { return f.QuerySignal }

func (f Facet) ShowOptionExpr() string {
	return "amFuzzy($" + f.QuerySignal + ", el.dataset.label)"
}

func (f Facet) NoMatchExpr() string {
	return "amNoMatch(el, $" + f.QuerySignal + ")"
}

func (f Facet) OptionClassExpr() string {
	return "{'am-opt-on': amHas($" + f.Signal + ", el.dataset.label)}"
}

func (f Facet) OptionCheckedExpr() string {
	return "amHas($" + f.Signal + ", el.dataset.label) ? 'true' : 'false'"
}

func (f Facet) ToggleOptionExpr() string {
	return "$" + f.Signal + " = amToggle($" + f.Signal + ", el.dataset.label); $page = 1"
}

func (f Facet) SummaryExpr() string { return "amSummary($" + f.Signal + ")" }

func (f Facet) SummaryClassExpr() string {
	return "{'am-facet-summary-on': amAny($" + f.Signal + ")}"
}

func (f Facet) ClearExpr() string { return "$" + f.Signal + " = '[]'; $page = 1" }

// SortExpr is the click behaviour of a sortable column header: descending first,
// then ascending, computed from the state the server just rendered.
func SortExpr(q view.CatalogQuery, key view.SortKey) string {
	_, next, _ := q.SortState(key)
	return "$sort = '" + string(key) + "'; $dir = '" + string(next) + "'; $page = 1"
}

func SortClass(q view.CatalogQuery, key view.SortKey) string {
	if active, _, _ := q.SortState(key); active {
		return "am-sort am-sort-on"
	}
	return "am-sort"
}

func SortArrow(q view.CatalogQuery, key view.SortKey) string {
	_, _, arrow := q.SortState(key)
	return arrow
}

// ChipExpr selects a single-selection filter chip (FR-011).
func ChipExpr(signal, value string) string {
	return "$" + signal + " = '" + value + "'; $page = 1"
}

func ChipClassExpr(signal, value string) string {
	return "{'am-chip-on': $" + signal + " === '" + value + "'}"
}

// PageExpr moves the pager. Paging is a plain server round trip, like sorting and
// the chips: only the facet menus keep state on the client.
func PageExpr(page int) string {
	return "$page = " + strconv.Itoa(page)
}

// KindClass and ScanClass map a row's kind and verdict onto the design's pills.
func KindClass(kind view.Kind) string {
	if kind == view.KindPlugin {
		return "am-kind am-kind-plugin"
	}
	return "am-kind"
}

func ScanClass(scan view.Scan) string {
	return "am-scan am-scan-" + scan.Tone()
}

// ---- the registration modal --------------------------------------------------

// Import is the modal's props. It is a distinct type from view.Import so a
// component signature never becomes the place a new field is added silently.
type Import struct {
	Categories []string
	Preview    *view.ImportPreview
	// Result is the outcome of a submission, when there has been one.
	Result *view.ImportResult
}

// The modal's two round trips. Both are user-initiated — attaching a file and
// pressing the button — so neither is reachable from a signal patch, which is
// what keeps the R7 budget the underscore-prefixed signals establish.
//
// `contentType: 'form'` is what makes datastar send a FormData body rather than
// the signal JSON, and the selector names the form rather than relying on
// closest(): the submit control is a sibling of the fields, not a descendant of
// anything that would make closest() obvious.
const importFormSelector = "#import-form"

// ImportAttachExpr previews the attached archive. The guard matters: clearing a
// file picker also fires change, and posting an empty archive would answer FR-005
// with a report about nothing.
func ImportAttachExpr() string {
	return "$_importFile = el.files.length ? el.files[0].name : ''; " +
		"if (el.files.length) @post('/catalog/import/preview', {contentType: 'form', selector: '" +
		importFormSelector + "'})"
}

func ImportSubmitExpr() string {
	return "@post('/catalog/import', {contentType: 'form', selector: '" + importFormSelector + "'})"
}

// ImportSubmitDisabledExpr is T046's disabled-until-attached submit. It applies
// to the upload tab only: the URL tab has nothing to attach.
func ImportSubmitDisabledExpr() string {
	return "$_importTab === '" + string(view.ImportUpload) + "' && $_importFile === '' ? 'disabled' : null"
}

// ImportResultClass tones the outcome banner. A refusal is --dan and an
// acknowledgement is --warn, not --ok: a 202 means the fetch is queued, and
// nothing has been scanned yet (FR-008).
func ImportResultClass(result view.ImportResult) string {
	if result.Registered {
		return "am-import-note am-import-note-warn"
	}
	return "am-import-note am-import-note-dan"
}

// ImportTabExpr selects a tab. It touches one signal and that signal is
// underscore-prefixed, so switching tabs costs no round trip. The tab id is a
// constant from view, never user text, which is why it is quoted the same way
// ChipExpr quotes a filter value.
func ImportTabExpr(tab view.ImportTab) string {
	return "$_importTab = '" + string(tab) + "'"
}

func ImportTabClassExpr(tab view.ImportTab) string {
	return "{'am-chip-on': $_importTab === '" + string(tab) + "'}"
}

func ImportTabSelectedExpr(tab view.ImportTab) string {
	return "$_importTab === '" + string(tab) + "' ? 'true' : 'false'"
}

// ImportMarkStyle is the mark column's colour. The tone comes from the entry
// rather than from the caller so a kept file and a dropped one cannot be given
// the same glyph and different colours.
func ImportMarkStyle(entry view.ImportEntry) string {
	return "width:12px;flex:0 0 12px;font-size:11px;color:var(--" + entry.Tone() + ")"
}

// ---- the two governance screens ----------------------------------------------

// tone maps a view model's tone onto the four the stylesheet paints, and refuses
// anything else.
//
// The guard is not paranoia about the call sites — every tone on these screens is
// produced by a method in internal/web/view over a closed switch. It is here
// because these classes are the one place a value derived from api data reaches a
// class attribute rather than a text node, and templ escapes the attribute but
// cannot know that `am-pill-` plus a rule pack's string is not a class this
// stylesheet has ever heard of. An unknown tone renders neutral, which is legible
// in both themes; a passed-through one renders unstyled, which is not.
func tone(want string) string {
	switch want {
	case "ok", "warn", "dan":
		return want
	default:
		return "neutral"
	}
}

// PillClass is the shared pill: severity, finding state, version verdict and audit
// kind are all one shape in the design, so they are one class here and the tone is
// what separates them.
func PillClass(want string) string { return "am-pill am-pill-" + tone(want) }

func SeverityClass(severity view.Severity) string { return PillClass(severity.Tone()) }

func FindingStateClass(state view.FindingState) string { return PillClass(state.Tone()) }

func VerdictClass(verdict view.Verdict) string { return PillClass(verdict.Tone()) }

func AuditKindClass(row view.AuditRow) string { return PillClass(row.KindTone()) }

// CheckMarkClass colours the matrix's glyph. The glyph itself already carries the
// result, so the colour is reinforcement rather than the only signal.
func CheckMarkClass(check view.Check) string {
	return "am-chk-mark am-chk-mark-" + tone(check.Result.Tone())
}

// StatValueClass tones one headline figure. An untoned figure reads in --fg, which
// is the design's default for the two that are counts rather than warnings.
func StatValueClass(card view.StatCard) string {
	if card.Tone == "" {
		return "am-stat-value"
	}
	return "am-stat-value am-stat-value-" + tone(card.Tone)
}

// NoticeClass tones the banner a decision leaves behind.
func NoticeClass(notice view.Notice) string {
	return "am-gov-notice am-gov-notice-" + tone(notice.Tone)
}

// ReviewNoteLimit is the note field's maxlength, as a string for the attribute. It
// mirrors the api's cap so a reviewer is stopped while typing rather than after
// submitting; the api is still what decides.
func ReviewNoteLimit() string { return strconv.Itoa(view.MaxReviewNote) }
