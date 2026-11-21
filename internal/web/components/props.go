// Package components holds the templ components of the web role.
//
// templ escapes every interpolated value and nothing here calls templ.Raw, so
// package-derived text reaches the page only escaped; archcheck enforces this.
package components

import (
	"encoding/json"
	"strconv"

	"agent-manager/internal/web/view"
)

// NavItem is one sidebar entry.
//
// It carries no count: counts are per viewer and per request and live on Shell.
type NavItem struct {
	ID    string
	Label string
	Href  string
	// Alert renders the badge in --dan.
	Alert bool
}

// NavGroup is one labelled block of sidebar entries.
type NavGroup struct {
	Label string
	Items []NavItem
}

// Nav is the sidebar's structure only; counts come per request from Shell.Badge.
var Nav = []NavGroup{
	{Label: "Workspace", Items: []NavItem{
		{ID: "catalog", Label: "Catalog", Href: "/catalog"},
		{ID: "profiles", Label: "Profiles", Href: "/profiles"},
		{ID: "machines", Label: "Machines", Href: "/machines"},
	}},
	{Label: "Security", Items: []NavItem{
		{ID: "scanner", Label: "Scanner", Href: "/scanner", Alert: true},
		{ID: "audit", Label: "Audit log", Href: "/audit"},
	}},
	{Label: "Administration", Items: []NavItem{
		{ID: "storage", Label: "Storage", Href: "/storage"},
		{ID: "org", Label: "Organization", Href: "/org"},
		{ID: "webhooks", Label: "Webhooks", Href: "/webhooks"},
		{ID: "runtime", Label: "Runtime", Href: "/runtime"},
		{ID: "river", Label: "River Dashboard", Href: "/river"},
	}},
	{Label: "Onboarding", Items: []NavItem{
		{ID: "cli", Label: "Connect the CLI", Href: "/cli"},
		{ID: "tokens", Label: "Service tokens", Href: "/tokens"},
	}},
}

// ProductName is a constant so the identity sweep test can exempt exactly this
// one pair of capitalised words.
const ProductName = "Agent Manager"

// Shell is everything the layout needs that is not the screen itself.
type Shell struct {
	Title string
	// Theme is "light" or "dark", written to data-sm-theme server-side so the
	// first paint is already right.
	Theme  string
	Next   string
	Active string
	// Return is the path the theme form comes back to, already validated as local.
	Return string
	// AppCSS, AppJS and VendorJS are content-addressed, so far-future caching is safe.
	AppCSS   string
	AppJS    string
	VendorJS string
	// Viewer is who this request resolved as. A pointer with no fallback: nil
	// renders no chip, so a forgotten resolution is visibly missing rather than a
	// zero-value chip claiming an unverified identity.
	Viewer *view.Viewer
	// Badges are the request's sidebar counts, or nil when unreadable. Nil renders
	// no badges rather than zeroes, since a zero must be earned.
	Badges *view.Badges
	// NavGate is why an entry cannot be followed, keyed by NavItem.ID. A gated
	// entry renders disabled with its reason rather than vanishing, so readers know
	// the screen exists and can ask for access.
	NavGate map[string]string
}

// Badge is the count beside one nav entry, or "" for none, including a genuine zero.
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

// Gate is why this entry cannot be followed, and "" when it can.
func (s Shell) Gate(id string) string { return s.NavGate[id] }

func (s Shell) ToggleIcon() string {
	if s.Theme == "dark" {
		return "☀"
	}
	return "☾"
}

// Facet is one multi-select facet menu.
type Facet struct {
	Name  string
	Label string
	// Signal holds the selection as a JSON array in a string. It is sent to the
	// server; the underscored filter text signals never are, which keeps typing free.
	Signal string
	// QuerySignal is the client-only filter text signal.
	QuerySignal string
	Placeholder string
	Mono        bool
	Options     []view.FacetOption
	Selected    []string
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
	// Notice is a package delete's acknowledgement: the deleted package's own
	// page 404s, so the outcome is said here.
	Notice *view.Notice
}

// Signals is the initial datastar state as JSON: a valid datastar expression, with
// query-string input escaped by encoding/json and the attribute by templ.
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
		// Underscore-prefixed signals are never sent to the server, which is the
		// point of the client-side facet filter box.
		"_catQuery": "",
		"_tagQuery": "",
		// The registration modal's whole state is client-side, for the same reason.
		"_importOpen":      false,
		"_importTab":       string(view.ImportUpload),
		"_importFile":      "",
		"_importURL":       "",
		"_importRef":       "",
		"_importSubdir":    "",
		"_importPublisher": "",
		"_importName":      "",
		"_importVersion":   "",
		"_importKind":      "",
		"_importTags":      "",
		// Set by data-indicator while the submit request is in flight; declared so
		// the disabled expression has a value on first paint.
		"_importBusy": false,
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

// The expressions below are built in Go so a facet's signal name appears once.

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

// SortExpr toggles a sortable column: descending first, then ascending.
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

// ChipExpr selects a single-selection filter chip.
func ChipExpr(signal, value string) string {
	return "$" + signal + " = '" + value + "'; $page = 1"
}

func ChipClassExpr(signal, value string) string {
	return "{'am-chip-on': $" + signal + " === '" + value + "'}"
}

// PageExpr moves the pager. Paging is a server round trip; only the facet menus
// keep state on the client.
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

// SignatureClass reuses the scan badge's three tones.
func SignatureClass(signature view.VersionSignature) string {
	return "am-scan am-scan-" + signature.Tone()
}

// VisibilityClass tones the visibility badge; organisation, the neutral default,
// carries no modifier.
func VisibilityClass(visibility string) string {
	switch visibility {
	case "team", "private":
		return "am-vis am-vis-" + visibility
	default:
		return "am-vis"
	}
}

// ---- the registration modal --------------------------------------------------

// Import is the modal's props, distinct from view.Import so no field is added to a
// component signature silently.
type Import struct {
	Categories []string
	// Visibilities is computed by the handler, which holds the session; a
	// component has none to read groups from.
	Visibilities []view.ImportOption
	Preview      *view.ImportPreview
	Result       *view.ImportResult
}

// The modal's two round trips are user-initiated, so neither is reachable from a
// signal patch. `contentType: 'form'` makes datastar send FormData, and the
// selector names the form because the submit control is not inside it.
const importFormSelector = "#import-form"

// ImportAttachExpr previews the attached archive. Clearing a file picker also
// fires change, hence the guard against posting an empty archive.
func ImportAttachExpr() string {
	return "$_importFile = el.files.length ? el.files[0].name : ''; " +
		"if (el.files.length) @post('/catalog/import/preview', {contentType: 'form', selector: '" +
		importFormSelector + "'})"
}

func ImportSubmitExpr() string {
	return "@post('/catalog/import', {contentType: 'form', selector: '" + importFormSelector + "'})"
}

// ImportSubmitDisabledExpr disables submit until a file is attached (upload tab
// only) and while a request is in flight, which stops a duplicate registration.
func ImportSubmitDisabledExpr() string {
	return "$_importBusy || ($_importTab === '" + string(view.ImportUpload) +
		"' && $_importFile === '') ? 'disabled' : null"
}

// ImportBusySignal is set by data-indicator while registration is in flight.
const ImportBusySignal = "_importBusy"

// ImportKinds are the kind selector's options. The empty "detect" value is the
// default because the manifest at the tree root decides kind once fetched.
func ImportKinds() []view.ImportOption {
	return []view.ImportOption{
		{Value: "", Label: "Detect from the manifest"},
		{Value: "plugin", Label: "Plugin"},
		{Value: "skill", Label: "Skill"},
	}
}

// ImportTagsLimit is the tags maxlength attribute, mirroring
// view.MaxTagsFieldLength; the api still decides.
func ImportTagsLimit() string { return strconv.Itoa(view.MaxTagsFieldLength) }

// ImportResultClass tones the outcome banner. Acceptance is --warn, not --ok:
// a 202 means the fetch is queued and nothing has been scanned.
func ImportResultClass(result view.ImportResult) string {
	if result.Registered {
		return "am-import-note am-import-note-warn"
	}
	return "am-import-note am-import-note-dan"
}

// ImportTabExpr selects a tab via one underscore-prefixed signal, so it costs no
// round trip. The tab id is a view constant, never user text.
func ImportTabExpr(tab view.ImportTab) string {
	return "$_importTab = '" + string(tab) + "'"
}

func ImportTabClassExpr(tab view.ImportTab) string {
	return "{'am-chip-on': $_importTab === '" + string(tab) + "'}"
}

func ImportTabSelectedExpr(tab view.ImportTab) string {
	return "$_importTab === '" + string(tab) + "' ? 'true' : 'false'"
}

// ImportMarkStyle derives the colour from the entry, so glyph and colour cannot
// disagree.
func ImportMarkStyle(entry view.ImportEntry) string {
	return "width:12px;flex:0 0 12px;font-size:11px;color:var(--" + entry.Tone() + ")"
}

// ---- the two governance screens ----------------------------------------------

// tone maps a view model's tone onto the four the stylesheet paints. This is the
// one place api-derived values reach a class attribute, and templ cannot know an
// arbitrary `am-pill-` suffix is unstyled; an unknown tone renders neutral.
func tone(want string) string {
	switch want {
	case "ok", "warn", "dan":
		return want
	default:
		return "neutral"
	}
}

// PillClass is the shared pill for severity, finding state, verdict and audit kind.
func PillClass(want string) string { return "am-pill am-pill-" + tone(want) }

func SeverityClass(severity view.Severity) string { return PillClass(severity.Tone()) }

func FindingStateClass(state view.FindingState) string { return PillClass(state.Tone()) }

func VerdictClass(verdict view.Verdict) string { return PillClass(verdict.Tone()) }

func AuditKindClass(row view.AuditRow) string { return PillClass(row.KindTone()) }

// CheckMarkClass colours the matrix glyph, which already carries the result.
func CheckMarkClass(check view.Check) string {
	return "am-chk-mark am-chk-mark-" + tone(check.Result.Tone())
}

// StatValueClass tones one headline figure; untoned reads in --fg.
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

// ReviewNoteLimit is the note maxlength attribute, mirroring the api's cap so a
// reviewer is stopped while typing; the api still decides.
func ReviewNoteLimit() string { return strconv.Itoa(view.MaxReviewNote) }

// OutcomeClass tones a profile entry's gate outcome pill.
func OutcomeClass(outcome view.ProfileOutcome) string { return PillClass(outcome.Tone()) }

// StateRowClass tones the Runtime job-count rows; only retryable and discarded,
// whose presence is the concern, are coloured.
func StateRowClass(row view.StateRow) string {
	if row.Tone == "" {
		return "am-kv-val"
	}
	return "am-kv-val am-kv-val-" + tone(row.Tone)
}

// ---- catalog delete: package and version ---------------------------------

// PackageDeleteConfirmDisabledExpr disables delete until the typed text matches
// the package id. namespace/name is validated at registration, so it needs no JS
// string escaping.
func PackageDeleteConfirmDisabledExpr(id string) string {
	return "$_deletePkgConfirm !== '" + id + "' ? 'disabled' : null"
}

// VersionDeleteConfirmDisabledExpr is the same idiom with namespace/name@version.
func VersionDeleteConfirmDisabledExpr(id, version string) string {
	return "$_deleteVersionConfirm !== '" + id + "@" + version + "' ? 'disabled' : null"
}

// VersionDeleteToggleExpr opens one row's confirm form, closing any other and
// clearing the typed text so it cannot carry over.
func VersionDeleteToggleExpr(version string) string {
	return "$_deleteVersion = ($_deleteVersion === '" + version + "' ? '' : '" + version +
		"'); $_deleteVersionConfirm = ''"
}

// VersionDeleteFormStyleExpr uses data-style:display, not data-show: the form is
// display:flex, and data-show only removes display, leaving it block.
func VersionDeleteFormStyleExpr(version string) string {
	return "$_deleteVersion === '" + version + "' ? 'flex' : 'none'"
}
