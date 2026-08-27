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
type NavItem struct {
	ID    string
	Label string
	Href  string
	Badge string
	// Alert renders the badge in --dan. The scanner's open-findings count is the
	// only badge the design colours.
	Alert bool
}

// NavGroup is one labelled block of sidebar entries.
type NavGroup struct {
	Label string
	Items []NavItem
}

// Nav is the design's sidebar (docs/design/agent-manager.dc.html lines 938-943).
// The badge counts are the design's seed values; the layer that owns each screen
// replaces them with real ones.
var Nav = []NavGroup{
	{Label: "Workspace", Items: []NavItem{
		{ID: "catalog", Label: "Catalog", Href: "/catalog", Badge: "10"},
		{ID: "profiles", Label: "Profiles", Href: "/profiles", Badge: "4"},
	}},
	{Label: "Security", Items: []NavItem{
		{ID: "scanner", Label: "Scanner", Href: "/scanner", Badge: "4", Alert: true},
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
