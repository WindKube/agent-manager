// Package view holds the web role's view models.
//
// These types are the contract between a data source and the templ components.
// The web role never sees a store row: a CatalogPage is assembled by whatever
// implements web.CatalogSource — today a fixture, from US2 an apiclient call —
// and the components render nothing else.
package view

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Kind separates a portable plugin from a standalone skill (US3 scenarios 1-2).
type Kind string

const (
	KindPlugin Kind = "plugin"
	KindSkill  Kind = "skill"
)

// Label is the design's badge text for a kind.
func (k Kind) Label() string {
	if k == KindPlugin {
		return "Plugin"
	}
	return "Skill"
}

// Scan is the latest version's scan verdict.
type Scan string

const (
	ScanClean   Scan = "clean"
	ScanFlagged Scan = "flagged"
	ScanPending Scan = "pending"
)

// Label and Tone give the design's pill: clean to ok, flagged to dan, anything
// else to warn.
func (s Scan) Label() string {
	switch s {
	case ScanClean:
		return "Clean"
	case ScanFlagged:
		return "Flagged"
	default:
		return "Scanning"
	}
}

func (s Scan) Tone() string {
	switch s {
	case ScanClean:
		return "ok"
	case ScanFlagged:
		return "dan"
	default:
		return "warn"
	}
}

// Kind and Status filters are single-selection (FR-011). The strings are the
// design's chip labels, which are also what the URL and the datastar signals
// carry, so there is one spelling of each value end to end.
const (
	KindFilterAll     = "All"
	KindFilterPlugins = "Plugins"
	KindFilterSkills  = "Skills"

	StatusAll       = "All"
	StatusVerified  = "Verified"
	StatusCommunity = "Community"
	StatusFlagged   = "Flagged"
)

var (
	KindFilters   = []string{KindFilterAll, KindFilterPlugins, KindFilterSkills}
	StatusFilters = []string{StatusAll, StatusVerified, StatusCommunity, StatusFlagged}
)

// SortKey and SortDir back FR-014.
type SortKey string

const (
	SortName    SortKey = "name"
	SortUses    SortKey = "uses"
	SortUpdated SortKey = "updated"
)

type SortDir string

const (
	DirDesc SortDir = "desc"
	DirAsc  SortDir = "asc"
)

// Arrow is the glyph appended to the active column header only.
func (d SortDir) Arrow() string {
	if d == DirAsc {
		return " ↑"
	}
	return " ↓"
}

// DefaultPageSize is what the design's catalog shows: its ten packages fit on
// one page. Paging is a plain server round trip.
const DefaultPageSize = 10

// CatalogQuery is one catalog request. Categories are disjunctive and Tags are
// conjunctive (FR-013) — the asymmetry is deliberate: categories widen a search,
// tags narrow it.
type CatalogQuery struct {
	Text       string
	Kind       string
	Status     string
	Categories []string
	Tags       []string
	Sort       SortKey
	Dir        SortDir
	Page       int
}

// Normalise fills the defaults so a zero query is the design's default view and
// a hostile query cannot ask for an unbounded page.
func (q CatalogQuery) Normalise() CatalogQuery {
	q.Text = strings.TrimSpace(q.Text)
	if !contains(KindFilters, q.Kind) {
		q.Kind = KindFilterAll
	}
	if !contains(StatusFilters, q.Status) {
		q.Status = StatusAll
	}
	switch q.Sort {
	case SortName, SortUses, SortUpdated:
	default:
		q.Sort = SortUses
	}
	if q.Dir != DirAsc {
		q.Dir = DirDesc
	}
	if q.Page < 1 {
		q.Page = 1
	}
	q.Categories = cleaned(q.Categories)
	q.Tags = cleaned(q.Tags)
	return q
}

// SortState reports the header state for one column: whether it is active, and
// the direction a click would select next (descending first, then ascending).
func (q CatalogQuery) SortState(key SortKey) (active bool, next SortDir, arrow string) {
	if q.Sort != key {
		return false, DirDesc, ""
	}
	if q.Dir == DirDesc {
		return true, DirAsc, q.Dir.Arrow()
	}
	return true, DirDesc, q.Dir.Arrow()
}

// Row is one catalog result. Tags belong to the latest version, not the package
// (data-model.md), so what lands here is already the latest version's set.
type Row struct {
	Key       string
	ID        string
	Name      string
	Publisher string
	Category  string
	Version   string
	Updated   string
	Kind      Kind
	Scan      Scan
	Uses      int
	Tags      []string
}

// Href is the row's link. The key is path-escaped: it comes from a package id,
// so a key containing "../" or a "?" must not be able to rewrite the URL.
func (r Row) Href() string { return "/packages/" + url.PathEscape(r.Key) }

// FacetOption is one checkbox in a facet menu. Count is what selecting this
// option would yield, so it responds to every other filter.
type FacetOption struct {
	Label    string
	Count    int
	Selected bool
}

// CatalogPage is one rendered page of results plus both facets.
type CatalogPage struct {
	Query      CatalogQuery
	Rows       []Row
	Total      int
	Page       int
	PageSize   int
	Categories []FacetOption
	Tags       []FacetOption
}

// Pages is the page count, at least one so the pager always has a current page.
func (p CatalogPage) Pages() int {
	size := p.PageSize
	if size < 1 {
		size = DefaultPageSize
	}
	if p.Total <= 0 {
		return 1
	}
	return (p.Total + size - 1) / size
}

// ResultCount is the design's live count line.
func (p CatalogPage) ResultCount() string {
	if p.Total == 1 {
		return "1 result"
	}
	return strconv.Itoa(p.Total) + " results"
}

// Empty backs the distinct empty state of FR-015.
func (p CatalogPage) Empty() bool { return len(p.Rows) == 0 }

// SelectedSummary is the facet trigger's summary text.
func SelectedSummary(selected []string) string {
	switch len(selected) {
	case 0:
		return "Any"
	case 1:
		return selected[0]
	default:
		return strconv.Itoa(len(selected)) + " selected"
	}
}

func contains(haystack []string, want string) bool {
	for _, v := range haystack {
		if v == want {
			return true
		}
	}
	return false
}

// cleaned drops blanks and duplicates and orders the result, so two queries that
// mean the same thing are the same query.
func cleaned(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
