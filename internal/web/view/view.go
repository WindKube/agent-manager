// Package view holds the web role's view models: the contract between a
// data source and the templ components. The web role never sees a store
// row — a CatalogPage is assembled by whatever implements
// web.CatalogSource, and the components render nothing else.
package view

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kind separates a portable plugin from a standalone skill.
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

// Kind and Status filters are single-selection. The strings are the chip
// labels, also what the URL and datastar signals carry, so there is one
// spelling of each value end to end.
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

// CatalogQuery is one catalog request. Categories are disjunctive and Tags
// are conjunctive — the asymmetry is deliberate: categories widen a search,
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

// Row is one catalog result. Tags belong to the latest version, not the
// package, so what lands here is already the latest version's set.
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

// Href is the row's link, built from the ID rather than the Key: the detail
// screen is addressed by `namespace/name`, and Key is whatever the source
// chose to identify a row by.
func (r Row) Href() string { return PackageHref(r.ID) }

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

	// SignedOut is the third outcome: an empty catalog is an answer, an
	// unreachable api is a 502, and this renders because the screen is not
	// the secret — only the rows are.
	SignedOut bool
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

// ResultCount is the live count line. Signed out it counts nothing rather
// than "0 results", a claim about the catalog.
func (p CatalogPage) ResultCount() string {
	switch {
	case p.SignedOut:
		return "Signed out"
	case p.Total == 1:
		return "1 result"
	default:
		return strconv.Itoa(p.Total) + " results"
	}
}

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

// Title is the display name of a package. It is DERIVED: `package.name` is
// the manifest name and no column carries a human title. Title-casing the
// hyphenated name recovers "Platform Toolkit" from "platform-toolkit" but
// cannot recover an acronym, so "PII Redactor" renders as "Pii Redactor".
func Title(name string) string {
	words := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		// By rune, not byte: word[:1] on a multi-byte first character
		// renders as U+FFFD.
		first, size := utf8.DecodeRuneInString(word)
		words[i] = string(unicode.ToUpper(first)) + word[size:]
	}
	if len(words) == 0 {
		return name
	}
	return strings.Join(words, " ")
}

// Relative renders a timestamp as the Updated column reads it. The API
// returns an instant, not a phrase, since a relative string is wrong the
// moment anything caches it. A future timestamp reads as "just now" rather
// than a negative age.
func Relative(at, now time.Time) string {
	switch age := now.Sub(at); {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		return ago(int(age.Minutes()), "minute")
	case age < 24*time.Hour:
		return ago(int(age.Hours()), "hour")
	case age < 48*time.Hour:
		return "yesterday"
	case age < 7*24*time.Hour:
		return ago(int(age.Hours()/24), "day")
	case age < 30*24*time.Hour:
		return ago(int(age.Hours()/(24*7)), "week")
	case age < 365*24*time.Hour:
		return ago(int(age.Hours()/(24*30)), "month")
	default:
		return ago(int(age.Hours()/(24*365)), "year")
	}
}

// ago is the age formatter Relative is built from, and it is NOT a
// pluraliser: every string it returns ends in "ago".
func ago(n int, unit string) string {
	return plural(n, unit) + " ago"
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// ErrSignedOut is a CatalogSource reporting that the caller has no usable
// session, a state to render rather than a failure to log.
var ErrSignedOut = errors.New("no usable session")

// tokenKey carries the browser's session token from the request into the source.
type tokenKey struct{}

// WithToken puts the caller's own session token in the context. The web
// role holds no credential of its own, so every api call it makes is made
// AS the person, or not at all.
func WithToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, tokenKey{}, token)
}

// TokenFrom returns the caller's session token, or "" when there is none.
func TokenFrom(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}

// Badges are the sidebar's three counts, scoped to the viewer. A pointer to
// one of these is what the shell holds, and nil is a request that could not
// read them — not the same as three zeroes, which would render "0
// packages" beside a catalog full of them.
type Badges struct {
	Packages     int
	Profiles     int
	OpenFindings int
}
