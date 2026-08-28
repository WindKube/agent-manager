// Package view holds the web role's view models.
//
// These types are the contract between a data source and the templ components.
// The web role never sees a store row: a CatalogPage is assembled by whatever
// implements web.CatalogSource — today a fixture, from US2 an apiclient call —
// and the components render nothing else.
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

// Href is the row's link, built from the ID rather than the Key: the detail
// screen is addressed by `namespace/name`, and Key is whatever the source chose
// to identify a row by. See PackageHref for why the id is validated and not
// merely escaped.
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

	// SignedOut is the third outcome, and it is neither of the other two. An
	// empty catalog is an answer; an unreachable api is a 502; this is a screen
	// that renders because the screen is not the secret — only the rows are.
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

// ResultCount is the design's live count line. Signed out it counts nothing
// rather than saying "0 results", which would be a claim about the catalog.
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

// Title is the display name of a package.
//
// It is DERIVED, and it has to be: `package.name` is the manifest name and
// matches `^[a-z0-9][a-z0-9.-]*$`, no column carries a human title, and neither
// Agent Plugins 1.0.0 nor Agent Skills defines one. Title-casing the hyphenated
// name recovers "Platform Toolkit" from "platform-toolkit"; it cannot recover an
// acronym, so the design's "PII Redactor" and "ADR Writer" render as "Pii
// Redactor" and "Adr Writer" until `package` grows a display name.
func Title(name string) string {
	words := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		// By rune, not by byte: the manifest name is untrusted input (principle III)
		// and word[:1] on a multi-byte first character renders as U+FFFD.
		first, size := utf8.DecodeRuneInString(word)
		words[i] = string(unicode.ToUpper(first)) + word[size:]
	}
	if len(words) == 0 {
		return name
	}
	return strings.Join(words, " ")
}

// Relative renders a timestamp the way the design's Updated column reads.
//
// The API returns an instant, not a phrase: which words express an age is a
// rendering decision, and a relative string is wrong the moment anything caches
// it. A future timestamp reads as "just now" rather than as a negative age —
// clock skew between the hub and a publisher is not something to render.
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

// ago is the age formatter Relative is built from, and it is NOT a pluraliser:
// every string it returns ends in "ago". It was called `plural` until the detail
// screen's origin line reused it for a component count and rendered "2 skills
// ago". The name is the fix — `plural` below does what that caller wanted.
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
// session, and it is a state to render rather than a failure to log.
//
// It lives here, beside the types the source's methods already speak, because
// both sides of that interface import this package and neither imports the
// other: internal/web declares the interface and internal/web/hub implements it
// over the generated client.
var ErrSignedOut = errors.New("no usable session")

// tokenKey carries the browser's session token from the request into the source.
type tokenKey struct{}

// WithToken puts the caller's own session token in the context.
//
// Constitution principle II: the web role holds no credential of its own, and
// there is none it could hold — auth.Sessions.Resolve is a lookup in the session
// table by hashed token, so a token exists only because a person signed in. Every
// api call the web role makes is therefore made AS the person, or not at all.
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
