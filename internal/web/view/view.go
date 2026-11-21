// Package view holds the web role's view models: the contract between the hub client and the templ
// components. The web role never sees a store row.
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

// Kind and Status filters are single-selection; the chip labels are also what the URL and datastar signals carry.
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

func (d SortDir) Arrow() string {
	if d == DirAsc {
		return " ↑"
	}
	return " ↓"
}

const DefaultPageSize = 10

// CatalogQuery is one catalog request. Categories are disjunctive (widen) and Tags conjunctive (narrow), deliberately.
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

// Normalise fills defaults so a zero query is the default view and a hostile query is bounded.
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

// SortState reports whether a column is active and the direction a click selects next (descending first).
func (q CatalogQuery) SortState(key SortKey) (active bool, next SortDir, arrow string) {
	if q.Sort != key {
		return false, DirDesc, ""
	}
	if q.Dir == DirDesc {
		return true, DirAsc, q.Dir.Arrow()
	}
	return true, DirDesc, q.Dir.Arrow()
}

// Row is one catalog result. Tags are the latest version's.
type Row struct {
	Key        string
	ID         string
	Name       string
	Publisher  string
	Category   string
	Version    string
	Updated    string
	Kind       Kind
	Scan       Scan
	Visibility string
	Uses       int
	Tags       []string
}

// Href is built from ID, not Key: Key is whatever the source chose to identify a row by.
func (r Row) Href() string { return PackageHref(r.ID) }

func (r Row) VisibilityLabel() string { return visibilityLabels[r.Visibility] }

// FacetOption is one checkbox in a facet menu. Count is what selecting it would yield given the other filters.
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

	SignedOut bool
}

// Pages is at least one so the pager always has a current page.
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

// ResultCount says "Signed out" rather than claiming "0 results".
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

// CatalogNoticeFrom is a package delete's acknowledgement; it lands on the catalog because the deleted
// package's own page now 404s.
func CatalogNoticeFrom(raw, id string) *Notice {
	if raw != "package-deleted" {
		return nil
	}
	text := "Package deleted from the catalog."
	if id != "" {
		text = "Package " + id + " deleted from the catalog. An existing profile pin or a " +
			"published revision still resolves its versions."
	}
	return &Notice{Tone: "ok", Text: text}
}

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

// cleaned drops blanks and duplicates and sorts, so equivalent queries are equal.
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

// Title derives a display name from the manifest name, since none is stored. Acronyms are not recovered:
// "pii-redactor" renders as "Pii Redactor".
func Title(name string) string {
	words := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	for i, word := range words {
		// By rune, not byte, so a multi-byte first character survives.
		first, size := utf8.DecodeRuneInString(word)
		words[i] = string(unicode.ToUpper(first)) + word[size:]
	}
	if len(words) == 0 {
		return name
	}
	return strings.Join(words, " ")
}

// Relative renders an age against the reader's clock; a future timestamp reads as "just now".
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

func ago(n int, unit string) string {
	return plural(n, unit) + " ago"
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// ErrSignedOut means the caller has no usable session: a state to render, not a failure to log.
var ErrSignedOut = errors.New("no usable session")

type tokenKey struct{}

// WithToken puts the caller's session token in the context. The web role holds no credential of its own,
// so every api call is made as the person or not at all.
func WithToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, tokenKey{}, token)
}

func TokenFrom(ctx context.Context) string {
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}

// Badges are the sidebar's counts, scoped to the viewer. A nil *Badges means they could not be read,
// which must not render as zeroes.
type Badges struct {
	Packages     int
	Profiles     int
	OpenFindings int
}
