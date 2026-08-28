package queries

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The catalog read (US2, research R4).
//
// Two statements, issued concurrently: one for the filtered page, one for the
// facet counts and the total. One statement would force either a GROUPING SETS
// monster or counting in Go over a full scan; two are simpler, independently
// cacheable, and the latency is max() rather than sum().
//
// They run against the BASE TABLES. `catalog_entry`, the one projection
// principle VIII sanctions, is not built: R12 makes it conditional on
// measurement, and catalog_bench_integration_test.go is that measurement.

// CatalogSort is the sortable column set of FR-014.
type CatalogSort string

const (
	CatalogSortName    CatalogSort = "name"
	CatalogSortUses    CatalogSort = "uses"
	CatalogSortUpdated CatalogSort = "updated"
)

// CatalogStatus is FR-011's status filter. The empty value is "All".
//
// Verified is BOTH conditions — a verified publisher AND a clean verdict (US2
// scenario 3). A verified publisher whose latest version is flagged is not
// Verified, which is the whole point of a status filter in a governance tool.
type CatalogStatus string

const (
	CatalogStatusAny       CatalogStatus = ""
	CatalogStatusVerified  CatalogStatus = "verified"
	CatalogStatusCommunity CatalogStatus = "community"
	CatalogStatusFlagged   CatalogStatus = "flagged"
)

// CatalogPageSize bounds are the design's page and a cap: the page size arrives
// from a client, and an unbounded one turns a paged read into a full dump.
const (
	DefaultCatalogPageSize = 10
	MaxCatalogPageSize     = 100
)

// maxTagOptions caps the tag facet's payload. Tags are free-form manifest
// keywords, so their cardinality is unbounded in a way categories' is not, and
// the whole option list is shipped to the browser when a menu opens (R7). The
// options dropped are the least common ones under the current filters.
const maxTagOptions = 200

// CatalogFilter is one catalog request.
//
// Categories narrow disjunctively and tags conjunctively (FR-013). The asymmetry
// looks like a bug until you read the requirement: a category widens a search
// ("infrastructure OR data"), a tag narrows it ("terraform AND aws").
type CatalogFilter struct {
	Text       string
	Kind       models.PackageKind
	Status     CatalogStatus
	Categories []string
	Tags       []string
	Sort       CatalogSort
	Ascending  bool
	Page       int
	PageSize   int
}

func (f CatalogFilter) normalise() CatalogFilter {
	f.Text = strings.TrimSpace(f.Text)
	switch f.Sort {
	case CatalogSortName, CatalogSortUses, CatalogSortUpdated:
	default:
		f.Sort = CatalogSortUses
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = DefaultCatalogPageSize
	}
	if f.PageSize > MaxCatalogPageSize {
		f.PageSize = MaxCatalogPageSize
	}
	f.Categories = distinct(f.Categories)
	f.Tags = distinct(f.Tags)
	return f
}

// maxSelections caps a facet selection. The list arrives from a client and each
// entry becomes a term in the statement, so an unbounded one turns a cheap filter
// into a statement whose size the caller chooses.
const maxSelections = 64

// Catalog answers one catalog request. db MUST be a pool and not a transaction:
// the two statements are issued concurrently, and a bun.Tx is a single
// connection that cannot serve both.
func Catalog(ctx context.Context, db bun.IDB, filter CatalogFilter) (contract.CatalogPage, error) {
	filter = filter.normalise()

	var (
		wait      sync.WaitGroup
		rows      []contract.CatalogPackage
		rowsErr   error
		facets    catalogFacets
		facetsErr error
	)
	wait.Add(2)
	go func() {
		defer wait.Done()
		rows, rowsErr = catalogRows(ctx, db, filter)
	}()
	go func() {
		defer wait.Done()
		facets, facetsErr = catalogFacetCounts(ctx, db, filter)
	}()
	wait.Wait()

	if err := errors.Join(rowsErr, facetsErr); err != nil {
		return contract.CatalogPage{}, err
	}

	// A page number that outran the result set is re-read at the last page rather
	// than answered with an empty table, so a stale `page` in a URL after a
	// narrowing filter shows results. The total comes from the facet statement,
	// so this is the only case that costs a third round trip.
	pages := (facets.Total + filter.PageSize - 1) / filter.PageSize
	if len(rows) == 0 && facets.Total > 0 && filter.Page > pages {
		filter.Page = pages
		if rows, rowsErr = catalogRows(ctx, db, filter); rowsErr != nil {
			return contract.CatalogPage{}, rowsErr
		}
	}

	return contract.CatalogPage{
		Packages:   rows,
		Total:      facets.Total,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
		Categories: facets.Categories,
		Tags:       facets.Tags,
	}, nil
}

// catalogFrom is the relation every catalog statement reads.
//
// A package reaches the catalog only through the version `latest_version_id`
// points at, and only while that version is visible. Both halves matter:
// commit-last (FR-008) means a half-published version exists as an invisible row,
// and a package whose only version is still being fetched has no pointer at all.
const catalogFrom = `
from package as pkg
join publisher as pub on pub.id = pkg.publisher_id
join version as ver on ver.id = pkg.latest_version_id and ver.visible
left join category as cat on cat.id = pkg.category_id`

// catalogID is the rendered package id, and it is NOT publisher.slug plus the
// name. Three concepts share two columns here:
//
//	namespace  first segment of publisher.slug — `example`, `community`
//	publisher  the whole slug, the owning team — `example/security`
//	name       the manifest name — `pii-redactor`
//
// The design renders `example/pii-redactor` (namespace/name) and internal/blob
// builds the same shape into the object key, so the id is namespace and name.
//
// It reads package.namespace rather than split_part(pub.slug, '/', 1) — the same
// string, but the column is held to the publisher's own first segment by a
// composite foreign key, so it cannot drift, and `unique (namespace, name)` makes
// the rendered id unique in the database rather than by convention. Deriving it
// with split_part would be a second definition of the id that nothing enforces
// against the first.
const catalogID = `pkg.namespace || '/' || pkg.name`

// catalogSearch is FR-010's search target: the needle must be a substring of ONE
// of name, id, publisher or a single tag.
//
// The obvious form — concatenate the four with spaces and match the whole string
// — matches across the joins between them, so `redactor example` finds
// `example/pii-redactor` by spanning the gap between its tags and its id. Nothing
// the reader typed is a substring of anything the catalog holds, and the result
// looks like the search is just bad at its job. Four predicates instead, and the
// tags one is an EXISTS over unnest so it cannot span two tags either.
//
// `position(lower(?) in ...)` rather than ILIKE because the needle is user input
// and `%` and `_` are ILIKE wildcards: escaping them is one more thing to get
// wrong, and FR-010 asks for a substring, not a pattern. The id and the publisher
// are separate terms because they are different strings — `example/pii-redactor`
// against `example/security`; the name needs no term of its own because the id
// ends with it.
const catalogSearch = `(
     position(lower(?) in lower(` + catalogID + `)) > 0
  or position(lower(?) in lower(pub.slug)) > 0
  or position(lower(?) in lower(pub.display_name)) > 0
  or exists (select 1 from unnest(ver.tags) as tag where position(lower(?) in lower(tag)) > 0)
)`

// predicates accumulates a WHERE clause and its arguments in step, so a clause
// can never drift out of order from the argument it consumes.
type predicates struct {
	clauses []string
	args    []any
}

func (p *predicates) add(clause string, args ...any) {
	p.clauses = append(p.clauses, clause)
	p.args = append(p.args, args...)
}

func (p *predicates) where() string {
	if len(p.clauses) == 0 {
		return ""
	}
	return "where " + strings.Join(p.clauses, "\n  and ")
}

// baseFilters is everything except the two facets: the filters that constrain
// both the result set AND every facet count.
// `visibility = 'organisation'` is unconditional, and that is a recorded
// limitation rather than a policy.
//
// The column has three values and the table names neither an owning team nor an
// owning identity, so `team` and `private` cannot be evaluated against a
// particular person — there is nothing to compare the caller to. Two readings
// were available and only one of them is safe: admit them (every member sees
// every private package) or exclude them (an entitled person is shown less than
// they could have been). A hub that leaks a private package is a worse failure
// than one that hides it, so this fails closed and `team` and `private` are
// currently invisible to EVERYONE, their publisher included.
//
// There is no caller-dependent branch here on purpose. One would have to key off
// something — the principal's identity, a role — and the schema offers nothing to
// key off, so any branch would be a guess wearing an access check. When `package`
// grows an owner, the comparison belongs here and this comment comes out.
func (f CatalogFilter) baseFilters() *predicates {
	p := &predicates{}
	p.add("pkg.visibility = 'organisation'")
	if f.Text != "" {
		p.add(catalogSearch, f.Text, f.Text, f.Text, f.Text)
	}
	switch f.Kind {
	case models.PackageKindPlugin, models.PackageKindSkill:
		p.add("pkg.kind = ?", f.Kind)
	}
	switch f.Status {
	case CatalogStatusVerified:
		// US2 scenario 3: both, not just the publisher flag. And read the column —
		// the `example` namespace is not the same claim as verified (data-model.md:
		// verified is admin-set and never inferred), so `slug like 'example/%'` is
		// the tempting shortcut that quietly makes a namespace into a trust badge.
		p.add("pub.verified and ver.verdict = 'clean'")
	case CatalogStatusCommunity:
		p.add("not pub.verified")
	case CatalogStatusFlagged:
		p.add("ver.verdict <> 'clean'")
	}
	return p
}

// categoryClause is FR-013's disjunctive half.
func (f CatalogFilter) categoryClause(alias string) (clause string, args []any) {
	if len(f.Categories) == 0 {
		return "", nil
	}
	return alias + " in (?)", []any{bun.List(f.Categories)}
}

// tagClause is FR-013's conjunctive half. `@>` is array containment, so every
// selected tag must be present — and it is the operator the tags GIN index
// answers, unlike `= any(...)`.
func (f CatalogFilter) tagClause(alias string) (clause string, args []any) {
	if len(f.Tags) == 0 {
		return "", nil
	}
	return alias + " @> ?::text[]", []any{pgdialect.Array(f.Tags)}
}

func (f CatalogFilter) orderBy() string {
	column := "coalesce(uses.n, 0)"
	switch f.Sort {
	case CatalogSortName:
		column = "pkg.name"
	case CatalogSortUpdated:
		column = "ver.created_at"
	}
	direction := "desc"
	if f.Ascending {
		direction = "asc"
	}
	// pkg.id last so a page boundary cannot repeat or drop a row when several
	// packages share a sort value — uuid v7 makes the tiebreak creation order.
	return "order by " + column + " " + direction + ", pkg.id"
}

// catalogRows is the page half of R4.
//
// `uses` is R8's number — profiles containing the package — aggregated once and
// joined, not counted per row: profile_entry's primary key is
// (profile_id, package_id), so there is no index on package_id alone and a
// correlated count would scan the table once per package.
func catalogRows(ctx context.Context, db bun.IDB, f CatalogFilter) ([]contract.CatalogPackage, error) {
	where := f.baseFilters()
	if clause, args := f.categoryClause("cat.name"); clause != "" {
		where.add(clause, args...)
	}
	if clause, args := f.tagClause("ver.tags"); clause != "" {
		where.add(clause, args...)
	}

	query := `
select
  ` + catalogID + `,
  pkg.name,
  pub.slug,
  pkg.kind::text,
  coalesce(cat.name, ''),
  ver.semver,
  ver.verdict::text,
  ver.tags,
  ver.created_at,
  coalesce(uses.n, 0)` + catalogFrom + `
left join (select package_id, count(*) as n from profile_entry group by package_id) as uses
       on uses.package_id = pkg.id
` + where.where() + `
` + f.orderBy() + `
limit ? offset ?`

	where.args = append(where.args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := db.QueryContext(ctx, query, where.args...)
	if err != nil {
		return nil, fmt.Errorf("read the catalog page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	packages := []contract.CatalogPackage{}
	for rows.Next() {
		entry := contract.CatalogPackage{Tags: []string{}}
		if err := rows.Scan(&entry.ID, &entry.Name, &entry.Publisher, &entry.Kind, &entry.Category,
			&entry.Version, &entry.Verdict, pgdialect.Array(&entry.Tags), &entry.UpdatedAt,
			&entry.Uses); err != nil {
			return nil, fmt.Errorf("scan a catalog row: %w", err)
		}
		if entry.Tags == nil {
			entry.Tags = []string{}
		}
		packages = append(packages, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the catalog page: %w", err)
	}
	return packages, nil
}

type catalogFacets struct {
	Total      int
	Categories []contract.CatalogFacetOption
	Tags       []contract.CatalogFacetOption
}

// catalogFacetCounts is the facet half of R4, and the two facets do NOT compute
// their counts the same way. The asymmetry follows FR-013's:
//
//   - Categories are disjunctive, so the count is taken with the category filter
//     REMOVED. Otherwise every unselected category reads zero and the menu tells
//     the reader nothing about the filter they are building.
//   - Tags are conjunctive, so the count is a drill-down: it keeps the tag filter
//     on and reports how many of the CURRENT results also carry this tag. That is
//     exactly what selecting it yields. Removing the tag filter here — the rule
//     that is right for the disjunctive facet — would overstate every option by
//     the size of the intersection the reader is about to lose.
//
// The total rides the same statement because it is the same scan.
func catalogFacetCounts(ctx context.Context, db bun.IDB, f CatalogFilter) (catalogFacets, error) {
	base := f.baseFilters()
	categoryClause, categoryArgs := f.categoryClause("base.category")
	tagOnBase, tagOnBaseArgs := f.tagClause("base.tags")
	tagOnJoin, tagOnJoinArgs := f.tagClause("counted.tags")

	// The argument order below is the order the placeholders appear in the
	// statement, which is the only thing that keeps a hand-assembled query honest.
	args := append([]any{}, base.args...)
	args = append(args, categoryArgs...)
	args = append(args, tagOnBaseArgs...)
	args = append(args, tagOnJoinArgs...)

	query := `
with base as (
  select pkg.id as package_id, pkg.category_id, coalesce(cat.name, '') as category, ver.tags` +
		catalogFrom + `
  ` + base.where() + `
),
scoped as (
  select * from base
  ` + andWhere(categoryClause, tagOnBase) + `
),
categories as (
  select cat.id::text as ord, cat.name as value, count(counted.package_id) as n
  from category as cat
  left join base as counted
    on counted.category_id = cat.id` + andJoin(tagOnJoin) + `
  group by cat.id, cat.name
),
tags as (
  select tag as value, count(*) as n
  from (select unnest(tags) as tag from scoped) as exploded
  group by tag
  order by count(*) desc, tag asc
  limit ` + fmt.Sprint(maxTagOptions) + `
)
select 'total', '', (select count(*) from scoped), null
union all
select 'category', value, n, ord from categories
union all
select 'tag', value, n, null from tags`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return catalogFacets{}, fmt.Errorf("read the catalog facets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		facets     catalogFacets
		categories []facetRow
	)
	for rows.Next() {
		var (
			facet string
			value string
			count int
			ord   *string
		)
		if err := rows.Scan(&facet, &value, &count, &ord); err != nil {
			return catalogFacets{}, fmt.Errorf("scan a catalog facet: %w", err)
		}
		switch facet {
		case "total":
			facets.Total = count
		case "category":
			order := ""
			if ord != nil {
				order = *ord
			}
			categories = append(categories, facetRow{order: order,
				option: contract.CatalogFacetOption{Value: value, Count: count}})
		case "tag":
			facets.Tags = append(facets.Tags, contract.CatalogFacetOption{Value: value, Count: count})
		}
	}
	if err := rows.Err(); err != nil {
		return catalogFacets{}, fmt.Errorf("read the catalog facets: %w", err)
	}

	// The vocabulary is admin-curated (FR-049) and the table carries no position
	// column, so curated order is the order the categories were created. uuid v7
	// sorts by creation, which is what makes that recoverable at all.
	sort.Slice(categories, func(i, j int) bool { return categories[i].order < categories[j].order })
	facets.Categories = make([]contract.CatalogFacetOption, 0, len(categories))
	for _, row := range categories {
		facets.Categories = append(facets.Categories, row.option)
	}

	// Ranked by count to choose which tags survive maxTagOptions, then listed
	// alphabetically: the menu is typed into, not scanned by popularity.
	sort.Slice(facets.Tags, func(i, j int) bool { return facets.Tags[i].Value < facets.Tags[j].Value })
	if facets.Tags == nil {
		facets.Tags = []contract.CatalogFacetOption{}
	}
	return facets, nil
}

type facetRow struct {
	order  string
	option contract.CatalogFacetOption
}

func andWhere(clauses ...string) string {
	kept := nonEmpty(clauses)
	if len(kept) == 0 {
		return ""
	}
	return "where " + strings.Join(kept, " and ")
}

func andJoin(clauses ...string) string {
	kept := nonEmpty(clauses)
	if len(kept) == 0 {
		return ""
	}
	return " and " + strings.Join(kept, " and ")
}

func nonEmpty(clauses []string) []string {
	kept := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		if clause != "" {
			kept = append(kept, clause)
		}
	}
	return kept
}

// distinct drops blanks and duplicates and orders what is left, so two requests
// that mean the same thing produce the same statement.
func distinct(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > maxSelections {
		out = out[:maxSelections]
	}
	return out
}
