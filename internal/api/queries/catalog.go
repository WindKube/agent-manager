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
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The catalog read runs two concurrent statements, the page and the facet
// counts, so latency is max() rather than sum().

type CatalogSort string

const (
	CatalogSortName    CatalogSort = "name"
	CatalogSortUses    CatalogSort = "uses"
	CatalogSortUpdated CatalogSort = "updated"
)

// CatalogStatus is the status filter; the empty value is "All".
type CatalogStatus string

const (
	CatalogStatusAny       CatalogStatus = ""
	CatalogStatusVerified  CatalogStatus = "verified"
	CatalogStatusCommunity CatalogStatus = "community"
	CatalogStatusFlagged   CatalogStatus = "flagged"
)

// Catalog page size bounds; the size arrives from a client.
const (
	DefaultCatalogPageSize = 10
	MaxCatalogPageSize     = 100
)

// maxTagOptions caps the tag facet's payload: tags are free-form keywords
// with unbounded cardinality, and the whole list ships when a menu opens.
const maxTagOptions = 200

// CatalogFilter is one catalog request. Categories combine with OR, tags
// with AND.
type CatalogFilter struct {
	Principal  auth.Principal
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

// maxSelections caps a facet selection, so an unbounded list can't turn a
// cheap filter into a statement whose size the caller chooses.
const maxSelections = 64

// Catalog answers one catalog request. db must be a pool, not a
// transaction: the two statements run concurrently.
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

	// A page past the end is re-read at the last page rather than answered empty.
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

// catalogFrom is the relation every catalog statement reads; a half-published
// version is an invisible row, hence the `visible` join.
const catalogFrom = `
from package as pkg
join publisher as pub on pub.id = pkg.publisher_id
join version as ver on ver.id = pkg.latest_version_id and ver.visible
left join category as cat on cat.id = pkg.category_id`

// catalogID is the rendered package id, `namespace/name`, matching the shape
// internal/blob builds into the object key.
const catalogID = `pkg.namespace || '/' || pkg.name`

// catalogSearch matches each field separately, since a concatenation would
// match across field gaps. It uses position() rather than ILIKE because `%`
// and `_` in user input are ILIKE wildcards.
const catalogSearch = `(
     position(lower(?) in lower(` + catalogID + `)) > 0
  or position(lower(?) in lower(pub.slug)) > 0
  or position(lower(?) in lower(pub.display_name)) > 0
  or exists (select 1 from unnest(ver.tags) as tag where position(lower(?) in lower(tag)) > 0)
)`

// predicates accumulates WHERE clauses with their arguments so they stay in order.
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

// baseFilters constrains both the result set and every facet count.
func (f CatalogFilter) baseFilters() *predicates {
	p := &predicates{}
	readable, readableArgs := PackageReadable("pkg", f.Principal)
	p.add(readable, readableArgs...)
	if f.Text != "" {
		p.add(catalogSearch, f.Text, f.Text, f.Text, f.Text)
	}
	switch f.Kind {
	case models.PackageKindPlugin, models.PackageKindSkill:
		p.add("pkg.kind = ?", f.Kind)
	}
	switch f.Status {
	case CatalogStatusVerified:
		// Both conditions: a namespace alone must not act as a trust badge.
		p.add("pub.verified and ver.verdict = 'clean'")
	case CatalogStatusCommunity:
		p.add("not pub.verified")
	case CatalogStatusFlagged:
		p.add("ver.verdict <> 'clean'")
	}
	return p
}

func (f CatalogFilter) categoryClause(alias string) (clause string, args []any) {
	if len(f.Categories) == 0 {
		return "", nil
	}
	return alias + " in (?)", []any{bun.List(f.Categories)}
}

// tagClause uses `@>` so every selected tag must be present and the tags GIN
// index applies.
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
	// pkg.id last so a page boundary cannot repeat or drop a row when
	// several packages share a sort value.
	return "order by " + column + " " + direction + ", pkg.id"
}

// catalogRows is the page half of the catalog read. `uses` is aggregated once
// and joined because, with no index on package_id alone, a correlated count
// would scan the table per package.
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
  pkg.visibility::text,
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
		if err := rows.Scan(&entry.ID, &entry.Name, &entry.Publisher, &entry.Kind, &entry.Visibility,
			&entry.Category, &entry.Version, &entry.Verdict, pgdialect.Array(&entry.Tags), &entry.UpdatedAt,
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

// catalogFacetCounts counts categories with the category filter removed,
// otherwise every unselected option reads zero; tags keep the tag filter on
// as a drill-down.
func catalogFacetCounts(ctx context.Context, db bun.IDB, f CatalogFilter) (catalogFacets, error) {
	base := f.baseFilters()
	categoryClause, categoryArgs := f.categoryClause("base.category")
	tagOnBase, tagOnBaseArgs := f.tagClause("base.tags")
	tagOnJoin, tagOnJoinArgs := f.tagClause("counted.tags")

	// Argument order matches placeholder order in the statement below.
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

	// No position column, so curated order is creation order (uuid v7).
	sort.Slice(categories, func(i, j int) bool { return categories[i].order < categories[j].order })
	facets.Categories = make([]contract.CatalogFacetOption, 0, len(categories))
	for _, row := range categories {
		facets.Categories = append(facets.Categories, row.option)
	}

	// Ranked by count for maxTagOptions, then listed alphabetically.
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

// distinct drops blanks and duplicates and sorts, so equivalent requests
// produce the same statement.
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
