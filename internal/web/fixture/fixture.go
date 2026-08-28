// Package fixture serves the design's catalog dataset in-process.
//
// It is the ONE stand-in in the web role: the US2 layer swaps this
// implementation of web.CatalogSource for an apiclient-backed one, because the
// api has no catalog operation yet (only the seven frozen CLI-facing ones), and
// an honest seam is better than a web role that reads a database.
//
// The rows are transcribed from docs/design/agent-manager.dc.html items() at
// lines 867-920. Only catalog-facing fields are carried: the design's manifests
// are non-conformant with Agent Plugins 1.0.0 (research R1) and are deliberately
// not reproduced anywhere.
package fixture

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"agent-manager/internal/web/view"
)

// Categories is the design's category vocabulary (line 1005), in the design's
// order — the facet menu lists it as written, not alphabetically.
var Categories = []string{
	"Infrastructure",
	"Security & compliance",
	"Data",
	"Developer workflow",
	"Documentation",
}

// Catalog answers catalog queries from a fixed row set.
type Catalog struct {
	rows []view.Row
	tags []string
}

// New returns the design's ten packages.
func New() *Catalog { return build(baseRows()) }

// Scaled returns at least n rows by cloning the design's ten, so the R7
// measurement runs against seeded scale instead of ten rows. Clones carry a
// generated topic tag as well as their base tags, which is also how the tag
// facet reaches the 50 options the R7 exit criterion names.
func Scaled(n int) *Catalog {
	base := baseRows()
	if n <= len(base) {
		return build(base)
	}

	rows := make([]view.Row, 0, n)
	for i := range n {
		row := base[i%len(base)]
		if i >= len(base) {
			suffix := fmt.Sprintf("-%05d", i)
			row.Key += suffix
			row.ID += suffix
			row.Name = fmt.Sprintf("%s %05d", row.Name, i)
			tags := make([]string, 0, len(row.Tags)+1)
			tags = append(tags, row.Tags...)
			tags = append(tags, fmt.Sprintf("topic-%02d", i%40))
			row.Tags = tags
		}
		rows = append(rows, row)
	}
	return build(rows)
}

func build(rows []view.Row) *Catalog {
	seen := map[string]struct{}{}
	tags := []string{}
	for i := range rows {
		for _, tag := range rows[i].Tags {
			if _, dup := seen[tag]; dup {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return &Catalog{rows: rows, tags: tags}
}

// Rows is the whole fixture, for tests and for the scale measurement.
func (c *Catalog) Rows() []view.Row { return c.rows }

// Catalog implements web.CatalogSource.
func (c *Catalog) Catalog(_ context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
	q = q.Normalise()

	matched := make([]view.Row, 0, len(c.rows))
	for i := range c.rows {
		if matches(&c.rows[i], q) {
			matched = append(matched, c.rows[i])
		}
	}
	sortRows(matched, q.Sort, q.Dir)

	page := view.CatalogPage{
		Query:      q,
		Total:      len(matched),
		Page:       q.Page,
		PageSize:   view.DefaultPageSize,
		Categories: c.categoryFacet(q),
		Tags:       c.tagFacet(q),
	}
	page.Rows = window(matched, page.Page, page.PageSize)
	return page, nil
}

// window clamps the requested page into the result set, so a stale page number
// after a narrowing filter shows the last page rather than nothing.
func window(rows []view.Row, page, size int) []view.Row {
	if len(rows) == 0 {
		return nil
	}
	pages := (len(rows) + size - 1) / size
	if page > pages {
		page = pages
	}
	start := (page - 1) * size
	end := min(start+size, len(rows))
	return rows[start:end]
}

// matches applies every filter except the free-text one's own facet exclusions.
// FR-013 lives here: categories are OR, tags are AND.
func matches(row *view.Row, q view.CatalogQuery) bool {
	return matchText(row, q.Text) &&
		matchKind(row, q.Kind) &&
		matchStatus(row, q.Status) &&
		matchCategories(row, q.Categories) &&
		matchTags(row, q.Tags)
}

// matchText is a case-insensitive substring match against name, id, publisher or
// a single tag (FR-010).
//
// Per field, matching internal/api/queries. Joining them into one string first
// matches across the gaps between them — "redactor example" would find
// example/pii-redactor — and the fixture and the api must answer the same screen
// the same way or the screen tests stop being evidence about the real one.
func matchText(row *view.Row, text string) bool {
	if text == "" {
		return true
	}

	needle := strings.ToLower(text)
	for _, field := range append([]string{row.Name, row.ID, row.Publisher}, row.Tags...) {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

func matchKind(row *view.Row, kind string) bool {
	switch kind {
	case view.KindFilterPlugins:
		return row.Kind == view.KindPlugin
	case view.KindFilterSkills:
		return row.Kind == view.KindSkill
	default:
		return true
	}
}

// matchStatus mirrors the design's status chips. Verified is a publisher flag in
// the real model, never inferred from the id prefix (DESIGN-DATA.md); the
// fixture's example/ prefix is seed data expressing that flag.
func matchStatus(row *view.Row, status string) bool {
	switch status {
	case view.StatusVerified:
		return strings.HasPrefix(row.Publisher, "example") && row.Scan == view.ScanClean
	case view.StatusCommunity:
		return strings.HasPrefix(row.Publisher, "community")
	case view.StatusFlagged:
		return row.Scan != view.ScanClean
	default:
		return true
	}
}

func matchCategories(row *view.Row, categories []string) bool {
	if len(categories) == 0 {
		return true
	}
	for _, want := range categories {
		if row.Category == want {
			return true
		}
	}
	return false
}

func matchTags(row *view.Row, tags []string) bool {
	for _, want := range tags {
		if !hasTag(row, want) {
			return false
		}
	}
	return true
}

func hasTag(row *view.Row, want string) bool {
	for _, tag := range row.Tags {
		if tag == want {
			return true
		}
	}
	return false
}

// categoryFacet counts what each option would yield if it were the selected
// category, holding every other filter. That is what makes the count live: a
// count computed over the unfiltered set never changes and tells the reader
// nothing about the filter they are building.
func (c *Catalog) categoryFacet(q view.CatalogQuery) []view.FacetOption {
	rest := q
	rest.Categories = nil

	counts := make(map[string]int, len(Categories))
	for i := range c.rows {
		if matches(&c.rows[i], rest) {
			counts[c.rows[i].Category]++
		}
	}

	options := make([]view.FacetOption, 0, len(Categories))
	for _, name := range Categories {
		options = append(options, view.FacetOption{
			Label:    name,
			Count:    counts[name],
			Selected: contains(q.Categories, name),
		})
	}
	return options
}

// tagFacet counts the drill-down: rows already matching the selected tags that
// also carry this one. With AND semantics that is the number the reader is about
// to get, not a population count.
func (c *Catalog) tagFacet(q view.CatalogQuery) []view.FacetOption {
	rest := q
	rest.Categories = q.Categories

	counts := make(map[string]int, len(c.tags))
	for i := range c.rows {
		if !matches(&c.rows[i], rest) {
			continue
		}
		for _, tag := range c.rows[i].Tags {
			counts[tag]++
		}
	}

	options := make([]view.FacetOption, 0, len(c.tags))
	for _, tag := range c.tags {
		options = append(options, view.FacetOption{
			Label:    tag,
			Count:    counts[tag],
			Selected: contains(q.Tags, tag),
		})
	}
	return options
}

func contains(haystack []string, want string) bool {
	for _, v := range haystack {
		if v == want {
			return true
		}
	}
	return false
}

func sortRows(rows []view.Row, key view.SortKey, dir view.SortDir) {
	sign := -1
	if dir == view.DirAsc {
		sign = 1
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case view.SortName:
			return strings.Compare(a.Name, b.Name)*sign < 0
		case view.SortUpdated:
			// Recency, not age: descending means newest first, so the comparison
			// runs against the negated sign. This mirrors the design's `* -dir`.
			return (ageDays(a.Updated)-ageDays(b.Updated))*-sign < 0
		default:
			return (a.Uses-b.Uses)*sign < 0
		}
	})
}

// ageDays parses the design's relative date strings. The real model renders
// these from stored timestamps (spec Assumptions); the fixture keeps the
// design's strings so the seeded screen matches the design, and sorts on the
// same reading of them the design uses.
func ageDays(updated string) int {
	switch {
	case strings.Contains(updated, "hour"):
		return 0
	case updated == "yesterday":
		return 1
	}

	digits := strings.TrimLeft(updated, " ")
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(digits[:end])
	if err != nil {
		return 0
	}
	switch {
	case strings.Contains(updated, "week"):
		return n * 7
	case strings.Contains(updated, "month"):
		return n * 30
	default:
		return n
	}
}

func baseRows() []view.Row {
	return []view.Row{
		{Key: "platform-toolkit", ID: "example/platform-toolkit", Name: "Platform Toolkit", Publisher: "example/platform",
			Category: "Infrastructure", Version: "1.3.0", Updated: "2 days ago", Kind: view.KindPlugin, Scan: view.ScanClean,
			Uses: 42, Tags: []string{"terraform", "aws", "guardrails", "scaffolding"}},
		{Key: "security-kit", ID: "example/security-review-kit", Name: "Security Review Kit", Publisher: "example/security",
			Category: "Security & compliance", Version: "2.0.1", Updated: "4 days ago", Kind: view.KindPlugin, Scan: view.ScanClean,
			Uses: 31, Tags: []string{"pii", "security", "review"}},
		{Key: "release-toolkit", ID: "community/release-toolkit", Name: "Release Toolkit", Publisher: "community/octoflow",
			Category: "Developer workflow", Version: "1.2.7", Updated: "6 hours ago", Kind: view.KindPlugin, Scan: view.ScanPending,
			Uses: 6, Tags: []string{"github", "changelog", "releases"}},
		{Key: "slack-digest", ID: "community/slack-digest", Name: "Slack Digest", Publisher: "community/hexley",
			Category: "Developer workflow", Version: "0.5.1", Updated: "2 days ago", Kind: view.KindPlugin, Scan: view.ScanFlagged,
			Uses: 3, Tags: []string{"slack", "summaries"}},
		{Key: "tf-review", ID: "example/terraform-module-review", Name: "Terraform Module Review", Publisher: "example/platform",
			Category: "Infrastructure", Version: "2.4.1", Updated: "2 days ago", Kind: view.KindSkill, Scan: view.ScanClean,
			Uses: 38, Tags: []string{"terraform", "review", "aws", "guardrails"}},
		{Key: "k8s-triage", ID: "example/k8s-incident-triage", Name: "Kubernetes Incident Triage", Publisher: "example/sre",
			Category: "Infrastructure", Version: "1.9.0", Updated: "5 days ago", Kind: view.KindSkill, Scan: view.ScanClean,
			Uses: 22, Tags: []string{"kubernetes", "incident", "runbook"}},
		{Key: "pg-migrate", ID: "community/postgres-migration-guard", Name: "Postgres Migration Guard", Publisher: "community/dbtools",
			Category: "Data", Version: "0.8.3", Updated: "yesterday", Kind: view.KindSkill, Scan: view.ScanFlagged,
			Uses: 9, Tags: []string{"postgres", "migrations"}},
		{Key: "adr-writer", ID: "example/adr-writer", Name: "ADR Writer", Publisher: "example/architecture",
			Category: "Documentation", Version: "3.1.0", Updated: "3 weeks ago", Kind: view.KindSkill, Scan: view.ScanClean,
			Uses: 47, Tags: []string{"adr", "docs", "review"}},
		{Key: "aws-cost", ID: "community/aws-cost-explainer", Name: "AWS Cost Explainer", Publisher: "community/finops",
			Category: "Infrastructure", Version: "2.0.0", Updated: "1 week ago", Kind: view.KindSkill, Scan: view.ScanClean,
			Uses: 15, Tags: []string{"aws", "cost", "finops"}},
		{Key: "pii-redact", ID: "example/pii-redactor", Name: "PII Redactor", Publisher: "example/security",
			Category: "Security & compliance", Version: "1.4.2", Updated: "4 days ago", Kind: view.KindSkill, Scan: view.ScanClean,
			Uses: 34, Tags: []string{"pii", "security"}},
	}
}
