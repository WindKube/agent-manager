package fakeapi

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"agent-manager/internal/apiclient"
)

// Scale grows the catalog to at least n packages by cloning the seed; each
// clone carries an extra topic tag.
func (d *Data) Scale(n int) {
	base := slices.Clone(d.Packages)
	for i := len(base); i < n; i++ {
		row := base[i%len(base)]
		suffix := fmt.Sprintf("-%05d", i)
		row.Id += suffix
		row.Name += suffix
		row.Tags = append(slices.Clone(row.Tags), fmt.Sprintf("topic-%02d", i%40))
		d.Packages = append(d.Packages, row)
	}
}

// catalog answers listPackages as internal/api/queries does: text across
// fields, categories OR'd, tags AND'd, facet counts live against the other filters.
func (d *Data) catalog(r *http.Request) apiclient.CatalogPage {
	q := r.URL.Query()
	f := filter{
		text:       strings.ToLower(q.Get("q")),
		kind:       q.Get("kind"),
		status:     q.Get("status"),
		categories: q["category"],
		tags:       q["tag"],
	}

	matched := make([]apiclient.CatalogPackage, 0, len(d.Packages))
	for i := range d.Packages {
		if f.match(&d.Packages[i]) {
			matched = append(matched, d.Packages[i])
		}
	}
	sortPackages(matched, q.Get("sort"), q.Get("dir"))

	page := queryInt(r, "page", 1)
	size := queryInt(r, "pageSize", 10)
	if pages := (int64(len(matched)) + size - 1) / size; page > pages && pages > 0 {
		page = pages
	}
	start := min((page-1)*size, int64(len(matched)))
	end := min(start+size, int64(len(matched)))

	return apiclient.CatalogPage{
		Packages:   matched[start:end],
		Total:      int64(len(matched)),
		Page:       page,
		PageSize:   size,
		Categories: d.categoryFacet(f),
		Tags:       d.tagFacet(f),
	}
}

type filter struct {
	text, kind, status string
	categories, tags   []string
}

func (f filter) match(p *apiclient.CatalogPackage) bool {
	if f.text != "" && !slices.ContainsFunc(append([]string{p.Name, p.Id, p.Publisher}, p.Tags...),
		func(s string) bool { return strings.Contains(strings.ToLower(s), f.text) }) {
		return false
	}
	if f.kind != "" && f.kind != "all" && string(p.Kind) != f.kind {
		return false
	}
	switch f.status {
	case "verified":
		if !strings.HasPrefix(p.Publisher, "example") || p.Verdict != apiclient.CatalogPackageVerdictClean {
			return false
		}
	case "community":
		if !strings.HasPrefix(p.Publisher, "community") {
			return false
		}
	case "flagged":
		if p.Verdict == apiclient.CatalogPackageVerdictClean {
			return false
		}
	}
	if len(f.categories) > 0 && (p.Category == nil || !slices.Contains(f.categories, *p.Category)) {
		return false
	}
	for _, tag := range f.tags {
		if !slices.Contains(p.Tags, tag) {
			return false
		}
	}
	return true
}

func (d *Data) categoryFacet(f filter) []apiclient.CatalogFacetOption {
	rest := f
	rest.categories = nil
	counts := map[string]int64{}
	for i := range d.Packages {
		p := &d.Packages[i]
		if p.Category != nil && rest.match(p) {
			counts[*p.Category]++
		}
	}
	out := make([]apiclient.CatalogFacetOption, 0, len(d.Categories))
	for _, name := range d.Categories {
		out = append(out, apiclient.CatalogFacetOption{Value: name, Count: counts[name]})
	}
	return out
}

func (d *Data) tagFacet(f filter) []apiclient.CatalogFacetOption {
	all := map[string]struct{}{}
	counts := map[string]int64{}
	for i := range d.Packages {
		p := &d.Packages[i]
		for _, tag := range p.Tags {
			all[tag] = struct{}{}
		}
		if !f.match(p) {
			continue
		}
		for _, tag := range p.Tags {
			counts[tag]++
		}
	}
	names := make([]string, 0, len(all))
	for tag := range all {
		names = append(names, tag)
	}
	sort.Strings(names)
	out := make([]apiclient.CatalogFacetOption, 0, len(names))
	for _, tag := range names {
		out = append(out, apiclient.CatalogFacetOption{Value: tag, Count: counts[tag]})
	}
	return out
}

func sortPackages(rows []apiclient.CatalogPackage, key, dir string) {
	sign := -1
	if dir == "asc" {
		sign = 1
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case "name":
			return strings.Compare(a.Name, b.Name)*sign < 0
		case "updated":
			return a.UpdatedAt.Compare(b.UpdatedAt)*sign < 0
		default:
			return (a.Uses-b.Uses)*int64(sign) < 0
		}
	})
}
