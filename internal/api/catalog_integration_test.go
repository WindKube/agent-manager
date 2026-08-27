//go:build integration

// The catalog against a real Postgres (US2, T054, SC-004).
//
// Every expectation below is HAND-DERIVED from docs/design/agent-manager.dc.html
// items() at lines 867-920 and written out as a literal set. It is deliberately
// not computed from the seed by a second Go implementation of the same filters:
// two sides that share an author share a misreading, and FR-013's asymmetry is
// exactly the kind of thing both sides would get wrong together.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
	"agent-manager/internal/web/view"
)

// The design's ten packages, transcribed.
//
// Three strings are at work and only two of them are columns. `publisher` here is
// the whole slug — the owning team, `example/security` — and it is what carries
// `verified`. The namespace is its FIRST segment, and namespace/name is both the
// id the design renders (`example/pii-redactor`) and the prefix of the object key.
// Transcribing the design's eight publishers rather than collapsing them to two
// is the point: with one publisher per namespace the query could pass while
// treating the slug as the namespace, and every assertion here would still hold.
var designPackages = []struct {
	publisher string
	name      string
	kind      models.PackageKind
	category  string
	semver    string
	verdict   models.Verdict
	tags      []string
	// age is the version's age at seed time, chosen so every package has a
	// distinct one: `order by updated` must be a total order or the assertion on
	// it is asserting the tiebreak instead.
	age time.Duration
	// profiles is how many profiles contain the package, which is `uses`.
	profiles int
}{
	{"community/octoflow", "release-toolkit", models.PackageKindPlugin, "Developer workflow", "1.2.7",
		models.VerdictScanning, []string{"github", "changelog", "releases"}, 6 * time.Hour, 0},
	{"community/dbtools", "postgres-migration-guard", models.PackageKindSkill, "Data", "0.8.3",
		models.VerdictFlagged, []string{"postgres", "migrations"}, 30 * time.Hour, 0},
	{"example/platform", "platform-toolkit", models.PackageKindPlugin, "Infrastructure", "1.3.0",
		models.VerdictClean, []string{"terraform", "aws", "guardrails", "scaffolding"}, 48 * time.Hour, 4},
	{"community/hexley", "slack-digest", models.PackageKindPlugin, "Developer workflow", "0.5.1",
		models.VerdictFlagged, []string{"slack", "summaries"}, 50 * time.Hour, 0},
	{"example/platform", "terraform-module-review", models.PackageKindSkill, "Infrastructure", "2.4.1",
		models.VerdictClean, []string{"terraform", "review", "aws", "guardrails"}, 52 * time.Hour, 2},
	{"example/security", "security-review-kit", models.PackageKindPlugin, "Security & compliance", "2.0.1",
		models.VerdictClean, []string{"pii", "security", "review"}, 96 * time.Hour, 0},
	{"example/security", "pii-redactor", models.PackageKindSkill, "Security & compliance", "1.4.2",
		models.VerdictClean, []string{"pii", "security"}, 98 * time.Hour, 0},
	{"example/sre", "k8s-incident-triage", models.PackageKindSkill, "Infrastructure", "1.9.0",
		models.VerdictClean, []string{"kubernetes", "incident", "runbook"}, 120 * time.Hour, 1},
	{"community/finops", "aws-cost-explainer", models.PackageKindSkill, "Infrastructure", "2.0.0",
		models.VerdictClean, []string{"aws", "cost", "finops"}, 168 * time.Hour, 0},
	{"example/architecture", "adr-writer", models.PackageKindSkill, "Documentation", "3.1.0",
		models.VerdictClean, []string{"adr", "docs", "review"}, 504 * time.Hour, 3},
}

// designCategories is the vocabulary in the design's order (line 1005). The
// catalog returns it in that order, which it can only do because uuid v7 sorts
// by creation and `category` has no position column — so these are inserted in
// this order deliberately, not incidentally.
var designCategories = []string{
	"Infrastructure", "Security & compliance", "Data", "Developer workflow", "Documentation",
}

// restrictedPackage is not in the design. It exists to prove the one thing
// `package.visibility` can currently enforce.
const restrictedPackage = "example/internal-only"

func namespaceOf(slug string) string {
	namespace, _, _ := strings.Cut(slug, "/")
	return namespace
}

var seedCatalogOnce sync.Once

func seedCatalog(t *testing.T) {
	t.Helper()

	seedCatalogOnce.Do(func() {
		ctx := t.Context()
		insert := func(model any) {
			_, err := db.NewInsert().Model(model).Exec(ctx)
			require.NoError(t, err)
		}

		categories := map[string]uuid.UUID{}
		for _, name := range designCategories {
			row := &models.Category{
				ID: models.NewID(), Name: name,
				Slug: strings.ToLower(strings.NewReplacer(" & ", "-", " ", "-").Replace(name)),
			}
			insert(row)
			categories[name] = row.ID
		}

		// FR-011's Verified/Community split is this flag and nothing else. It is
		// never inferred from the slug prefix, which is why the seed sets it here
		// and the query reads only the column.
		publishers := map[string]uuid.UUID{}
		for _, spec := range []struct {
			slug, display string
			verified      bool
		}{
			{"example/platform", "Platform Engineering", true},
			{"example/security", "Security Engineering", true},
			{"example/sre", "Site Reliability", true},
			{"example/architecture", "Architecture", true},
			{"community/octoflow", "Octoflow", false},
			{"community/hexley", "Hexley", false},
			{"community/dbtools", "DB Tools", false},
			{"community/finops", "FinOps", false},
		} {
			row := &models.Publisher{
				ID: models.NewID(), Slug: spec.slug, DisplayName: spec.display, Verified: spec.verified,
			}
			insert(row)
			publishers[spec.slug] = row.ID
		}

		profiles := profileIDs(t)
		now := time.Now().UTC()

		for i := range designPackages {
			spec := &designPackages[i]
			categoryID := categories[spec.category]
			pkg := &models.Package{
				ID: models.NewID(), PublisherID: publishers[spec.publisher], Name: spec.name,
				Kind: spec.kind, CategoryID: &categoryID, Visibility: models.PackageVisibilityOrganisation,
			}
			insert(pkg)

			version := &models.Version{
				ID: models.NewID(), PackageID: pkg.ID, Semver: spec.semver, SemverSort: spec.semver,
				// The key is namespaced, not published-by: skills/example/... for a
				// package of example/platform. Getting this wrong is invisible until
				// two teams in one namespace publish the same name.
				ObjectKey: fmt.Sprintf("skills/%s/%s/%s/bundle.tar.zst",
					namespaceOf(spec.publisher), spec.name, spec.semver),
				Digest: bundleSHA, Manifest: json.RawMessage(`{"name":"` + spec.name + `"}`),
				Tags:    spec.tags,
				DistTag: models.DistTagLatest, Verdict: spec.verdict, Visible: true,
				CreatedAt: now.Add(-spec.age),
			}
			insert(version)

			_, err := db.NewUpdate().Model((*models.Package)(nil)).
				Set("latest_version_id = ?", version.ID).Where("id = ?", pkg.ID).Exec(ctx)
			require.NoError(t, err)

			for i := range spec.profiles {
				insert(&models.ProfileEntry{
					ProfileID: profiles[i], PackageID: pkg.ID,
					Mode: models.EntryModeLatest, Position: int32(i),
				})
			}
		}

		// The private one, which no anonymous reader may see.
		restricted := &models.Package{
			ID: models.NewID(), PublisherID: publishers["example/platform"], Name: "internal-only",
			Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityPrivate,
		}
		insert(restricted)
		version := &models.Version{
			ID: models.NewID(), PackageID: restricted.ID, Semver: "0.1.0", SemverSort: "0.1.0",
			ObjectKey: "skills/example/internal-only/0.1.0/bundle.tar.zst", Digest: bundleSHA,
			Manifest: json.RawMessage(`{"name":"internal-only"}`), Tags: []string{"internal"},
			DistTag: models.DistTagLatest, Verdict: models.VerdictClean, Visible: true,
			CreatedAt: now,
		}
		insert(version)
		_, err := db.NewUpdate().Model((*models.Package)(nil)).
			Set("latest_version_id = ?", version.ID).Where("id = ?", restricted.ID).Exec(ctx)
		require.NoError(t, err)
	})
}

// profileIDs returns the suite's four seeded profiles, in a fixed order, so
// `uses` is reproducible.
func profileIDs(t *testing.T) []uuid.UUID {
	t.Helper()

	var ids []uuid.UUID
	require.NoError(t, db.NewSelect().Model((*models.Profile)(nil)).
		Column("id").Order("slug").Scan(t.Context(), &ids))
	require.GreaterOrEqual(t, len(ids), 4, "the suite seeds four profiles")
	return ids
}

func catalog(t *testing.T, handler http.Handler, token string, query url.Values) contract.CatalogPage {
	t.Helper()

	rec := request(t, handler, http.MethodGet, "/v1/packages?"+query.Encode(), token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var page contract.CatalogPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	return page
}

func idsOf(page contract.CatalogPage) []string {
	out := make([]string, 0, len(page.Packages))
	for i := range page.Packages {
		out = append(out, page.Packages[i].ID)
	}
	return out
}

func countOf(t *testing.T, options []contract.CatalogFacetOption, value string) int {
	t.Helper()

	for _, option := range options {
		if option.Value == value {
			return option.Count
		}
	}
	require.Failf(t, "missing facet option", "no option %q in %v", value, options)
	return 0
}

func query(pairs ...string) url.Values {
	values := url.Values{}
	for i := 0; i < len(pairs); i += 2 {
		values.Add(pairs[i], pairs[i+1])
	}
	return values
}

// ---- T054 --------------------------------------------------------------------

func TestEveryFilterCombinationReturnsExactlyTheSeededPackagesThatMatch(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	for _, tc := range []struct {
		name  string
		query url.Values
		want  []string
	}{
		{
			name:  "no filter is the whole organisation-visible catalog",
			query: query("pageSize", "50"),
			want: []string{
				"example/platform-toolkit", "example/security-review-kit", "community/release-toolkit",
				"community/slack-digest", "example/terraform-module-review", "example/k8s-incident-triage",
				"community/postgres-migration-guard", "example/adr-writer", "community/aws-cost-explainer",
				"example/pii-redactor",
			},
		},
		{
			name:  "kind plugins",
			query: query("kind", "plugin", "pageSize", "50"),
			want: []string{"example/platform-toolkit", "example/security-review-kit",
				"community/release-toolkit", "community/slack-digest"},
		},
		{
			name:  "kind skills",
			query: query("kind", "skill", "pageSize", "50"),
			want: []string{"example/terraform-module-review", "example/k8s-incident-triage",
				"community/postgres-migration-guard", "example/adr-writer",
				"community/aws-cost-explainer", "example/pii-redactor"},
		},
		{
			// US2 scenario 3. slack-digest is NOT here even though nothing about its
			// publisher disqualifies it, and neither is anything under community/
			// even when its verdict is clean.
			name:  "status verified is a verified publisher AND a clean verdict",
			query: query("status", "verified", "pageSize", "50"),
			want: []string{"example/platform-toolkit", "example/security-review-kit",
				"example/terraform-module-review", "example/k8s-incident-triage",
				"example/adr-writer", "example/pii-redactor"},
		},
		{
			name:  "status community is the publisher flag alone, verdict irrelevant",
			query: query("status", "community", "pageSize", "50"),
			want: []string{"community/release-toolkit", "community/slack-digest",
				"community/postgres-migration-guard", "community/aws-cost-explainer"},
		},
		{
			name:  "status flagged is every verdict that is not clean, scanning included",
			query: query("status", "flagged", "pageSize", "50"),
			want: []string{"community/release-toolkit", "community/slack-digest",
				"community/postgres-migration-guard"},
		},
		{
			name:  "search matches the id",
			query: query("q", "redactor"),
			want:  []string{"example/pii-redactor"},
		},
		{
			name:  "search matches a tag no id or name carries",
			query: query("q", "guardrails"),
			want:  []string{"example/platform-toolkit", "example/terraform-module-review"},
		},
		{
			name:  "search matches the namespace every id starts with",
			query: query("q", "community", "pageSize", "50"),
			want: []string{"community/release-toolkit", "community/slack-digest",
				"community/postgres-migration-guard", "community/aws-cost-explainer"},
		},
		{
			// FR-010 lists the publisher and the id separately, and this needle shows
			// why: `community/dbtools` is in no id at all. A haystack built from the
			// id alone answers this with nothing.
			name:  "search matches the publisher slug, which appears in no id",
			query: query("q", "community/dbtools"),
			want:  []string{"community/postgres-migration-guard"},
		},
		{
			// And the mirror: this needle is in no publisher slug. adr-writer belongs
			// to example/architecture, so a haystack built from the slug alone answers
			// this with nothing.
			name:  "search matches the id, which appears in no publisher slug",
			query: query("q", "example/adr"),
			want:  []string{"example/adr-writer"},
		},
		{
			// The needle must be inside ONE field. Concatenating the four into a
			// single string and matching that would answer this with the package,
			// because "redactor" ends its id and "example" starts its publisher
			// slug — a match the reader cannot see in anything on the row.
			name:  "a needle spanning two fields matches nothing",
			query: query("q", "redactor example"),
			want:  []string{},
		},
		{
			// The same trap between two tags of one package. pii-redactor carries
			// exactly ["pii","security"], and this is neither of them.
			name:  "a needle spanning two tags of the same package matches nothing",
			query: query("q", "pii security"),
			want:  []string{},
		},
		{
			name:  "search is case-insensitive",
			query: query("q", "SECURITY"),
			want:  []string{"example/security-review-kit", "example/pii-redactor"},
		},
		{
			// FR-010 asks for a substring, not a pattern. `%` is an ILIKE wildcard
			// and would match everything if the needle reached one unescaped.
			name:  "a wildcard in the search text is a literal",
			query: query("q", "%"),
			want:  []string{},
		},
		{
			name:  "one category",
			query: query("category", "Data"),
			want:  []string{"community/postgres-migration-guard"},
		},
		{
			name:  "one tag",
			query: query("tag", "terraform"),
			want:  []string{"example/platform-toolkit", "example/terraform-module-review"},
		},
		{
			name:  "a filter combination that matches nothing",
			query: query("kind", "plugin", "category", "Documentation"),
			want:  []string{},
		},
		{
			name:  "kind and status compose",
			query: query("kind", "plugin", "status", "flagged"),
			want:  []string{"community/release-toolkit", "community/slack-digest"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := catalog(t, liveHandler(t), kw.token, tc.query)
			require.ElementsMatch(t, tc.want, idsOf(page))
			require.Equal(t, len(tc.want), page.Total,
				"the live count of FR-015 must agree with the rows")
		})
	}

	t.Run("the id is the namespace and the name, and the publisher is neither", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("q", "adr-writer"))
		require.Len(t, page.Packages, 1)

		row := page.Packages[0]
		require.Equal(t, "example/adr-writer", row.ID)
		require.Equal(t, "example/architecture", row.Publisher)
		require.Equal(t, "adr-writer", row.Name)
		// The one that would go unnoticed: concatenating the publisher and the name
		// gives example/architecture/adr-writer, which is neither the id the design
		// renders nor a key any bundle was written under.
		require.NotEqual(t, row.Publisher+"/"+row.Name, row.ID)
	})

	t.Run("a package with no latest version pointer is not in the catalog", func(t *testing.T) {
		// acme/code-review is seeded by the suite with two VISIBLE versions and no
		// latest_version_id, which is what a half-published package looks like
		// between the fetcher's writes (FR-008).
		page := catalog(t, handler, kw.token, query("pageSize", "50"))
		require.NotContains(t, idsOf(page), "acme/code-review")
	})
}

// FR-013's asymmetry, which is the one thing on this screen that looks like a
// bug to anyone who has not read the requirement.
func TestTagsNarrowConjunctivelyAndCategoriesNarrowDisjunctively(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	t.Run("two categories return the union, which is larger than either", func(t *testing.T) {
		infrastructure := idsOf(catalog(t, handler, kw.token, query("category", "Infrastructure", "pageSize", "50")))
		data := idsOf(catalog(t, handler, kw.token, query("category", "Data", "pageSize", "50")))
		both := idsOf(catalog(t, handler, kw.token,
			query("category", "Infrastructure", "category", "Data", "pageSize", "50")))

		require.Len(t, infrastructure, 4)
		require.Len(t, data, 1)
		require.Len(t, both, 5)
		require.Subset(t, both, infrastructure)
		require.Subset(t, both, data)
	})

	t.Run("two tags return the intersection, which is smaller than either", func(t *testing.T) {
		aws := idsOf(catalog(t, handler, kw.token, query("tag", "aws", "pageSize", "50")))
		review := idsOf(catalog(t, handler, kw.token, query("tag", "review", "pageSize", "50")))
		both := idsOf(catalog(t, handler, kw.token, query("tag", "aws", "tag", "review", "pageSize", "50")))

		require.ElementsMatch(t,
			[]string{"example/platform-toolkit", "example/terraform-module-review",
				"community/aws-cost-explainer"}, aws)
		require.ElementsMatch(t,
			[]string{"example/security-review-kit", "example/terraform-module-review",
				"example/adr-writer"}, review)
		require.Equal(t, []string{"example/terraform-module-review"}, both)
	})

	t.Run("two tags nothing carries together return nothing, unlike two categories", func(t *testing.T) {
		// The sharpest form of the asymmetry: the same shape of request, one
		// widening to five and the other narrowing to zero.
		tags := catalog(t, handler, kw.token, query("tag", "terraform", "tag", "docs", "pageSize", "50"))
		categories := catalog(t, handler, kw.token,
			query("category", "Infrastructure", "category", "Documentation", "pageSize", "50"))

		require.Equal(t, 0, tags.Total)
		require.Equal(t, 5, categories.Total)
	})
}

// The facet counts, and the second half of the same asymmetry: each facet counts
// the way its own combining rule makes meaningful.
func TestFacetCountsAreComputedTheWayEachFacetCombines(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	t.Run("the whole curated vocabulary is returned, in curated order", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("kind", "plugin"))

		names := make([]string, 0, len(page.Categories))
		for _, option := range page.Categories {
			names = append(names, option.Value)
		}
		require.Equal(t, designCategories, names, "FR-049's vocabulary, in the design's order")

		// Two of them match no plugin at all and are still listed, because a menu
		// that hides its empty options cannot tell you they are empty.
		require.Equal(t, 0, countOf(t, page.Categories, "Data"))
		require.Equal(t, 0, countOf(t, page.Categories, "Documentation"))
		require.Equal(t, 2, countOf(t, page.Categories, "Developer workflow"))
	})

	t.Run("a category's count ignores the category filter", func(t *testing.T) {
		unfiltered := catalog(t, handler, kw.token, query())
		filtered := catalog(t, handler, kw.token, query("category", "Data"))

		// Selecting Data must not zero every other category: they are combined with
		// OR, so each count says what selecting it as well would add.
		require.Equal(t, 1, filtered.Total)
		for _, name := range designCategories {
			require.Equalf(t, countOf(t, unfiltered.Categories, name), countOf(t, filtered.Categories, name),
				"category %q changed count when a DIFFERENT category was selected", name)
		}
		require.Equal(t, 4, countOf(t, filtered.Categories, "Infrastructure"))
	})

	t.Run("a category's count still honours the tag filter", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("tag", "aws"))

		require.Equal(t, 3, page.Total)
		require.Equal(t, 3, countOf(t, page.Categories, "Infrastructure"))
		require.Equal(t, 0, countOf(t, page.Categories, "Security & compliance"))
	})

	t.Run("a tag's count is a drill-down and not a population count", func(t *testing.T) {
		unfiltered := catalog(t, handler, kw.token, query())
		filtered := catalog(t, handler, kw.token, query("tag", "aws"))

		// `review` is on three packages overall, but only one of them also carries
		// `aws`. With AND semantics, one is the number selecting it would yield;
		// three would be a promise the next click breaks.
		require.Equal(t, 3, countOf(t, unfiltered.Tags, "review"))
		require.Equal(t, 1, countOf(t, filtered.Tags, "review"))
		require.Equal(t, 3, countOf(t, filtered.Tags, "aws"), "the selected tag counts the result set")
	})

	t.Run("the tag list holds only tags reachable from the current results", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("tag", "aws"))

		values := make([]string, 0, len(page.Tags))
		for _, option := range page.Tags {
			values = append(values, option.Value)
			require.Positivef(t, option.Count, "tag %q is offered with nothing behind it", option.Value)
		}
		require.Subset(t, values, []string{"aws", "terraform", "cost"})
		require.NotContains(t, values, "postgres")
		require.True(t, sortedAscending(values), "the menu is typed into, so it is alphabetical")
	})
}

func sortedAscending(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}

// FR-014. Descending first is the default, and `uses` is derived from profile
// membership at query time — nothing writes a counter on a catalog read (R8).
func TestSortingIsDescendingFirstAndUsesIsDerived(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	t.Run("by uses, descending", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("sort", "uses", "dir", "desc", "pageSize", "4"))
		require.Equal(t, []string{
			"example/platform-toolkit", "example/adr-writer",
			"example/terraform-module-review", "example/k8s-incident-triage",
		}, idsOf(page))
		require.Equal(t, []int{4, 3, 2, 1}, usesOf(page))
	})

	t.Run("by uses, ascending, is the same order reversed at the ends", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("sort", "uses", "dir", "asc", "pageSize", "50"))
		uses := usesOf(page)
		require.Equal(t, 0, uses[0])
		require.Equal(t, 4, uses[len(uses)-1])
	})

	t.Run("by name, ascending", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("sort", "name", "dir", "asc", "pageSize", "50"))
		require.Equal(t, []string{
			"example/adr-writer", "community/aws-cost-explainer", "example/k8s-incident-triage",
			"example/pii-redactor", "example/platform-toolkit", "community/postgres-migration-guard",
			"community/release-toolkit", "example/security-review-kit", "community/slack-digest",
			"example/terraform-module-review",
		}, idsOf(page))
	})

	t.Run("by recency, descending, is newest first", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("sort", "updated", "dir", "desc", "pageSize", "50"))
		require.Equal(t, []string{
			"community/release-toolkit", "community/postgres-migration-guard",
			"example/platform-toolkit", "community/slack-digest", "example/terraform-module-review",
			"example/security-review-kit", "example/pii-redactor", "example/k8s-incident-triage",
			"community/aws-cost-explainer", "example/adr-writer",
		}, idsOf(page))
	})

	t.Run("a catalog read writes nothing", func(t *testing.T) {
		// R8: no write on the hottest path. A counter incremented on view would
		// both lie and put a write in front of every browse.
		before := auditCount(t)
		catalog(t, handler, kw.token, query("q", "terraform"))
		require.Equal(t, before, auditCount(t))
	})
}

func usesOf(page contract.CatalogPage) []int {
	out := make([]int, 0, len(page.Packages))
	for i := range page.Packages {
		out = append(out, page.Packages[i].Uses)
	}
	return out
}

func auditCount(t *testing.T) int {
	t.Helper()

	count, err := db.NewSelect().Model((*models.AuditEvent)(nil)).Count(t.Context())
	require.NoError(t, err)
	return count
}

func TestPagingClampsInsteadOfAnsweringWithAnEmptyTable(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	first := catalog(t, handler, kw.token, query("sort", "name", "dir", "asc", "pageSize", "4", "page", "1"))
	require.Len(t, first.Packages, 4)
	require.Equal(t, 10, first.Total)

	last := catalog(t, handler, kw.token, query("sort", "name", "dir", "asc", "pageSize", "4", "page", "3"))
	require.Len(t, last.Packages, 2)

	// A stale page number in a URL, after a narrowing filter, shows the last page
	// rather than an empty one.
	beyond := catalog(t, handler, kw.token, query("sort", "name", "dir", "asc", "pageSize", "4", "page", "99"))
	require.Equal(t, 3, beyond.Page)
	require.Equal(t, idsOf(last), idsOf(beyond))
}

// The one thing package.visibility can enforce today. It is also why the
// operation admits an anonymous caller at all.
// spec.md's Out of Scope names "public anonymous browsing" alongside
// multi-tenancy. The operation therefore declares no security of its own and
// inherits the document's root bearer requirement — which is also the safe
// direction for a mistake to fall in, since an operation that says nothing is
// authenticated.
func TestBrowsingTheCatalogRequiresASession(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	for _, tc := range []struct{ name, token string }{
		{"no token at all", ""},
		{"a token that was never a session", "not-a-session-token"},
		{"a bearer prefix with nothing after it", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler, http.MethodGet, "/v1/packages", tc.token, "")
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		})
	}

	t.Run("a member with a session reads the catalog", func(t *testing.T) {
		page := catalog(t, handler, kw.token, query("pageSize", "50"))
		require.Equal(t, 10, page.Total)
	})

	// The negative control for the assertion above: 401 must come from the missing
	// session and not from the handler being unreachable for some other reason, so
	// the same request with a session must succeed — which the subtest above proves
	// — and an operation that IS public must still answer without one.
	t.Run("a public operation still answers with no token", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/health", "", "")
		require.Equal(t, http.StatusOK, rec.Code,
			"the root requirement must not have been applied to everything")
	})
}

// TestTheModalOffersExactlyTheVisibilitiesTheCatalogCanHonour binds three real
// artifacts that are otherwise free to drift: the package_visibility enum as the
// LIVE database defines it, the option list the modal actually renders, and what
// the catalog query actually returns for a package at each value.
//
// The failure it exists to catch is silent in both directions. Re-add "Private"
// to the modal with no predicate behind it and a person's package vanishes with
// no explanation; widen the predicate with no option beside it and rows appear
// that nobody chose to publish. Neither shows up in a test of either side alone,
// which is why this one reads the enum from Postgres rather than from a list in
// this file.
func TestTheModalOffersExactlyTheVisibilitiesTheCatalogCanHonour(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)
	ctx := t.Context()

	var vocabulary []string
	require.NoError(t, db.NewRaw(
		"select unnest(enum_range(null::package_visibility))::text").Scan(ctx, &vocabulary))
	require.Len(t, vocabulary, 3, "the enum this test reasons about")

	offered := map[string]bool{}
	for _, option := range view.ImportVisibilities {
		require.Containsf(t, vocabulary, option.Value,
			"the modal offers %q, which is not a package_visibility value at all", option.Value)
		offered[option.Value] = true
	}

	// One probe package per enum value, under its own publisher so nothing here
	// perturbs the totals the rest of this file asserts.
	publisher := &models.Publisher{
		ID: models.NewID(), Slug: "probe/visibility", DisplayName: "Visibility Probe",
	}
	_, err := db.NewInsert().Model(publisher).Exec(ctx)
	require.NoError(t, err)
	// Torn down in dependency order and not by cascade: package.latest_version_id
	// and version.package_id point at each other, so the pointer is dropped first.
	// The totals every other test in this file asserts depend on this running.
	t.Cleanup(func() {
		for _, statement := range []string{
			`update package set latest_version_id = null where publisher_id = ?`,
			`delete from version where package_id in (select id from package where publisher_id = ?)`,
			`delete from package where publisher_id = ?`,
			`delete from publisher where id = ?`,
		} {
			_, cleanupErr := db.ExecContext(context.Background(), statement, publisher.ID)
			require.NoError(t, cleanupErr)
		}
	})

	for _, visibility := range vocabulary {
		pkg := &models.Package{
			ID: models.NewID(), PublisherID: publisher.ID, Name: "probe-" + visibility,
			Kind: models.PackageKindSkill, Visibility: models.PackageVisibility(visibility),
		}
		_, err = db.NewInsert().Model(pkg).Exec(ctx)
		require.NoError(t, err)

		version := &models.Version{
			ID: models.NewID(), PackageID: pkg.ID, Semver: "1.0.0", SemverSort: "1.0.0",
			ObjectKey: "skills/probe/probe-" + visibility + "/1.0.0/bundle.tar.zst", Digest: bundleSHA,
			Manifest: json.RawMessage(`{"name":"probe-` + visibility + `"}`), Tags: []string{},
			DistTag: models.DistTagLatest, Verdict: models.VerdictClean, Visible: true,
			CreatedAt: time.Now().UTC(),
		}
		_, err = db.NewInsert().Model(version).Exec(ctx)
		require.NoError(t, err)
		_, err = db.NewUpdate().Model((*models.Package)(nil)).
			Set("latest_version_id = ?", version.ID).Where("id = ?", pkg.ID).Exec(ctx)
		require.NoError(t, err)
	}

	visible := idsOf(catalog(t, handler, kw.token, query("q", "probe-", "pageSize", "50")))
	for _, visibility := range vocabulary {
		id := "probe/probe-" + visibility
		if offered[visibility] {
			require.Containsf(t, visible, id,
				"the modal offers %q but a package registered with it is not in the catalog: "+
					"the person who chose it has lost their package with nothing on screen to say so",
				visibility)
			continue
		}
		require.NotContainsf(t, visible, id,
			"a package with visibility %q is in the catalog but the modal does not offer it: "+
				"either the predicate widened without the option or the option was removed "+
				"while the rows stayed", visibility)
	}
}

// A hub that leaks a private package is a worse failure than one that hides it,
// and `package` names no owner to compare a caller to, so `team` and `private`
// are hidden from every caller including the one who published them. This is the
// limitation, asserted so that giving `package` an owner has to come back here.
func TestTeamAndPrivatePackagesAreHiddenFromEveryone(t *testing.T) {
	seedCatalog(t)
	handler := liveHandler(t)

	page := catalog(t, handler, kw.token, query("pageSize", "50"))
	require.NotContains(t, idsOf(page), restrictedPackage,
		"a private package must not appear merely because the reader is signed in")
	require.Equal(t, 10, page.Total)

	byName := catalog(t, handler, kw.token, query("q", "internal-only", "pageSize", "50"))
	require.Empty(t, byName.Packages,
		"nor may search reach it: hiding it from the list and finding it by name is not hiding it")
}
