package fixture_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

func TestCatalogFiltering(t *testing.T) {
	tests := []struct {
		name     string
		query    view.CatalogQuery
		wantIDs  []string
		wantSome bool
	}{
		{
			name:  "no filter returns the design's ten packages, most used first",
			query: view.CatalogQuery{},
			wantIDs: []string{
				"example/adr-writer", "example/platform-toolkit", "example/terraform-module-review",
				"example/pii-redactor", "example/security-review-kit", "example/k8s-incident-triage",
				"community/aws-cost-explainer", "community/postgres-migration-guard",
				"community/release-toolkit", "community/slack-digest",
			},
		},
		{
			name:  "two selected tags narrow conjunctively (FR-013)",
			query: view.CatalogQuery{Tags: []string{"terraform", "guardrails"}},
			wantIDs: []string{
				"example/platform-toolkit", "example/terraform-module-review",
			},
		},
		{
			name:    "a tag pair no package carries yields nothing, not the union",
			query:   view.CatalogQuery{Tags: []string{"terraform", "postgres"}},
			wantIDs: []string{},
		},
		{
			name:  "two selected categories widen disjunctively (FR-013)",
			query: view.CatalogQuery{Categories: []string{"Data", "Documentation"}},
			wantIDs: []string{
				"example/adr-writer", "community/postgres-migration-guard",
			},
		},
		{
			name:  "the kind filter selects plugins only (FR-011)",
			query: view.CatalogQuery{Kind: view.KindFilterPlugins},
			wantIDs: []string{
				"example/platform-toolkit", "example/security-review-kit",
				"community/release-toolkit", "community/slack-digest",
			},
		},
		{
			name:  "verified means a verified publisher and a clean scan",
			query: view.CatalogQuery{Status: view.StatusVerified},
			wantIDs: []string{
				"example/adr-writer", "example/platform-toolkit", "example/terraform-module-review",
				"example/pii-redactor", "example/security-review-kit", "example/k8s-incident-triage",
			},
		},
		{
			name:  "flagged means any verdict other than clean",
			query: view.CatalogQuery{Status: view.StatusFlagged},
			wantIDs: []string{
				"community/postgres-migration-guard", "community/release-toolkit", "community/slack-digest",
			},
		},
		{
			name:  "free text matches a publisher (FR-010)",
			query: view.CatalogQuery{Text: "octoflow"},
			wantIDs: []string{
				"community/release-toolkit",
			},
		},
		{
			name:  "free text matches a tag, case-insensitively",
			query: view.CatalogQuery{Text: "KUBERNETES"},
			wantIDs: []string{
				"example/k8s-incident-triage",
			},
		},
		{
			name:  "free text is a substring match, not a subsequence one",
			query: view.CatalogQuery{Text: "tfm"},
			// The facet menus fuzzy-match; the search box does not (FR-010).
			wantIDs: []string{},
		},
		{
			name:  "sorting by name ascending orders alphabetically (FR-014)",
			query: view.CatalogQuery{Sort: view.SortName, Dir: view.DirAsc, Categories: []string{"Documentation", "Data"}},
			wantIDs: []string{
				"example/adr-writer", "community/postgres-migration-guard",
			},
		},
		{
			name:  "sorting by recency descending puts the newest first",
			query: view.CatalogQuery{Sort: view.SortUpdated, Dir: view.DirDesc, Kind: view.KindFilterPlugins},
			wantIDs: []string{
				"community/release-toolkit", "example/platform-toolkit",
				"community/slack-digest", "example/security-review-kit",
			},
		},
	}

	catalog := fixture.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, err := catalog.Catalog(context.Background(), tc.query)
			require.NoError(t, err)

			got := make([]string, 0, len(page.Rows))
			for _, row := range page.Rows {
				got = append(got, row.ID)
			}
			require.Equal(t, tc.wantIDs, got)
			require.Equal(t, len(tc.wantIDs), page.Total)
		})
	}
}

func TestFacetCountsRespondToTheOtherFilters(t *testing.T) {
	catalog := fixture.New()

	t.Run("a category count is the number selecting it would yield", func(t *testing.T) {
		page, err := catalog.Catalog(context.Background(), view.CatalogQuery{})
		require.NoError(t, err)
		require.Equal(t, 4, countOf(t, page.Categories, "Infrastructure"))

		narrowed, err := catalog.Catalog(context.Background(), view.CatalogQuery{Kind: view.KindFilterPlugins})
		require.NoError(t, err)
		require.Equal(t, 1, countOf(t, narrowed.Categories, "Infrastructure"),
			"only one of the four Infrastructure packages is a plugin")
	})

	t.Run("a category count ignores the category selection it belongs to", func(t *testing.T) {
		page, err := catalog.Catalog(context.Background(), view.CatalogQuery{Categories: []string{"Data"}})
		require.NoError(t, err)
		require.Equal(t, 4, countOf(t, page.Categories, "Infrastructure"),
			"selecting Data must not zero every other option, or the facet could never be widened")
	})

	t.Run("a tag count is the drill-down count under AND semantics", func(t *testing.T) {
		page, err := catalog.Catalog(context.Background(), view.CatalogQuery{Tags: []string{"terraform"}})
		require.NoError(t, err)
		require.Equal(t, 2, countOf(t, page.Tags, "guardrails"),
			"two of the terraform packages also carry guardrails")
		require.Equal(t, 0, countOf(t, page.Tags, "postgres"))
	})

	t.Run("the selected options come back marked", func(t *testing.T) {
		page, err := catalog.Catalog(context.Background(), view.CatalogQuery{
			Categories: []string{"Data"}, Tags: []string{"postgres"},
		})
		require.NoError(t, err)
		require.True(t, selectedOf(t, page.Categories, "Data"))
		require.True(t, selectedOf(t, page.Tags, "postgres"))
		require.False(t, selectedOf(t, page.Tags, "terraform"))
	})
}

func TestScaled(t *testing.T) {
	t.Run("reaches the requested row count", func(t *testing.T) {
		require.Len(t, fixture.Scaled(10000).Rows(), 10000)
	})

	t.Run("keeps package ids unique so a row is addressable", func(t *testing.T) {
		seen := map[string]struct{}{}
		for _, row := range fixture.Scaled(10000).Rows() {
			_, dup := seen[row.ID]
			require.Falsef(t, dup, "duplicate id %s", row.ID)
			seen[row.ID] = struct{}{}
		}
	})

	t.Run("offers at least the 50 tag options the R7 exit criterion names", func(t *testing.T) {
		page, err := fixture.Scaled(10000).Catalog(context.Background(), view.CatalogQuery{})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(page.Tags), 50)
	})

	t.Run("pages rather than returning everything", func(t *testing.T) {
		page, err := fixture.Scaled(10000).Catalog(context.Background(), view.CatalogQuery{})
		require.NoError(t, err)
		require.Len(t, page.Rows, view.DefaultPageSize)
		require.Equal(t, 10000, page.Total)
		require.Equal(t, 1000, page.Pages())
	})

	t.Run("clamps a page number past the end onto the last page", func(t *testing.T) {
		page, err := fixture.New().Catalog(context.Background(), view.CatalogQuery{Page: 99})
		require.NoError(t, err)
		require.NotEmpty(t, page.Rows)
	})

	t.Run("a request below the base size still returns the base rows", func(t *testing.T) {
		require.Len(t, fixture.Scaled(3).Rows(), 10)
	})
}

func countOf(t *testing.T, options []view.FacetOption, label string) int {
	t.Helper()
	for _, option := range options {
		if option.Label == label {
			return option.Count
		}
	}
	t.Fatalf("no option %q", label)
	return 0
}

func selectedOf(t *testing.T, options []view.FacetOption, label string) bool {
	t.Helper()
	for _, option := range options {
		if option.Label == label {
			return option.Selected
		}
	}
	t.Fatalf("no option %q", label)
	return false
}
