package fakeapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

func TestRoutesExistInTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../apiclient/openapi.json")
	require.NoError(t, err)
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	contract := map[string]string{}
	for path, ops := range doc.Paths {
		for method, op := range ops {
			if op.OperationID != "" {
				contract[op.OperationID] = strings.ToUpper(method) + " " + path
			}
		}
	}
	for op, route := range fakeapi.Routes() {
		require.Equal(t, contract[op], route, "operation %s", op)
	}
}

func TestTheSeedDecodesThroughTheRealClient(t *testing.T) {
	api := fakeapi.New(t)
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	ctx := view.WithToken(t.Context(), "fake-session-token")

	viewer, err := client.Viewer(ctx)
	require.NoError(t, err)
	require.True(t, viewer.HasRole)

	page, err := client.Catalog(ctx, view.CatalogQuery{})
	require.NoError(t, err)
	require.Equal(t, 10, page.Total)

	plugins, err := client.Catalog(ctx, view.CatalogQuery{Kind: view.KindFilterPlugins})
	require.NoError(t, err)
	require.Equal(t, 4, plugins.Total)

	for _, id := range []string{"example/platform-toolkit", "example/pii-redactor"} {
		ns, name, _ := strings.Cut(id, "/")
		_, pkgErr := client.Package(ctx, ns, name)
		require.NoError(t, pkgErr, id)
	}

	_, err = client.Profiles(ctx)
	require.NoError(t, err)
	_, err = client.Findings(ctx, hub.FindingQuery{})
	require.NoError(t, err)
	_, err = client.Organization(ctx)
	require.NoError(t, err)
	_, err = client.Storage(ctx)
	require.NoError(t, err)
	_, err = client.Runtime(ctx)
	require.NoError(t, err)
}

func TestNoBearerIsSignedOut(t *testing.T) {
	api := fakeapi.New(t)
	client, err := hub.New(api.URL)
	require.NoError(t, err)

	_, err = client.Catalog(t.Context(), view.CatalogQuery{})
	require.ErrorIs(t, err, view.ErrSignedOut)
}

func TestFailOverridesOneOperation(t *testing.T) {
	api := fakeapi.New(t)
	api.Fail("getStorage", http.StatusServiceUnavailable)
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	ctx := view.WithToken(t.Context(), "fake-session-token")

	_, err = client.Storage(ctx)
	require.Error(t, err)
	_, err = client.Runtime(ctx)
	require.NoError(t, err)
	require.Len(t, api.Calls("getStorage"), 1)
}

func TestCatalogFiltering(t *testing.T) {
	tests := []struct {
		name    string
		query   view.CatalogQuery
		wantIDs []string
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

	client, ctx := seededClient(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, err := client.Catalog(ctx, tc.query)
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
	client, ctx := seededClient(t)

	t.Run("a category count is the number selecting it would yield", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{})
		require.NoError(t, err)
		require.Equal(t, 4, countOf(t, page.Categories, "Infrastructure"))

		narrowed, err := client.Catalog(ctx, view.CatalogQuery{Kind: view.KindFilterPlugins})
		require.NoError(t, err)
		require.Equal(t, 1, countOf(t, narrowed.Categories, "Infrastructure"),
			"only one of the four Infrastructure packages is a plugin")
	})

	t.Run("a category count ignores the category selection it belongs to", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{Categories: []string{"Data"}})
		require.NoError(t, err)
		require.Equal(t, 4, countOf(t, page.Categories, "Infrastructure"),
			"selecting Data must not zero every other option, or the facet could never be widened")
	})

	t.Run("a tag count is the drill-down count under AND semantics", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{Tags: []string{"terraform"}})
		require.NoError(t, err)
		require.Equal(t, 2, countOf(t, page.Tags, "guardrails"),
			"two of the terraform packages also carry guardrails")
		require.Equal(t, 0, countOf(t, page.Tags, "postgres"))
	})

	t.Run("the selected options come back marked", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{
			Categories: []string{"Data"}, Tags: []string{"postgres"},
		})
		require.NoError(t, err)
		require.True(t, selectedOf(t, page.Categories, "Data"))
		require.True(t, selectedOf(t, page.Tags, "postgres"))
		require.False(t, selectedOf(t, page.Tags, "terraform"))
	})
}

func TestScale(t *testing.T) {
	api := fakeapi.New(t)
	api.Data.Scale(10000)
	client, err := hub.New(api.URL)
	require.NoError(t, err)
	ctx := view.WithToken(t.Context(), "fake-session-token")

	t.Run("keeps package ids unique so a row is addressable", func(t *testing.T) {
		require.Len(t, api.Data.Packages, 10000)
		seen := map[string]struct{}{}
		for _, row := range api.Data.Packages {
			_, dup := seen[row.Id]
			require.Falsef(t, dup, "duplicate id %s", row.Id)
			seen[row.Id] = struct{}{}
		}
	})

	t.Run("offers at least the 50 tag options the R7 exit criterion names", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(page.Tags), 50)
	})

	t.Run("pages rather than returning everything", func(t *testing.T) {
		page, err := client.Catalog(ctx, view.CatalogQuery{})
		require.NoError(t, err)
		require.Len(t, page.Rows, view.DefaultPageSize)
		require.Equal(t, 10000, page.Total)
		require.Equal(t, 1000, page.Pages())
	})
}

func TestAPageNumberPastTheEndClampsOntoTheLastPage(t *testing.T) {
	client, ctx := seededClient(t)
	page, err := client.Catalog(ctx, view.CatalogQuery{Page: 99})
	require.NoError(t, err)
	require.NotEmpty(t, page.Rows)
}

func seededClient(t *testing.T) (*hub.Client, context.Context) {
	t.Helper()
	client, err := hub.New(fakeapi.New(t).URL)
	require.NoError(t, err)
	return client, view.WithToken(t.Context(), "fake-session-token")
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
