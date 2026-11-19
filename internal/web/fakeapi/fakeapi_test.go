package fakeapi_test

import (
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
