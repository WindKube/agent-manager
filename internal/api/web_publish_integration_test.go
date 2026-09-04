//go:build integration

// TestPublishingThroughTheWebScreenMatchesWhatTheWireContractServes is the
// closest this module can come to running "the CLI's own operation" against a
// revision the web screen just published (T090).
//
// The CLI lives in its own Go module (cli/go.mod forbids a replace directive
// back to this one on purpose, so `go install .../cli@latest` keeps working for
// everyone outside this tree), and its getRevision call is inside an internal
// package of that module — unreachable from here regardless of archcheck, which
// only governs imports within this module. What this test exercises instead is
// the identical wire operation, GET /v1/profiles/{slug}/revisions/head, which is
// the exact request the CLI's generated client sends and the exact contract
// internal/apiclient and the CLI's client are both generated from (constitution
// principle V). A real web.Server, backed by the real api over httptest, creates
// a profile and publishes a revision; the test then reads that revision back
// over the wire and asserts it matches what the screen displayed.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
	"agent-manager/internal/web"
	"agent-manager/internal/web/hub"
)

func TestPublishingThroughTheWebScreenMatchesWhatTheWireContractServes(t *testing.T) {
	apiServer := httptest.NewServer(liveHandler(t))
	t.Cleanup(apiServer.Close)

	client, err := hub.New(apiServer.URL)
	require.NoError(t, err)

	webHandler := web.New(web.Deps{
		Catalog: client, Packages: client, Viewers: client, Sessions: client,
		Profiles: client, Curator: client, Log: zerolog.Nop(),
	}, web.Options{}).Handler()

	const slug = "e2e-web-cli"
	postFormAsBrowser(t, webHandler, "/profiles", url.Values{
		"slug": {slug}, "name": {"E2E web-to-CLI"}, "visibility": {"private"},
	}, kw.token)

	// The web screens offer no way to add a package to a profile yet (there is
	// no "add to profile" action from the catalog), so the one live entry this
	// test needs is seeded directly, the same way seed() populates the catalog
	// this test already runs against.
	packageID := packageIDFor(t, "acme", "code-review")
	insertEntry(t, slug, packageID)

	postFormAsBrowser(t, webHandler, "/profiles/revisions", url.Values{
		"slug": {slug}, "note": {"published through the web screen"},
	}, kw.token)

	screen := getBody(t, webHandler, "/profiles/"+slug, kw.token)
	require.Contains(t, screen, "code-review")
	require.Contains(t, screen, "2.4.1")

	rec := request(t, liveHandler(t), http.MethodGet, "/v1/profiles/"+slug+"/revisions/head", kw.token, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var lock contract.Lockfile
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lock))

	require.Len(t, lock.Entries, 1)
	require.Equal(t, "acme/code-review", lock.Entries[0].ID)
	require.Equal(t, "2.4.1", lock.Entries[0].Version)
	require.Contains(t, screen, lock.Entries[0].Version,
		"the version the screen displayed must be the version the wire contract serves")
}

func packageIDFor(t *testing.T, namespace, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.NewSelect().Table("package").Column("id").
		Where("namespace = ? and name = ?", namespace, name).Scan(context.Background(), &id)
	require.NoError(t, err)
	return id
}

func insertEntry(t *testing.T, slug string, packageID uuid.UUID) {
	t.Helper()

	var profileID uuid.UUID
	require.NoError(t, db.NewSelect().Table("profile").Column("id").
		Where("slug = ?", slug).Scan(context.Background(), &profileID))

	_, err := db.NewInsert().Model(&models.ProfileEntry{
		ProfileID: profileID,
		PackageID: packageID,
		Mode:      models.EntryModeLatest,
		Position:  0,
	}).Exec(context.Background())
	require.NoError(t, err)
}

func postFormAsBrowser(t *testing.T, h http.Handler, path string, form url.Values, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "am_session", Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getBody(t *testing.T, h http.Handler, path, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	req.AddCookie(&http.Cookie{Name: "am_session", Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	return rec.Body.String()
}
