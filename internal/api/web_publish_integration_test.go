//go:build integration

// The CLI is a separate module this one cannot import, so this test reads a
// web-published revision back via the same wire operation the CLI's client sends.
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

	webHandler := web.New(web.Deps{Hub: client, Log: zerolog.Nop()}, web.Options{}).Handler()

	const slug = "e2e-web-cli"
	postFormAsBrowser(t, webHandler, "/profiles", url.Values{
		"slug": {slug}, "name": {"E2E web-to-CLI"}, "visibility": {"private"},
	}, kw.token)

	// The web screens cannot add a package to a profile yet, so the entry is seeded directly.
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
