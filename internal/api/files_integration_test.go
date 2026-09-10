//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/bundle"
	"agent-manager/internal/store/models"
)

// The package files operations (US3/US5: read a skill's files before using
// it) over a REAL packed bundle: internal/bundle.Pack producing the bytes,
// a real (in-memory) bucket holding them, and internal/bundle.Unpack — the
// same extraction the fetcher uses on ingestion — reading them back. A
// handler-shaped test with a fake bundle.Bundle would not catch a mistake in
// how the archive is actually walked.

// packBundle builds and packs a bundle.Bundle from path/content pairs, the
// smallest reusable seam between "what a fixture wants a file to contain"
// and internal/bundle's real tar+zstd writer.
func packBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()

	b := bundle.New()
	for path, content := range files {
		require.NoError(t, b.Add(path, 0o644, []byte(content)))
	}
	packed, _, _, err := bundle.Pack(b)
	require.NoError(t, err)
	data, err := io.ReadAll(packed)
	require.NoError(t, err)
	return data
}

// seedPackageWithBundle inserts a publisher, package and one visible version
// pointed to by latest_version_id — the same relation every other "latest"
// read in this api joins through (queries.LatestBundle included) — and
// returns the object key the bytes were packed under, for the caller to
// write into the bucket liveHandler serves from.
func seedPackageWithBundle(t *testing.T, namespace, name string, verdict models.Verdict, key string) {
	t.Helper()
	ctx := context.Background()

	publisher := &models.Publisher{ID: models.NewID(), Slug: namespace + "/" + name, DisplayName: namespace}
	_, err := db.NewInsert().Model(publisher).Exec(ctx)
	require.NoError(t, err)

	pkg := &models.Package{
		ID: models.NewID(), PublisherID: publisher.ID, Namespace: namespace, Name: name,
		Kind: models.PackageKindSkill, Visibility: models.PackageVisibilityOrganisation,
	}
	_, err = db.NewInsert().Model(pkg).Exec(ctx)
	require.NoError(t, err)

	version := &models.Version{
		ID: models.NewID(), PackageID: pkg.ID, Semver: "1.0.0", SemverSort: "1.0.0",
		ObjectKey: key, Digest: bytes.Repeat([]byte{0xEE}, 32),
		Manifest: json.RawMessage(`{"name":"` + name + `"}`),
		Tags:     []string{},
		DistTag:  models.DistTagLatest, Verdict: verdict, Visible: true,
	}
	_, err = db.NewInsert().Model(version).Exec(ctx)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `update package set latest_version_id = $1 where id = $2`, version.ID, pkg.ID)
	require.NoError(t, err)
}

func TestPackageFilesServesTheLatestVisibleVersionsRealBundle(t *testing.T) {
	const bigBody = "big file body byte " // repeated past the 256 KiB render cap below
	big := bytes.Repeat([]byte(bigBody), (300*1024/len(bigBody))+1)

	packed := packBundle(t, map[string]string{
		"SKILL.md":        "# Read me first\n\nDo this, then that.\n",
		"notes.txt":       "plain notes, nothing fancy",
		"assets/logo.png": "\x89PNG\x00\x0d\x0a\x1a\x0a" + "binary-ish payload with a NUL byte \x00 in it",
		"big.md":          string(big),
	})
	key := "skills/filestest/reader-demo/1.0.0/bundle.tar.zst"
	seedPackageWithBundle(t, "filestest", "reader-demo", models.VerdictClean, key)

	handler := liveHandler(t, map[string][]byte{key: packed})

	var list contract.PackageFileList
	t.Run("the list names every file, classified, with a default", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files", kw.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Equal(t, "SKILL.md", list.Default)

		byPath := map[string]contract.PackageFile{}
		for _, f := range list.Files {
			byPath[f.Path] = f
		}
		require.Equal(t, "markdown", byPath["SKILL.md"].Kind)
		require.False(t, byPath["SKILL.md"].OverLimit)
		require.Equal(t, "text", byPath["notes.txt"].Kind)
		require.Equal(t, "binary", byPath["assets/logo.png"].Kind)
		require.Equal(t, "markdown", byPath["big.md"].Kind)
		require.True(t, byPath["big.md"].OverLimit, "the list must flag an oversized file rather than let the size speak for itself")
	})

	t.Run("a markdown file's content comes back verbatim, marked for the markdown pipeline", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files/content?path=SKILL.md", kw.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var content contract.PackageFileContent
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &content))
		require.Equal(t, "markdown", content.Kind)
		require.Contains(t, content.Content, "Read me first")
	})

	t.Run("a text file is marked for verbatim escaped rendering", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files/content?path=notes.txt", kw.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var content contract.PackageFileContent
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &content))
		require.Equal(t, "text", content.Kind)
		require.Equal(t, "plain notes, nothing fancy", content.Content)
	})

	t.Run("a binary member is refused, not rendered", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files/content?path=assets/logo.png", kw.token, "")
		require.Equal(t, http.StatusUnsupportedMediaType, rec.Code, rec.Body.String())
	})

	t.Run("a file over the render cap is refused outright, not truncated", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files/content?path=big.md", kw.token, "")
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), bigBody, "a refusal must carry none of the file, not even a prefix")
	})

	t.Run("a path that names no archive member is a 404, never a filesystem lookup", func(t *testing.T) {
		for _, path := range []string{
			"../../../../etc/passwd", "/etc/passwd", "..%2F..%2Fetc%2Fpasswd", "SKILL.md/../../etc/passwd",
		} {
			rec := request(t, handler, http.MethodGet,
				"/v1/packages/filestest/reader-demo/files/content?path="+path, kw.token, "")
			require.Equalf(t, http.StatusNotFound, rec.Code, "path %q: %s", path, rec.Body.String())
		}
	})

	t.Run("no token is a 401 on both operations", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files", "", "")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		rec = request(t, handler, http.MethodGet, "/v1/packages/filestest/reader-demo/files/content?path=SKILL.md", "", "")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("an unknown package is a 404 on both operations", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/no-such-package/files", kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code)
		rec = request(t, handler, http.MethodGet, "/v1/packages/filestest/no-such-package/files/content?path=SKILL.md", kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// TestPackageFilesRefusesARejectedLatestVersionOnBothOperations is FR-029 for
// this pair of operations: a rejected version is never served, exactly as
// getBundle refuses one — checked here at the LATEST-version door these two
// operations use, which getBundle's own version-addressed test does not
// exercise.
func TestPackageFilesRefusesARejectedLatestVersionOnBothOperations(t *testing.T) {
	packed := packBundle(t, map[string]string{"SKILL.md": "# Should never be served\n"})
	key := "skills/filestest/rejected-latest/1.0.0/bundle.tar.zst"
	seedPackageWithBundle(t, "filestest", "rejected-latest", models.VerdictRejected, key)

	handler := liveHandler(t, map[string][]byte{key: packed})

	rec := request(t, handler, http.MethodGet, "/v1/packages/filestest/rejected-latest/files", kw.token, "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	rec = request(t, handler, http.MethodGet,
		"/v1/packages/filestest/rejected-latest/files/content?path=SKILL.md", kw.token, "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}
