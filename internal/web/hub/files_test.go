package hub_test

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The files panel's two methods, with the api stubbed and the assertions on
// the wire — same reasoning as the profile methods' own test file.

func TestPackageFilesMapsTheListSizesAndDefault(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		require.True(t, strings.HasSuffix(r.URL.Path, "/packages/example/toolkit/files"))
		writeCatalog(w, `{
			"default":"SKILL.md",
			"files":[
				{"path":"SKILL.md","kind":"markdown","sizeBytes":512},
				{"path":"notes.txt","kind":"text","sizeBytes":2048},
				{"path":"big.md","kind":"markdown","sizeBytes":900000,"overLimit":true}
			]
		}`)
	})

	list, err := client.PackageFiles(t.Context(), "example", "toolkit")
	require.NoError(t, err)
	require.Equal(t, "SKILL.md", list.Default)
	require.Len(t, list.Files, 3)
	require.Equal(t, view.FileRow{Path: "SKILL.md", Kind: "markdown", SizeLabel: "512 B"}, list.Files[0])
	require.Equal(t, view.FileRow{Path: "notes.txt", Kind: "text", SizeLabel: "2.0 KB"}, list.Files[1])
	require.True(t, list.Files[2].OverLimit)
}

func TestPackageFileParsesMarkdownContentButNotText(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "SKILL.md", r.URL.Query().Get("path"))
		writeCatalog(w, `{"path":"SKILL.md","kind":"markdown","content":"# Title\n\nBody.\n"}`)
	})

	detail, err := client.PackageFile(t.Context(), "example", "toolkit", "SKILL.md")
	require.NoError(t, err)
	require.Equal(t, "markdown", detail.Kind)
	require.NotNil(t, detail.Markdown.Root, "a markdown file's content must already be parsed for the panel")

	client = clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		writeCatalog(w, `{"path":"notes.txt","kind":"text","content":"plain"}`)
	})
	detail, err = client.PackageFile(t.Context(), "example", "toolkit", "notes.txt")
	require.NoError(t, err)
	require.Nil(t, detail.Markdown.Root, "a text file is never run through the markdown parser")
}

func TestPackageFileMapsTheThreeRefusalsToDistinctSentinels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"missing", http.StatusNotFound, view.ErrNotFound},
		{"too large", http.StatusRequestEntityTooLarge, hub.ErrFileTooLarge},
		{"binary", http.StatusUnsupportedMediaType, hub.ErrFileNotRenderable},
		{"rejected version", http.StatusForbidden, hub.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"title":"refused","status":` + strconv.Itoa(tc.status) + `,"detail":"refused"}`))
			})

			_, err := client.PackageFile(t.Context(), "example", "toolkit", "SKILL.md")
			require.Errorf(t, err, "status %d must be an error", tc.status)
			require.Truef(t, errors.Is(err, tc.want), "status %d: got %v, want it to wrap %v", tc.status, err, tc.want)
		})
	}
}
