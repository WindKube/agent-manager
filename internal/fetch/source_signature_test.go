package fetch_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/fetch"
)

func TestUploadSourceCarriesTheUploadedBundle(t *testing.T) {
	archive := zipArchive(t, map[string]string{"plugin.json": testPluginManifest})
	source := fetch.NewUploadSource()

	tree, err := source.Fetch(context.Background(), fetch.SourceRef{
		Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive), SigstoreBundle: []byte(`{"bundle":true}`),
	})
	require.NoError(t, err)
	require.Len(t, tree.Signatures, 1)
	require.Equal(t, []byte(`{"bundle":true}`), tree.Signatures[0].Bundle)

	tree, err = source.Fetch(context.Background(), fetch.SourceRef{Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive)})
	require.NoError(t, err)
	require.Empty(t, tree.Signatures)
}

func TestArchiveURLSourceLooksForASiblingBundle(t *testing.T) {
	archive := zipArchive(t, map[string]string{"plugin.json": testPluginManifest})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/signed.zip", "/unsigned.zip", "/private.zip", "/flaky.zip":
			_, _ = w.Write(archive)
		case "/signed.zip.sigstore.json":
			_, _ = w.Write([]byte(`{"mediaType":"x"}`))
		case "/unsigned.zip.sigstore.json":
			w.WriteHeader(http.StatusNotFound)
		case "/private.zip.sigstore.json":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()
	source := fetch.NewArchiveURLSource(&rewriteClient{server: server})
	fetchURL := func(path string) (fetch.Tree, error) {
		return source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceArchiveURL, URL: "https://cdn.example.dev" + path + "?token=t",
		})
	}

	t.Run("a sibling bundle is collected", func(t *testing.T) {
		tree, err := fetchURL("/signed.zip")
		require.NoError(t, err)
		require.Len(t, tree.Signatures, 1)
		require.Equal(t, []byte(`{"mediaType":"x"}`), tree.Signatures[0].Bundle)
		require.Equal(t, "https://cdn.example.dev/signed.zip.sigstore.json", tree.Signatures[0].Origin)
	})

	for _, path := range []string{"/unsigned.zip", "/private.zip"} {
		t.Run(path+" without a readable bundle is unsigned", func(t *testing.T) {
			tree, err := fetchURL(path)
			require.NoError(t, err)
			require.Empty(t, tree.Signatures)
		})
	}

	t.Run("any other failure is the remote's, to retry, not unsigned", func(t *testing.T) {
		_, err := fetchURL("/flaky.zip")
		require.ErrorIs(t, err, fetch.ErrRemote)
	})
}

func TestGitSourceCollectsReleaseBundles(t *testing.T) {
	tarball := forgeTarball(t, "example-platform-toolkit-9f1c2ab", map[string]string{"plugin.json": testPluginManifest})
	var auth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example/platform-toolkit/git/ref/tags/v1.3.0", "/repos/example/platform-toolkit/git/ref/tags/v2.0.0":
			_, _ = fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, testCommit)
		case "/repos/example/platform-toolkit/tarball/" + testCommit:
			_, _ = w.Write(tarball)
		case "/repos/example/platform-toolkit/releases/tags/v1.3.0":
			_, _ = w.Write([]byte(`{"assets":[
				{"id":1,"name":"checksums.txt","size":10},
				{"id":2,"name":"notes.sigstore.json","size":10},
				{"id":3,"name":"platform-toolkit-1.3.0.tar.gz.sigstore.json","size":10},
				{"id":4,"name":"huge.sigstore.json","size":99999999}]}`))
		case "/repos/example/platform-toolkit/releases/assets/2":
			auth = append(auth, r.Header.Get("Authorization"))
			require.Equal(t, "application/octet-stream", r.Header.Get("Accept"))
			_, _ = w.Write([]byte(`notes`))
		case "/repos/example/platform-toolkit/releases/assets/3":
			_, _ = w.Write([]byte(`tarball`))
		case "/repos/example/platform-toolkit/releases/tags/v2.0.0":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	source, err := fetch.NewGitSource(&rewriteClient{server: server}, "ghp_test")
	require.NoError(t, err)

	t.Run("sigstore assets of the tag's release are collected, tarball bundles first", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v1.3.0",
		})
		require.NoError(t, err)
		require.Len(t, tree.Signatures, 2)
		require.Equal(t, []byte("tarball"), tree.Signatures[0].Bundle)
		require.Contains(t, tree.Signatures[0].Origin, "platform-toolkit-1.3.0.tar.gz.sigstore.json")
		require.Equal(t, []byte("notes"), tree.Signatures[1].Bundle)
		require.Equal(t, []string{"Bearer ghp_test"}, auth)
	})

	t.Run("a failing release lookup is retried, not called unsigned", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v2.0.0",
		})
		require.ErrorIs(t, err, fetch.ErrRemote)
		require.NotErrorIs(t, err, fetch.ErrRefNotFound)
	})

	t.Run("a commit has no release to look up", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: testCommit,
		})
		require.NoError(t, err)
		require.Empty(t, tree.Signatures)
	})
}
