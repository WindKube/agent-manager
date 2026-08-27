package fetch_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/bundle"
	"agent-manager/internal/fetch"
)

const testPluginManifest = `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"platform-toolkit","version":"1.3.0"}`

// rewriteClient is a fetch.Client that sends every request to one test server,
// keeping the path and headers the caller built.
//
// This is the seam that makes the go-github path testable without reaching
// GitHub: the assertion that matters is which endpoint go-github built and how the
// answer is classified, and both are visible here. It implements fetch.Client
// rather than wrapping an http.Transport so the production client's own behaviour
// is never partially bypassed — the SSRF suite in safe_test.go is what tests that.
type rewriteClient struct {
	server *httptest.Server
	seen   []string
}

func (c *rewriteClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	c.seen = append(c.seen, req.URL.Path)

	target, err := url.Parse(c.server.URL)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(ctx)
	clone.URL.Scheme, clone.URL.Host = target.Scheme, target.Host
	clone.Host = ""
	return c.server.Client().Do(clone)
}

func (c *rewriteClient) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

func TestUploadSourceExtractsUnderTheR3Caps(t *testing.T) {
	source := fetch.NewUploadSource()
	require.Equal(t, "upload", source.Name())
	require.True(t, source.Handles(fetch.SourceRef{Kind: fetch.SourceUpload}))
	require.False(t, source.Handles(fetch.SourceRef{Kind: fetch.SourceGit}))

	t.Run("a zip at the archive root is rooted at .", func(t *testing.T) {
		archive := zipArchive(t, map[string]string{
			"plugin.json":       testPluginManifest,
			"skills/x/SKILL.md": "---\nname: x\ndescription: y\n---\n",
			"README.md":         "# hi\n",
		})
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive), ArchiveName: "platform-toolkit-1.3.0.zip",
		})
		require.NoError(t, err)
		require.Equal(t, ".", tree.Root)
		require.Equal(t, "upload platform-toolkit-1.3.0.zip", tree.Origin)
		require.Contains(t, tree.Files.Paths(), "plugin.json")
	})

	t.Run("a single wrapping directory holding the manifest becomes the root", func(t *testing.T) {
		archive := zipArchive(t, map[string]string{
			"platform-toolkit-1.3.0/plugin.json":       testPluginManifest,
			"platform-toolkit-1.3.0/skills/x/SKILL.md": "---\nname: x\ndescription: y\n---\n",
		})
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive),
		})
		require.NoError(t, err)
		require.Equal(t, "platform-toolkit-1.3.0", tree.Root)
	})

	t.Run("a lone directory with no manifest is not mistaken for a wrapper", func(t *testing.T) {
		// A tree whose root holds only skills/ is a legitimate shape. Stripping it
		// would publish the inside of a skill as if it were the package.
		archive := zipArchive(t, map[string]string{"skills/x/SKILL.md": "---\nname: x\ndescription: y\n---\n"})
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive),
		})
		require.NoError(t, err)
		require.Equal(t, ".", tree.Root)
	})

	t.Run("an explicit subdirectory is never second-guessed", func(t *testing.T) {
		archive := zipArchive(t, map[string]string{
			"plugin.json":                          testPluginManifest,
			"plugins/platform-toolkit/plugin.json": testPluginManifest,
		})
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceUpload, Archive: bytes.NewReader(archive), Subdirectory: "plugins/platform-toolkit",
		})
		require.NoError(t, err)
		require.Equal(t, "plugins/platform-toolkit", tree.Root)
	})

	// The negative control: the caps are internal/bundle's and the source must not
	// have its own reading of them.
	t.Run("a cap failure reaches the caller as a bundle error", func(t *testing.T) {
		archive := zipArchive(t, map[string]string{"plugin.json": testPluginManifest, "big": strings.Repeat("a", 4096)})
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind:    fetch.SourceUpload,
			Archive: bytes.NewReader(archive),
			Limits:  bundle.Limits{MaxEntryBytes: 16},
		})
		require.ErrorIs(t, err, bundle.ErrTooLarge)
	})

	t.Run("no archive is an error rather than an empty tree", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{Kind: fetch.SourceUpload})
		require.Error(t, err)
	})
}

func TestGitSourceUsesTheTarballEndpointAndNeverAShell(t *testing.T) {
	tarball := forgeTarball(t, "example-platform-toolkit-9f1c2ab", map[string]string{
		"plugin.json":                           testPluginManifest,
		"skills/terraform-plan-review/SKILL.md": "---\nname: terraform-plan-review\ndescription: y\n---\n",
		"plugins/nested/plugin.json":            testPluginManifest,
	})

	var served int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example/platform-toolkit/tarball/v1.3.0":
			served++
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tarball)
		case "/repos/example/platform-toolkit/tarball/v9.9.9":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case "/repos/example/private/tarball/HEAD":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Must have admin rights to Repository."}`))
		case "/repos/example/broken/tarball/HEAD":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"boom"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"unexpected path ` + r.URL.Path + `"}`))
		}
	}))
	defer server.Close()

	client := &rewriteClient{server: server}
	source, err := fetch.NewGitSource(client)
	require.NoError(t, err)
	require.Equal(t, "git", source.Name())

	t.Run("the endpoint is repos/{owner}/{repo}/tarball/{ref}", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v1.3.0",
		})
		require.NoError(t, err)
		require.Equal(t, 1, served)
		require.Equal(t, []string{"/repos/example/platform-toolkit/tarball/v1.3.0"}, client.seen)

		// The forge's unpredictable `owner-repo-<sha>/` wrapper is what Root strips.
		require.Equal(t, "example-platform-toolkit-9f1c2ab", tree.Root)
		require.Equal(t, "git https://github.com/example/platform-toolkit.git@v1.3.0", tree.Origin)
	})

	t.Run("a subdirectory is applied inside the wrapper", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit",
			Ref: "v1.3.0", Subdirectory: "plugins/nested",
		})
		require.NoError(t, err)
		require.Equal(t, "example-platform-toolkit-9f1c2ab/plugins/nested", tree.Root)
		require.Contains(t, tree.Origin, "(plugins/nested)")
	})

	// T045: each of these is a FETCH error with its own reason, and none of them is
	// a scan finding.
	t.Run("a missing ref is a fetch error naming the ref", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v9.9.9",
		})
		require.ErrorIs(t, err, fetch.ErrRefNotFound)
	})

	t.Run("an absent subdirectory is a fetch error, not an empty publish", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit",
			Ref: "v1.3.0", Subdirectory: "plugins/absent",
		})
		require.ErrorIs(t, err, fetch.ErrRefNotFound)
		require.Contains(t, err.Error(), "plugins/absent")
	})

	t.Run("a repository needing credentials the hub does not hold says so", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/private",
		})
		require.ErrorIs(t, err, fetch.ErrCredentialsRequired)
	})

	t.Run("any other refusal is reported as the remote's", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/broken",
		})
		require.ErrorIs(t, err, fetch.ErrRemote)
	})

	t.Run("an unparseable reference is refused before any request", func(t *testing.T) {
		before := len(client.seen)
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/../../etc/passwd",
		})
		require.Error(t, err)
		require.Len(t, client.seen, before, "a bad reference must not reach the network")
	})
}

func TestArchiveURLSourceFetchesThroughTheInjectedClient(t *testing.T) {
	archive := zipArchive(t, map[string]string{"plugin.json": testPluginManifest})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/platform-toolkit-1.3.0.zip":
			_, _ = w.Write(archive)
		case "/dist/gone.zip":
			w.WriteHeader(http.StatusNotFound)
		case "/dist/private.zip":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer server.Close()

	source := fetch.NewArchiveURLSource(&rewriteClient{server: server})
	require.Equal(t, "archive-url", source.Name())

	t.Run("a served archive becomes a tree", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceArchiveURL, URL: "https://cdn.example.dev/dist/platform-toolkit-1.3.0.zip",
		})
		require.NoError(t, err)
		require.Equal(t, ".", tree.Root)
		require.Contains(t, tree.Origin, "platform-toolkit-1.3.0.zip")
	})

	for _, tc := range []struct {
		name, path string
		want       error
	}{
		{name: "404 is a missing ref", path: "/dist/gone.zip", want: fetch.ErrRefNotFound},
		{name: "401 is a credential the hub does not hold", path: "/dist/private.zip", want: fetch.ErrCredentialsRequired},
		{name: "anything else is the remote's refusal", path: "/dist/teapot.zip", want: fetch.ErrRemote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := source.Fetch(context.Background(), fetch.SourceRef{
				Kind: fetch.SourceArchiveURL, URL: "https://cdn.example.dev" + tc.path,
			})
			require.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("a credential in the origin string is redacted", func(t *testing.T) {
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceArchiveURL,
			URL:  "https://user:hunter2@cdn.example.dev/dist/gone.zip",
		})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "hunter2")
	})
}

func TestRegistryRoutesByKindAndByShape(t *testing.T) {
	upload := fetch.NewUploadSource()
	git, err := fetch.NewGitSource(&rewriteClient{})
	require.NoError(t, err)
	archive := fetch.NewArchiveURLSource(&rewriteClient{})

	registry := fetch.NewRegistry(upload, git, archive)
	require.Len(t, registry.Sources(), 3)

	for _, tc := range []struct {
		name string
		ref  fetch.SourceRef
		want string
	}{
		{name: "an explicit upload", ref: fetch.SourceRef{Kind: fetch.SourceUpload}, want: "upload"},
		{name: "an explicit git", ref: fetch.SourceRef{Kind: fetch.SourceGit}, want: "git"},
		{name: "an explicit archive url", ref: fetch.SourceRef{Kind: fetch.SourceArchiveURL}, want: "archive-url"},
		{name: "a pasted repository url", ref: fetch.SourceRef{URL: "https://github.com/org/plugin"}, want: "git"},
		{name: "a pasted zip url", ref: fetch.SourceRef{URL: "https://cdn.example.dev/p-1.0.0.zip"}, want: "archive-url"},
		{name: "a pasted tar.gz url", ref: fetch.SourceRef{URL: "https://cdn.example.dev/p-1.0.0.tar.gz"}, want: "archive-url"},
	} {
		t.Run(tc.name+" routes to "+tc.want, func(t *testing.T) {
			source, err := registry.For(tc.ref)
			require.NoError(t, err)
			require.Equal(t, tc.want, source.Name())
		})
	}

	t.Run("an unroutable reference is refused rather than defaulted", func(t *testing.T) {
		_, err := registry.For(fetch.SourceRef{Kind: "oci"})
		require.ErrorIs(t, err, fetch.ErrNoSource)
	})
}

// zipArchive builds a zip in memory.
func zipArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, body := range files {
		w, err := zw.Create(path)
		require.NoError(t, err)
		_, err = io.WriteString(w, body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// forgeTarball builds the shape a forge's tarball endpoint returns: every entry
// under one `owner-repo-<sha>/` directory.
func forgeTarball(t *testing.T, wrapper string, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir, Name: wrapper + "/", Mode: 0o755,
	}))
	for path, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     fmt.Sprintf("%s/%s", wrapper, path),
			Mode:     0o644,
			Size:     int64(len(body)),
		}))
		_, err := io.WriteString(tw, body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
