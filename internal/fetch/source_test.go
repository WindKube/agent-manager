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

const (
	testCommit   = "3f9c2e1d8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e"
	testCommitB  = "b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9"
	testTagObjID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
		case "/repos/example/platform-toolkit/git/ref/tags/v1.3.0":
			_, _ = fmt.Fprintf(w, `{"ref":"refs/tags/v1.3.0","object":{"type":"commit","sha":%q}}`, testCommit)
		case "/repos/example/platform-toolkit/tarball/" + testCommit:
			served++
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(tarball)
		case "/repos/example/platform-toolkit/git/ref/tags/v9.9.9",
			"/repos/example/private/git/ref/tags/HEAD", "/repos/example/broken/git/ref/tags/HEAD":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case "/repos/example/platform-toolkit/commits/v9.9.9":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"No commit found for SHA: v9.9.9"}`))
		case "/repos/example/private/commits/HEAD":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Must have admin rights to Repository."}`))
		case "/repos/example/broken/commits/HEAD":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"boom"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"unexpected path ` + r.URL.Path + `"}`))
		}
	}))
	defer server.Close()

	client := &rewriteClient{server: server}
	source, err := fetch.NewGitSource(client, "")
	require.NoError(t, err)
	require.Equal(t, "git", source.Name())

	t.Run("the ref is resolved first and the tarball fetched by that sha", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v1.3.0",
		})
		require.NoError(t, err)
		require.Equal(t, 1, served)
		require.Equal(t, []string{
			"/repos/example/platform-toolkit/git/ref/tags/v1.3.0",
			"/repos/example/platform-toolkit/tarball/" + testCommit,
		}, client.seen)
		require.Equal(t, testCommit, tree.Commit)
		require.Equal(t, "https://github.com/example/platform-toolkit", tree.SourceURL)

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

func TestGitSourceResolvesARefToTheCommitItNamesNow(t *testing.T) {
	var accepts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example/kit/git/ref/tags/v1.0.0":
			_, _ = fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, testCommit)
		case "/repos/example/kit/git/ref/tags/v2.0.0":
			_, _ = fmt.Fprintf(w, `{"object":{"type":"tag","sha":%q}}`, testTagObjID)
		case "/repos/example/kit/git/tags/" + testTagObjID:
			_, _ = fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, testCommitB)
		case "/repos/example/kit/git/ref/tags/main", "/repos/example/kit/git/ref/tags/HEAD":
			w.WriteHeader(http.StatusNotFound)
		case "/repos/example/kit/commits/main", "/repos/example/kit/commits/HEAD":
			accepts = append(accepts, r.Header.Get("Accept"))
			_, _ = w.Write([]byte(strings.ToUpper(testCommitB)))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := &rewriteClient{server: server}
	source, err := fetch.NewGitSource(client, "")
	require.NoError(t, err)
	resolve := func(ref string) (fetch.Pin, error) {
		return source.Resolve(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/kit", Ref: ref,
		})
	}

	t.Run("a lightweight tag is one call", func(t *testing.T) {
		client.seen = nil
		pin, err := resolve("v1.0.0")
		require.NoError(t, err)
		require.Equal(t, fetch.Pin{RepoURL: "https://github.com/example/kit", Ref: "v1.0.0", Commit: testCommit, Tag: true}, pin)
		require.Len(t, client.seen, 1)
	})

	t.Run("an annotated tag is peeled to its commit", func(t *testing.T) {
		pin, err := resolve("v2.0.0")
		require.NoError(t, err)
		require.True(t, pin.Tag)
		require.Equal(t, testCommitB, pin.Commit)
	})

	t.Run("a branch is not a tag and resolves through the commits endpoint", func(t *testing.T) {
		pin, err := resolve("main")
		require.NoError(t, err)
		require.False(t, pin.Tag)
		require.Equal(t, testCommitB, pin.Commit, "the sha is normalised to lowercase")
		require.Equal(t, "application/vnd.github.sha", accepts[len(accepts)-1])
	})

	t.Run("no ref is HEAD", func(t *testing.T) {
		pin, err := resolve("")
		require.NoError(t, err)
		require.Equal(t, "HEAD", pin.Ref)
		require.False(t, pin.Tag)
	})

	t.Run("a full sha needs no request", func(t *testing.T) {
		client.seen = nil
		pin, err := resolve(strings.ToUpper(testCommit))
		require.NoError(t, err)
		require.Equal(t, testCommit, pin.Commit)
		require.Empty(t, client.seen)
	})

	t.Run("a fetch pinned to a commit does not resolve again", func(t *testing.T) {
		client.seen = nil
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/kit", Ref: "v1.0.0", Commit: testCommitB,
		})
		require.Error(t, err, "this server has no tarball")
		require.Equal(t, []string{"/repos/example/kit/tarball/" + testCommitB}, client.seen)
	})

	t.Run("a pinned value that is not a sha is refused before any request", func(t *testing.T) {
		client.seen = nil
		_, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/kit", Commit: "../../etc",
		})
		require.Error(t, err)
		require.Empty(t, client.seen)
	})
}

func TestArchiveURLSourceFetchesThroughTheInjectedClient(t *testing.T) {
	archive := zipArchive(t, map[string]string{"plugin.json": testPluginManifest})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/platform-toolkit-1.3.0.zip":
			_, _ = w.Write(archive)
		case "/dist/latest.zip":
			http.Redirect(w, r, "/dist/platform-toolkit-1.3.0.zip?X-Amz-Signature=secret", http.StatusFound)
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
		require.Empty(t, tree.Commit)
	})

	t.Run("the source url is where the bytes came from after redirects, without its query", func(t *testing.T) {
		tree, err := source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceArchiveURL, URL: "https://cdn.example.dev/dist/latest.zip",
		})
		require.NoError(t, err)
		require.True(t, strings.HasSuffix(tree.SourceURL, "/dist/platform-toolkit-1.3.0.zip"), tree.SourceURL)
		require.NotContains(t, tree.SourceURL, "secret")
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
	git, err := fetch.NewGitSource(&rewriteClient{}, "")
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

func TestProvenanceIsTheCanonicalSourceWithoutACredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  fetch.SourceRef
		want fetch.Provenance
	}{
		{
			name: "a git web path is split into repository, ref and subdirectory",
			ref:  fetch.SourceRef{Kind: fetch.SourceGit, URL: "https://github.com/Acme/Skills/tree/v1.2.0/pdf"},
			want: fetch.Provenance{Kind: fetch.SourceGit, URL: "https://github.com/acme/skills", Ref: "v1.2.0", Subdirectory: "pdf"},
		},
		{
			name: "no ref is HEAD",
			ref:  fetch.SourceRef{Kind: fetch.SourceGit, URL: "git@github.com:acme/skills.git"},
			want: fetch.Provenance{Kind: fetch.SourceGit, URL: "https://github.com/acme/skills", Ref: "HEAD"},
		},
		{
			name: "a self-hosted forge reached over http keeps its scheme",
			ref:  fetch.SourceRef{Kind: fetch.SourceGit, URL: "http://git.internal:8080/acme/skills", Ref: "main"},
			want: fetch.Provenance{Kind: fetch.SourceGit, URL: "http://git.internal:8080/acme/skills", Ref: "main"},
		},
		{
			name: "an archive keeps its url but not its userinfo, query or fragment",
			ref:  fetch.SourceRef{Kind: fetch.SourceArchiveURL, URL: "https://u:hunter2@cdn.example.dev/a.zip?v=1#top"},
			want: fetch.Provenance{Kind: fetch.SourceArchiveURL, URL: "https://cdn.example.dev/a.zip"},
		},
		{
			name: "a presigned archive url loses its signature",
			ref: fetch.SourceRef{Kind: fetch.SourceArchiveURL,
				URL: "https://bucket.s3.amazonaws.com/a.zip?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIA"},
			want: fetch.Provenance{Kind: fetch.SourceArchiveURL, URL: "https://bucket.s3.amazonaws.com/a.zip"},
		},
		{
			name: "an upload has no url",
			ref:  fetch.SourceRef{Kind: fetch.SourceUpload, ArchiveName: "a.zip"},
			want: fetch.Provenance{Kind: fetch.SourceUpload},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, fetch.ProvenanceOf(tc.ref))
		})
	}
}

func TestGitSourceAuthenticatesToTheGitHubAPIOnlyWhenGivenAToken(t *testing.T) {
	tarball := forgeTarball(t, "example-platform-toolkit-9f1c2ab", map[string]string{"plugin.json": testPluginManifest})
	for _, token := range []string{"", "ghp_test"} {
		var auth []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth = append(auth, r.Header.Get("Authorization"))
			switch r.URL.Path {
			case "/repos/example/platform-toolkit/git/ref/tags/v1.3.0":
				_, _ = fmt.Fprintf(w, `{"ref":"refs/tags/v1.3.0","object":{"type":"commit","sha":%q}}`, testCommit)
			default:
				w.Header().Set("Content-Type", "application/gzip")
				_, _ = w.Write(tarball)
			}
		}))
		source, err := fetch.NewGitSource(&rewriteClient{server: server}, token)
		require.NoError(t, err)
		_, err = source.Fetch(context.Background(), fetch.SourceRef{
			Kind: fetch.SourceGit, URL: "https://github.com/example/platform-toolkit", Ref: "v1.3.0",
		})
		server.Close()
		require.NoError(t, err)

		want := ""
		if token != "" {
			want = "Bearer " + token
		}
		require.Len(t, auth, 2)
		for _, got := range auth {
			require.Equal(t, want, got)
		}
	}
}

func TestGitSourceNeverSendsTheTokenToAnotherHost(t *testing.T) {
	tarball := forgeTarball(t, "example-kit-9f1c2ab", map[string]string{"plugin.json": testPluginManifest})
	var auth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if strings.HasSuffix(r.URL.Path, "/git/ref/tags/v1.0.0") {
			_, _ = fmt.Fprintf(w, `{"ref":"refs/tags/v1.0.0","object":{"type":"commit","sha":%q}}`, testCommit)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	source, err := fetch.NewGitSource(&rewriteClient{server: server}, "ghp_test")
	require.NoError(t, err)
	_, err = source.Fetch(context.Background(), fetch.SourceRef{
		Kind: fetch.SourceGit, URL: "https://git.attacker.example/example/kit", Ref: "v1.0.0",
	})
	require.NoError(t, err)
	require.NotEmpty(t, auth)
	for _, got := range auth {
		require.Empty(t, got)
	}
}
