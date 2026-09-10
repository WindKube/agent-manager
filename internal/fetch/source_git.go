package fetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v90/github"

	"agent-manager/internal/bundle"
	"agent-manager/internal/repourl"
)

// GitSource fetches a repository at a ref. It does not shell out to `git
// clone`; the repository arrives as the forge's own
// `repos/{owner}/{repo}/tarball/{ref}` archive, pulled through the
// SSRF-hardened Client.
type GitSource struct {
	client Client

	// api is a request builder only: every request it builds is handed to
	// s.client.Do instead of its own http.Client.
	api *github.Client
}

func NewGitSource(client Client) (GitSource, error) {
	api, err := github.NewClient()
	if err != nil {
		return GitSource{}, fmt.Errorf("build the github request builder: %w", err)
	}
	return GitSource{client: client, api: api}, nil
}

var _ Source = GitSource{}

func (GitSource) Name() string { return string(SourceGit) }

func (GitSource) Handles(ref SourceRef) bool {
	if ref.Kind == SourceGit {
		return true
	}
	return ref.Kind == "" && ref.URL != "" && !IsArchiveURL(ref.URL)
}

// DefaultRef is the ref used when a registration names none.
const DefaultRef = "HEAD"

func (s GitSource) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	if s.client == nil {
		return Tree{}, errors.New("git source: no outbound client")
	}

	repo, err := repourl.ParseWith(ref.URL, ref.Ref, ref.Subdirectory)
	if err != nil {
		return Tree{}, err
	}

	api, err := s.apiFor(repo.Host, apiScheme(ref.URL))
	if err != nil {
		return Tree{}, err
	}

	gitRef := repo.Ref
	if gitRef == "" {
		gitRef = DefaultRef
	}

	// Every segment came through repourl, which rejects a traversal
	// component rather than cleaning it.
	endpoint := fmt.Sprintf("repos/%s/%s/tarball/%s", repo.Owner, repo.Repo, gitRef)
	request, err := api.NewRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Tree{}, fmt.Errorf("build tarball request for %s: %w", repo, err)
	}

	resp, err := s.client.Do(ctx, request)
	if err != nil {
		return Tree{}, fmt.Errorf("fetch %s: %w", repo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if statusErr := githubError(resp, repo); statusErr != nil {
		return Tree{}, statusErr
	}

	// A forge tarball is always gzipped tar; the format is not sniffed.
	files, err := bundle.ExtractTarGz(ctx, resp.Body, ref.Limits)
	if err != nil {
		return Tree{}, fmt.Errorf("extract %s: %w", repo, err)
	}

	// A forge tarball wraps the tree in one unpredictable `owner-repo-<sha>/`
	// directory; stripping it is this Source's job alone.
	wrapper, _ := singleTopLevelDirectory(files)

	root := packageRoot(files, wrapper, repo.Subdir)
	if !hasManifestUnder(files, root) {
		if repo.Subdir != "" {
			return Tree{}, fmt.Errorf("%w: %s has no %s or %s under %q",
				ErrRefNotFound, repo, pluginManifestName, skillManifestName, repo.Subdir)
		}
		return Tree{}, fmt.Errorf("%w: %s has no %s or %s at its root",
			ErrRefNotFound, repo, pluginManifestName, skillManifestName)
	}

	return Tree{Files: files, Root: root, Origin: "git " + repo.CloneURL() + "@" + gitRef + subdirectorySuffix(repo.Subdir)}, nil
}

// apiFor returns a request builder pointed at the right base URL. github.com
// uses the public API; any other host is treated as a GitHub Enterprise
// Server.
func (s GitSource) apiFor(host, scheme string) (*github.Client, error) {
	if host == repourl.DefaultHost || strings.HasSuffix(host, ".github.com") {
		return s.api, nil
	}

	base := scheme + "://" + host + "/"
	api, err := github.NewClient(github.WithEnterpriseURLs(base, base))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnsupportedHost, host, err)
	}
	return api, nil
}

// githubError maps a non-2xx answer onto the fetch-error taxonomy.
func githubError(resp *http.Response, repo repourl.Repository) error {
	err := github.CheckResponse(resp)
	if err == nil {
		return nil
	}

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s (a private repository the hub holds no credential for answers the same way): %w",
			ErrRefNotFound, repo, err)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s: %w", ErrCredentialsRequired, repo, err)
	default:
		return fmt.Errorf("%w: %s answered %d: %w", ErrRemote, repo, resp.StatusCode, err)
	}
}

// apiScheme is the scheme the API is reached over for a self-hosted forge:
// https unless the reference itself said http.
func apiScheme(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && parsed.Scheme == "http" {
		return "http"
	}
	return "https"
}

func hasManifestUnder(files *bundle.Bundle, root string) bool {
	prefix := ""
	if root != "" && root != "." {
		prefix = strings.Trim(root, "/") + "/"
	}
	return files.Has(prefix+pluginManifestName) || files.Has(prefix+skillManifestName)
}
