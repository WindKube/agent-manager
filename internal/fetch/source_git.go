package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	// token is sent to the GitHub API only. Go drops Authorization on a redirect
	// to another host, so it never reaches the tarball download host.
	token string
}

func NewGitSource(client Client, token string) (GitSource, error) {
	api, err := github.NewClient()
	if err != nil {
		return GitSource{}, fmt.Errorf("build the github request builder: %w", err)
	}
	return GitSource{client: client, api: api, token: token}, nil
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

// Pin is a git ref resolved to the commit it named when it was asked.
type Pin struct {
	// RepoURL is the canonical repository address.
	RepoURL string
	// Ref is the ref as requested, DefaultRef when none was.
	Ref    string
	Commit string
	// Tag is whether Ref named a tag, the one kind of ref expected never to
	// move.
	Tag bool
}

var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsCommitSHA reports whether s is a full lowercase hex commit SHA.
func IsCommitSHA(s string) bool { return commitSHA.MatchString(s) }

// maxTagDepth bounds how many annotated tags pointing at tags are followed.
const maxTagDepth = 5

// Resolve asks the forge which commit ref.Ref names right now, without
// downloading anything.
func (s GitSource) Resolve(ctx context.Context, ref SourceRef) (Pin, error) {
	repo, api, err := s.target(ref)
	if err != nil {
		return Pin{}, err
	}
	return s.resolve(ctx, api, repo, ref.URL)
}

func (s GitSource) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	repo, api, err := s.target(ref)
	if err != nil {
		return Tree{}, err
	}

	gitRef := repo.Ref
	if gitRef == "" {
		gitRef = DefaultRef
	}

	// The tarball is always downloaded by SHA, so the recorded commit is the
	// one the bytes provably came from even if the ref moves meanwhile.
	commit := strings.ToLower(ref.Commit)
	if commit == "" {
		pin, resolveErr := s.resolve(ctx, api, repo, ref.URL)
		if resolveErr != nil {
			return Tree{}, resolveErr
		}
		commit = pin.Commit
	}
	if !IsCommitSHA(commit) {
		return Tree{}, fmt.Errorf("git source: %q is not a commit sha", ref.Commit)
	}

	// Every segment came through repourl, which rejects a traversal
	// component rather than cleaning it.
	endpoint := fmt.Sprintf("repos/%s/%s/tarball/%s", repo.Owner, repo.Repo, commit)
	request, err := api.NewRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Tree{}, fmt.Errorf("build tarball request for %s: %w", repo, err)
	}
	s.authorize(request)

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

	return Tree{
		Files:     files,
		Root:      root,
		Origin:    "git " + repo.CloneURL() + "@" + gitRef + subdirectorySuffix(repo.Subdir),
		SourceURL: repoURL(repo, ref.URL),
		Commit:    commit,
	}, nil
}

// target parses the reference and picks the API it is reached through,
// before any request is made.
func (s GitSource) target(ref SourceRef) (repourl.Repository, *github.Client, error) {
	if s.client == nil {
		return repourl.Repository{}, nil, errors.New("git source: no outbound client")
	}
	repo, err := repourl.ParseWith(ref.URL, ref.Ref, ref.Subdirectory)
	if err != nil {
		return repourl.Repository{}, nil, err
	}
	api, err := s.apiFor(repo.Host, apiScheme(ref.URL))
	if err != nil {
		return repourl.Repository{}, nil, err
	}
	return repo, api, nil
}

// resolve tries the ref as a tag first, so a tag and a branch of the same
// name resolve to the tag, and peels an annotated tag down to its commit.
func (s GitSource) resolve(ctx context.Context, api *github.Client, repo repourl.Repository, rawURL string) (Pin, error) {
	pin := Pin{RepoURL: repoURL(repo, rawURL), Ref: repo.Ref}
	if pin.Ref == "" {
		pin.Ref = DefaultRef
	}
	if lowered := strings.ToLower(pin.Ref); IsCommitSHA(lowered) {
		pin.Commit = lowered
		return pin, nil
	}

	var object gitObject
	found, err := s.getJSON(ctx, api, repo,
		fmt.Sprintf("repos/%s/%s/git/ref/tags/%s", repo.Owner, repo.Repo, pin.Ref), &object)
	if err != nil {
		return Pin{}, err
	}
	if found {
		pin.Tag = true
		commit, peelErr := s.peel(ctx, api, repo, object.Object)
		if peelErr != nil {
			return Pin{}, peelErr
		}
		pin.Commit = commit
		return pin, nil
	}

	request, err := api.NewRequest(ctx, http.MethodGet,
		fmt.Sprintf("repos/%s/%s/commits/%s", repo.Owner, repo.Repo, pin.Ref), nil)
	if err != nil {
		return Pin{}, fmt.Errorf("build commit request for %s: %w", repo, err)
	}
	s.authorize(request)
	request.Header.Set("Accept", "application/vnd.github.sha")
	resp, err := s.client.Do(ctx, request)
	if err != nil {
		return Pin{}, fmt.Errorf("resolve %s: %w", repo, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// The commits endpoint answers an unknown ref with 422, not 404.
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return Pin{}, fmt.Errorf("%w: %s", ErrRefNotFound, repo)
	}
	if statusErr := githubError(resp, repo); statusErr != nil {
		return Pin{}, statusErr
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return Pin{}, fmt.Errorf("%w: read the commit of %s: %w", ErrRemote, repo, err)
	}
	pin.Commit = strings.ToLower(strings.TrimSpace(string(body)))
	if !IsCommitSHA(pin.Commit) {
		return Pin{}, fmt.Errorf("%w: %s answered %q for a commit sha", ErrRemote, repo, firstBytes(body))
	}
	return pin, nil
}

type objectRef struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type gitObject struct {
	Object objectRef `json:"object"`
}

// peel follows annotated tags until it reaches the commit they point at.
func (s GitSource) peel(ctx context.Context, api *github.Client, repo repourl.Repository, object objectRef) (string, error) {
	for range maxTagDepth {
		sha := strings.ToLower(object.SHA)
		if !IsCommitSHA(sha) {
			return "", fmt.Errorf("%w: %s answered %q for an object sha", ErrRemote, repo, object.SHA)
		}
		switch object.Type {
		case "commit":
			return sha, nil
		case "tag":
			var tag gitObject
			found, err := s.getJSON(ctx, api, repo,
				fmt.Sprintf("repos/%s/%s/git/tags/%s", repo.Owner, repo.Repo, sha), &tag)
			if err != nil {
				return "", err
			}
			if !found {
				return "", fmt.Errorf("%w: %s has no tag object %s", ErrRefNotFound, repo, sha)
			}
			object = tag.Object
		default:
			return "", fmt.Errorf("%w: %s tag points at a %s, not a commit", ErrRefNotFound, repo, object.Type)
		}
	}
	return "", fmt.Errorf("%w: %s tag nests more than %d annotated tags", ErrRemote, repo, maxTagDepth)
}

// maxAPIBody bounds a JSON answer from the forge's API.
const maxAPIBody = 1 << 20

// getJSON decodes a forge API answer into out, reporting a 404 as not found
// rather than an error.
func (s GitSource) getJSON(ctx context.Context, api *github.Client, repo repourl.Repository, endpoint string, out any) (bool, error) {
	request, err := api.NewRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("build request for %s: %w", repo, err)
	}
	s.authorize(request)
	resp, err := s.client.Do(ctx, request)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", repo, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if statusErr := githubError(resp, repo); statusErr != nil {
		return false, statusErr
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(out); err != nil {
		return false, fmt.Errorf("%w: %s answered unreadable json: %w", ErrRemote, repo, err)
	}
	return true, nil
}

func firstBytes(b []byte) string {
	if len(b) > 64 {
		b = b[:64]
	}
	return string(b)
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

// repoURL is the canonical repository address, over http only when the
// reference itself said http, since that is the scheme its API is reached by.
func repoURL(repo repourl.Repository, rawURL string) string {
	if apiScheme(rawURL) == "http" {
		return "http://" + strings.TrimPrefix(repo.WebURL(), "https://")
	}
	return repo.WebURL()
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

func (s GitSource) authorize(request *http.Request) {
	if s.token != "" {
		request.Header.Set("Authorization", "Bearer "+s.token)
	}
}
