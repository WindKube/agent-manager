package fetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"agent-manager/internal/bundle"
)

// archiveSuffixes are the extensions this source claims. A URL is not sniffed
// before it is fetched: the decision of which Source handles a reference has to
// be made from the reference alone, or the registry would have to make a network
// request to route.
var archiveSuffixes = []string{".zip", ".tar.gz", ".tgz"}

// ArchiveURLSource fetches a `.zip` or `.tar.gz` straight off a URL.
type ArchiveURLSource struct {
	client Client
}

// NewArchiveURLSource takes the SSRF-hardened client rather than building
// one: the URL is user-supplied, and this is the package that exists to
// refuse the private addresses it can be made to resolve to.
func NewArchiveURLSource(client Client) ArchiveURLSource {
	return ArchiveURLSource{client: client}
}

var _ Source = ArchiveURLSource{}

func (ArchiveURLSource) Name() string { return string(SourceArchiveURL) }

func (ArchiveURLSource) Handles(ref SourceRef) bool {
	if ref.Kind == SourceArchiveURL {
		return true
	}
	// An unset kind is routed by shape, so an archive URL reaches this
	// source rather than the git one.
	return ref.Kind == "" && IsArchiveURL(ref.URL)
}

// IsArchiveURL reports whether a URL names an archive this source can fetch.
func IsArchiveURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	lowered := strings.ToLower(path.Base(parsed.Path))
	for _, suffix := range archiveSuffixes {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	return false
}

func (s ArchiveURLSource) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	if s.client == nil {
		return Tree{}, errors.New("archive-url source: no outbound client")
	}
	if strings.TrimSpace(ref.URL) == "" {
		return Tree{}, errors.New("archive-url source: no url")
	}

	resp, err := s.client.Get(ctx, ref.URL)
	if err != nil {
		// ErrBlocked travels up unwrapped-as-itself so the fetcher can
		// report an SSRF refusal as a refusal rather than "download failed".
		return Tree{}, fmt.Errorf("fetch archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if statusErr := statusError(resp, ref.URL); statusErr != nil {
		return Tree{}, statusErr
	}

	files, err := bundle.Extract(ctx, resp.Body, ref.Limits)
	if err != nil {
		return Tree{}, fmt.Errorf("extract archive from %s: %w", redactURL(ref.URL), err)
	}

	return Tree{
		Files:  files,
		Root:   packageRoot(files, "", ref.Subdirectory),
		Origin: "archive " + redactURL(ref.URL) + subdirectorySuffix(ref.Subdirectory),
	}, nil
}

// statusError maps a non-2xx answer onto the fetch-error taxonomy. 401 and 403
// are "we hold no credential" and not "not found": telling them apart is what
// lets an operator know whether to fix a token or a URL.
func statusError(resp *http.Response, rawURL string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s answered %d", ErrCredentialsRequired, redactURL(rawURL), resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusGone:
		return fmt.Errorf("%w: %s answered %d", ErrRefNotFound, redactURL(rawURL), resp.StatusCode)
	default:
		return fmt.Errorf("%w: %s answered %d", ErrRemote, redactURL(rawURL), resp.StatusCode)
	}
}

// redactURL strips any embedded credential before the URL reaches an audit row or
// a log line. The client refuses a URL carrying credentials outright, but this
// value is also rendered on paths that never went through it.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return credentialsInURL.ReplaceAllString(raw, "//$1:xxxxx@")
	}
	return parsed.Redacted()
}

func subdirectorySuffix(subdirectory string) string {
	if subdirectory == "" {
		return ""
	}
	return " (" + subdirectory + ")"
}
