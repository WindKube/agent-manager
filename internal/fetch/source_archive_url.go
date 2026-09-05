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

// archiveSuffixes are the extensions this source claims.
var archiveSuffixes = []string{".zip", ".tar.gz", ".tgz"}

// ArchiveURLSource fetches a `.zip` or `.tar.gz` straight off a URL.
type ArchiveURLSource struct {
	client Client
}

// NewArchiveURLSource takes the SSRF-hardened client rather than building one.
func NewArchiveURLSource(client Client) ArchiveURLSource {
	return ArchiveURLSource{client: client}
}

var _ Source = ArchiveURLSource{}

func (ArchiveURLSource) Name() string { return string(SourceArchiveURL) }

func (ArchiveURLSource) Handles(ref SourceRef) bool {
	if ref.Kind == SourceArchiveURL {
		return true
	}
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
		// ErrBlocked travels up unwrapped so an SSRF refusal reports as such.
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

// statusError maps a non-2xx answer onto the fetch-error taxonomy.
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

// redactURL strips any embedded credential before the URL reaches an audit
// row or log line.
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
