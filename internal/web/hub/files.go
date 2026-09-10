package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The package files panel's door to the api (US3/US5: read a skill's files
// before using it), through the generated client and nothing else.

// ErrFileTooLarge is getPackageFile's 413: the file exists but is over the
// size this hub renders, refused rather than truncated.
var ErrFileTooLarge = errors.New("this file is larger than this hub renders")

// ErrFileNotRenderable is getPackageFile's 415: a binary member, listed by
// PackageFiles but never rendered.
var ErrFileNotRenderable = errors.New("this file is binary and is not rendered")

// PackageFiles implements web.PackageFileSource against
// GET /v1/packages/{namespace}/{name}/files. A 403 is ErrForbidden: the
// version exists but FR-029 refuses to serve it, which the panel must say
// plainly rather than as an empty file list.
func (c *Client) PackageFiles(ctx context.Context, namespace, name string) (view.FileList, error) {
	resp, err := c.api.ListPackageFilesWithResponse(ctx, namespace, name)
	if err != nil {
		return view.FileList{}, fmt.Errorf("list files for %s/%s: %w", namespace, name, err)
	}
	if resp.JSON200 == nil {
		return view.FileList{}, fmt.Errorf("list files for %s/%s: %w", namespace, name,
			filesError(resp.HTTPResponse, resp.Body))
	}

	out := view.FileList{Default: deref(resp.JSON200.Default)}
	for _, f := range resp.JSON200.Files {
		out.Files = append(out.Files, view.FileRow{
			Path: f.Path, Kind: string(f.Kind), SizeLabel: humanSize(f.SizeBytes),
			OverLimit: f.OverLimit != nil && *f.OverLimit,
		})
	}
	return out, nil
}

// PackageFile implements web.PackageFileSource against
// GET /v1/packages/{namespace}/{name}/files/content. path is forwarded
// as-is: the api resolves it against the archive's own member list, and
// this hop builds no path from it either.
func (c *Client) PackageFile(ctx context.Context, namespace, name, path string) (view.FileDetail, error) {
	resp, err := c.api.GetPackageFileWithResponse(ctx, namespace, name,
		&apiclient.GetPackageFileParams{Path: path})
	if err != nil {
		return view.FileDetail{}, fmt.Errorf("read file %q in %s/%s: %w", path, namespace, name, err)
	}
	if resp.JSON200 == nil {
		return view.FileDetail{}, fmt.Errorf("read file %q in %s/%s: %w", path, namespace, name,
			filesError(resp.HTTPResponse, resp.Body))
	}

	body := resp.JSON200
	detail := view.FileDetail{Path: body.Path, Kind: string(body.Kind), Text: body.Content}
	if detail.Kind == "markdown" {
		detail.Markdown = view.ParseMarkdown([]byte(body.Content))
	}
	return detail, nil
}

// filesError adds the files panel's own two refusals to governanceError's
// 401/403 split.
func filesError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return view.ErrNotFound
		case http.StatusRequestEntityTooLarge:
			return ErrFileTooLarge
		case http.StatusUnsupportedMediaType:
			return ErrFileNotRenderable
		}
	}
	return governanceError(resp, body)
}
