package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// ErrFileTooLarge is the api's 413: the file is over the rendered size limit and
// is refused rather than truncated.
var ErrFileTooLarge = errors.New("this file is larger than this hub renders")

// ErrFileNotRenderable is the api's 415: a binary member, listed but never rendered.
var ErrFileNotRenderable = errors.New("this file is binary and is not rendered")

// PackageFiles lists a version's files. A 403 is ErrForbidden: the version exists
// but may not be served, which the panel must say rather than show an empty list.
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

// PackageFile reads one file's content. path is forwarded as-is; the api resolves
// it against the archive's own member list.
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

// filesError adds the files panel's 413 and 415 to governanceError.
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
