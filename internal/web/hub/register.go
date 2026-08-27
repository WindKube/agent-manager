package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The registration half of the modal (US1, FR-005 and FR-001).
//
// Both operations take a multipart body carrying a file, which oapi-codegen does
// not build for us — it generates only the WithBody variants for a multipart
// request — so the body is assembled here. It is streamed through an io.Pipe
// rather than buffered: the archive cap is 25 MB, the web role is one hop, and
// holding the whole upload twice buys nothing.

// Preview is FR-005's pre-submit report, from POST /v1/packages/preview. It
// writes nothing on the hub.
func (c *Client) Preview(ctx context.Context, archive view.Archive) (view.ImportPreview, error) {
	contentType, body := multipartBody(func(form *multipart.Writer) error {
		return writeArchive(form, archive)
	})
	defer func() { _ = body.Close() }()

	resp, err := c.api.PreviewPackageWithBodyWithResponse(ctx, contentType, body)
	if err != nil {
		return view.ImportPreview{}, fmt.Errorf("preview archive: %w", err)
	}

	var preview apiclient.PackagePreview
	if err := json.Unmarshal(resp.Body, &preview); err != nil || resp.HTTPResponse.StatusCode != http.StatusOK {
		// A refusal that is not a preview — 401, 413, 422 — is still an answer the
		// modal must show, so it becomes an invalid preview carrying the api's
		// problem detail rather than a transport error nobody sees.
		return view.ImportPreview{
			Problems: []view.ImportProblem{{Message: detailOf(resp.Body, resp.HTTPResponse)}},
		}, nil
	}
	return importPreview(preview), nil
}

// Register submits the modal to POST /v1/packages.
//
// A refusal is a result, not an error: the api's problem detail belongs in front
// of the person who submitted the form. Only a transport failure is an error.
func (c *Client) Register(ctx context.Context, registration view.Registration) (view.ImportResult, error) {
	contentType, body := multipartBody(func(form *multipart.Writer) error {
		return writeRegistration(form, registration)
	})
	defer func() { _ = body.Close() }()

	resp, err := c.api.RegisterPackageWithBodyWithResponse(ctx, contentType, body)
	if err != nil {
		return view.ImportResult{}, fmt.Errorf("register package: %w", err)
	}

	if resp.HTTPResponse.StatusCode != http.StatusAccepted {
		return view.ImportResult{Message: detailOf(resp.Body, resp.HTTPResponse)}, nil
	}

	var registered apiclient.PackageRegistered
	if err := json.Unmarshal(resp.Body, &registered); err != nil {
		return view.ImportResult{}, fmt.Errorf("decode the registration acknowledgement: %w", err)
	}

	result := view.ImportResult{
		Registered: true,
		// The banner shows the id the catalog will show, which is namespace/name:
		// the first segment of the publisher slug, never the whole slug. The api's
		// `publisher` field is the slug, and today the layer below it stores what
		// the form sent — so a two-segment publisher would read back as one here if
		// this concatenated it whole.
		ID:      namespaceOf(registered.Publisher) + "/" + registered.Name,
		Version: registered.Version,
	}
	if registered.Preview != nil {
		preview := importPreview(*registered.Preview)
		result.Preview = &preview
	}
	return result, nil
}

func namespaceOf(slug string) string {
	namespace, _, _ := strings.Cut(slug, "/")
	return namespace
}

// writeRegistration mirrors internal/api's registrationForm field for field. An
// empty optional field is omitted rather than sent blank, because huma's form
// decoding cannot tell "" from absent and the api's own defaulting is the only
// place that should decide what a missing ref means.
func writeRegistration(form *multipart.Writer, r view.Registration) error {
	source := "upload"
	if r.Tab == view.ImportURL {
		// git or archive-url is decided from the URL's shape by internal/fetch,
		// which is the only place that knows how; an empty source asks it to.
		source = ""
	}

	for _, field := range []struct{ name, value string }{
		{"source", source},
		{"url", r.URL},
		{"ref", r.Ref},
		{"subdirectory", r.Subdirectory},
		{"publisher", r.Publisher},
		{"name", r.Name},
		{"version", r.Version},
		{"category", r.Category},
		{"visibility", r.Visibility},
	} {
		if field.value == "" {
			continue
		}
		if err := form.WriteField(field.name, field.value); err != nil {
			return fmt.Errorf("write the %s field: %w", field.name, err)
		}
	}

	if r.Archive == nil {
		return nil
	}
	return writeArchive(form, *r.Archive)
}

func writeArchive(form *multipart.Writer, archive view.Archive) error {
	part, err := form.CreateFormFile("archive", archive.Filename)
	if err != nil {
		return fmt.Errorf("open the archive part: %w", err)
	}
	if _, err := io.Copy(part, archive.Content); err != nil {
		return fmt.Errorf("copy the archive: %w", err)
	}
	return nil
}

// multipartBody streams a multipart body. The content type is read before the
// goroutine starts: the boundary is fixed at construction, and reading it after
// the writer is in flight would be a race for no reason.
func multipartBody(write func(*multipart.Writer) error) (string, io.ReadCloser) {
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	contentType := form.FormDataContentType()

	go func() {
		err := write(form)
		if err == nil {
			err = form.Close()
		}
		// CloseWithError(nil) is CloseWithError(io.EOF), so a clean finish and a
		// failure both terminate the reader — the api never sees a truncated body
		// that looks complete.
		_ = writer.CloseWithError(err)
	}()

	return contentType, reader
}

func importPreview(preview apiclient.PackagePreview) view.ImportPreview {
	out := view.ImportPreview{Valid: preview.Valid}
	if preview.Kind != nil {
		out.Kind = view.Kind(*preview.Kind)
	}
	if preview.Name != nil {
		out.Name = *preview.Name
	}
	if preview.Version != nil {
		out.Version = *preview.Version
	}
	for _, entry := range preview.Entries {
		out.Entries = append(out.Entries, view.ImportEntry{
			Path: entry.Path, Note: entry.Note, Kept: entry.Kept, Mark: string(entry.Mark),
		})
	}
	for _, problem := range preview.Problems {
		out.Problems = append(out.Problems, view.ImportProblem{
			Manifest:   deref(problem.Manifest),
			SchemaPath: deref(problem.SchemaPath),
			Message:    problem.Message,
		})
	}
	return out
}

// detailOf reads the api's RFC 9457 problem detail. It falls back to the status
// line rather than to the raw body: an undecodable body is the api misbehaving,
// and echoing it into the page would put an unbounded upstream string in front
// of a browser.
func detailOf(body []byte, resp *http.Response) string {
	// A 401 is not a finding about the archive and must not be worded like one:
	// registration is fully authenticated and stays that way, so a signed-out
	// person needs to be told to sign in, not that their bundle was refused.
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return "Sign in to register a package."
	}

	var problem apiclient.Error
	if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
		return *problem.Detail
	}
	if resp == nil {
		return "the hub did not answer"
	}
	return fmt.Sprintf("the hub refused this registration (%s)", http.StatusText(resp.StatusCode))
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
