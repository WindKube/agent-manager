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

// The registration half of the modal. Both operations take a multipart body
// carrying a file, which oapi-codegen only generates WithBody variants for,
// so the body is assembled here and streamed through an io.Pipe rather than
// buffered, since holding the whole upload twice buys nothing.

// Preview is the pre-submit report, from POST /v1/packages/preview. It
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
		// A refusal that is not a preview is still an answer the modal must
		// show, so it becomes an invalid preview carrying the problem detail.
		return view.ImportPreview{
			Problems: []view.ImportProblem{{Message: detailOf(resp.Body, resp.HTTPResponse)}},
		}, nil
	}
	return importPreview(preview), nil
}

// Register submits the modal to POST /v1/packages. A refusal is a result,
// not an error: the problem detail belongs in front of the person who
// submitted the form. Only a transport failure is an error.
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
		// The banner shows namespace/name: the first segment of the
		// publisher slug, never the whole slug.
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

// writeRegistration mirrors internal/api's registrationForm field for field.
// An empty optional field is omitted rather than sent blank, since huma's
// form decoding cannot tell "" from absent.
func writeRegistration(form *multipart.Writer, r view.Registration) error {
	source := "upload"
	if r.Tab == view.ImportURL {
		// An empty source asks internal/fetch to decide git vs archive-url
		// from the URL's shape.
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

// multipartBody streams a multipart body. The content type is read before
// the goroutine starts, since reading it after the writer is in flight would
// be a race for no reason.
func multipartBody(write func(*multipart.Writer) error) (string, io.ReadCloser) {
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	contentType := form.FormDataContentType()

	go func() {
		err := write(form)
		if err == nil {
			err = form.Close()
		}
		// CloseWithError(nil) is CloseWithError(io.EOF): a clean finish and a
		// failure both terminate the reader.
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

// detailOf reads the api's RFC 9457 problem detail and falls back to the
// status line rather than the raw body: an undecodable body would put an
// unbounded upstream string in front of a browser.
func detailOf(body []byte, resp *http.Response) string {
	// A 401 must not be worded like a finding about the archive: registration
	// is fully authenticated, so a signed-out person needs to be told to sign in.
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
