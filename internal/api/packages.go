package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The registration surface (US1, T041/T042).
//
// The archive field is a real multipart file rather than a base64 string in a
// JSON body: 25 MB of base64 is 33 MB of request, and huma decodes a string body
// into memory before a handler sees it. The FORM VALUES ride the same body, which
// is why the request type lives here and not in internal/api/contract — a
// contract type may not name huma.FormFile.

// uploadForm is the multipart body of the preview operation.
type uploadForm struct {
	Archive huma.FormFile `form:"archive" contentType:"application/zip,application/gzip,application/x-gzip,application/x-tar,application/octet-stream" required:"true" doc:"A .zip or .tar.gz of the whole tree, with the manifest at its root."`
}

// registrationForm is the multipart body of the registration operation.
//
// It carries `publisher`, `name` and `version` because the api role cannot derive
// them for a URL source: it holds no outbound client, so it has not seen the
// manifest at the moment it must write the version row. For an upload it HAS seen
// the manifest, and the values below are checked against it rather than trusted.
type registrationForm struct {
	Source string `form:"source" required:"false" enum:"upload,git,archive-url" doc:"Which of FR-001's three shapes this is." example:"git"`

	URL          string `form:"url" required:"false" doc:"Repository or archive URL. Required unless source is upload." example:"https://github.com/org/plugin"`
	Ref          string `form:"ref" required:"false" doc:"Branch, tag or commit. Defaults to the remote's HEAD." example:"v1.3.0"`
	Subdirectory string `form:"subdirectory" required:"false" doc:"Path inside the tree holding the manifest." example:"plugins/platform-toolkit"`

	Publisher string `form:"publisher" required:"true" doc:"The publisher, as <namespace>/<team>. Required: no source carries one — a repository has an owner and an archive URL has a host, and neither is a namespace this hub chose. The namespace is the first segment, and it is what the object key and the package id are built from." example:"example/platform"`
	Name      string `form:"name" required:"false" doc:"The package name. Derived from the repository name when omitted, and always checked against the manifest." example:"platform-toolkit"`
	Version   string `form:"version" required:"false" doc:"The exact version. Derived from the ref when omitted." example:"1.3.0"`

	Kind       string `form:"kind" required:"false" enum:"plugin,skill" doc:"Provisional only. Kind is decided by which manifest is at the tree root, so the fetcher overwrites this once it has the bytes." example:"plugin"`
	Category   string `form:"category" required:"false" doc:"A category name or slug from the admin-curated vocabulary (FR-049)." example:"Infrastructure"`
	Visibility string `form:"visibility" required:"false" enum:"organisation,team,private" doc:"Who may see the package in the catalog." example:"organisation"`

	Archive huma.FormFile `form:"archive" required:"false" contentType:"application/zip,application/gzip,application/x-gzip,application/x-tar,application/octet-stream" doc:"Required when source is upload, and refused otherwise. huma treats a form field as required unless told otherwise, which is what required:\"false\" is doing on every optional field here."`
}

// maxUploadBytes is FR-001's 25 MB upload cap, applied to the WHOLE request body
// rather than to the file part. The archive is the only large part, and a cap on
// the part alone is enforced after the bytes have already been read into memory.
const maxUploadBytes = bundle.DefaultMaxCompressedBytes + (1 << 20)

type previewInput struct {
	RawBody huma.MultipartFormFiles[uploadForm]
}

type previewOutput struct {
	Body contract.PackagePreview
}

// previewPackage is FR-005's pre-submit answer, and it writes nothing.
//
// The whole point is that it runs the SAME internal/domain/pkgspec pass the
// fetcher runs, so the panel a user approves is the tree that gets stored. A
// second, friendlier implementation here is how a preview starts lying.
func (s *Server) previewPackage(ctx context.Context, in *previewInput) (*previewOutput, error) {
	form := in.RawBody.Data()
	archive, err := readFormFile(form.Archive)
	if err != nil {
		return nil, err
	}

	preview, _ := inspectArchive(ctx, form.Archive.Filename, archive)
	return &previewOutput{Body: preview}, nil
}

type registerInput struct {
	RawBody huma.MultipartFormFiles[registrationForm]
}

type registerOutput struct {
	Body contract.PackageRegistered
}

// registerPackage is T042: one transaction, then the fetch happens elsewhere.
//
// Nothing here touches object storage. The api role holds a blob READER and no
// writer (principle II), so the archive's bytes travel to `worker fetcher` in the
// outbox payload — see fetcher.JobSource.Archive for what that costs.
func (s *Server) registerPackage(ctx context.Context, in *registerInput) (*registerOutput, error) {
	log := logging.From(ctx)
	principal, _ := PrincipalFrom(ctx)

	// A read-only role may not create catalog state. It is refused here rather
	// than left to a grant, because am_api holds the grant on behalf of every
	// caller and the database cannot tell them apart.
	if principal.Role == models.OrgRoleReadOnly {
		return nil, huma.Error403Forbidden("this identity is read-only and cannot register a package")
	}

	form := in.RawBody.Data()
	request, err := registrationFrom(ctx, form)
	if err != nil {
		return nil, err
	}

	registered, err := commands.RegisterPackage(ctx, s.deps.DB, principal, request)
	switch {
	case errors.Is(err, commands.ErrImmutable):
		// FR-007, US1 scenario 4. A 409 and not a 422: the request is well formed
		// and the version is real — republishing it is the thing that is refused.
		return nil, huma.Error409Conflict(err.Error())
	case errors.Is(err, commands.ErrRegistration):
		return nil, huma.Error422UnprocessableEntity(err.Error())
	case err != nil:
		return nil, fail(log, err)
	}

	out := &registerOutput{Body: registered}
	if request.Preview != nil {
		out.Body.Preview = request.Preview
	}
	return out, nil
}

// registrationFrom turns the form into the command's input, refusing everything
// the command should never have to reason about.
func registrationFrom(ctx context.Context, form *registrationForm) (commands.Registration, error) {
	kind := fetch.SourceKind(strings.TrimSpace(form.Source))
	if kind == "" {
		// The shape is inferable from what was sent, and inferring it is friendlier
		// than refusing: a file means an upload, a URL means one of the two remote
		// shapes, and internal/fetch's registry decides which by URL shape.
		switch {
		case form.Archive.IsSet:
			kind = fetch.SourceUpload
		case form.URL != "":
			kind = fetch.SourceGit
			if fetch.IsArchiveURL(form.URL) {
				kind = fetch.SourceArchiveURL
			}
		}
	}

	out := commands.Registration{
		Source:       kind,
		URL:          strings.TrimSpace(form.URL),
		Ref:          strings.TrimSpace(form.Ref),
		Subdirectory: strings.TrimSpace(form.Subdirectory),
		Publisher:    strings.TrimSpace(form.Publisher),
		Name:         strings.TrimSpace(form.Name),
		Version:      strings.TrimSpace(form.Version),
		Kind:         models.PackageKind(strings.TrimSpace(form.Kind)),
		Category:     strings.TrimSpace(form.Category),
		Visibility:   models.PackageVisibility(strings.TrimSpace(form.Visibility)),
	}

	switch kind {
	case fetch.SourceUpload:
		archive, err := readFormFile(form.Archive)
		if err != nil {
			return commands.Registration{}, err
		}
		out.Archive = archive
		out.ArchiveName = form.Archive.Filename

		// The upload path is the one case where the api HAS the manifest before it
		// writes a row, so the manifest decides the kind, the name and the version
		// and the form only gets to agree with it. Refusing here means no version
		// row is written for a tree that would fail the fetch anyway (US1
		// scenario 3: nothing reaches object storage).
		preview, pkg := inspectArchive(ctx, form.Archive.Filename, archive)
		if !preview.Valid {
			return commands.Registration{}, previewRefusal(preview)
		}
		out.Preview = &preview
		out.Kind = models.PackageKind(preview.Kind)
		out.Name = preview.Name
		if form.Name != "" && form.Name != preview.Name {
			return commands.Registration{}, huma.Error422UnprocessableEntity(fmt.Sprintf(
				"the archive's manifest names %q, not %q", preview.Name, form.Name))
		}
		if out.Version == "" {
			out.Version = preview.Version
		}
		out.Keywords = pkg.Keywords

	case fetch.SourceGit, fetch.SourceArchiveURL:
		if form.Archive.IsSet {
			return commands.Registration{}, huma.Error422UnprocessableEntity(
				"a " + string(kind) + " registration carries no archive: the hub fetches the bytes itself")
		}

	default:
		return commands.Registration{}, huma.Error422UnprocessableEntity(
			"a registration needs either an archive or a url")
	}

	return out, nil
}

// inspectArchive extracts and inspects an archive without writing anything.
//
// The first result is filled in even when the tree is refused: FR-005's panel is
// what tells a user WHY, so a refusal that returns an empty preview is a refusal
// with no explanation.
func inspectArchive(ctx context.Context, filename string, archive []byte) (contract.PackagePreview, *pkgspec.Package) {
	tree, err := fetch.NewUploadSource().Fetch(ctx, fetch.SourceRef{
		Kind:        fetch.SourceUpload,
		ArchiveName: filename,
		Archive:     bytes.NewReader(archive),
	})
	if err != nil {
		return contract.PackagePreview{
			Problems: []contract.PreviewProblem{{Message: archiveProblem(err)}},
		}, nil
	}

	pkg, err := pkgspec.Inspect(tree.Files, tree.Root)
	return previewOf(pkg, err), pkg
}

// previewOf renders one inspection as the pre-submit panel.
func previewOf(pkg *pkgspec.Package, err error) contract.PackagePreview {
	out := contract.PackagePreview{
		Valid:      err == nil,
		Entries:    []contract.PreviewEntry{},
		Components: []contract.PreviewComponent{},
		Expected:   []contract.PreviewCapability{},
		Tags:       []string{},
		Dropped:    []string{},
		Problems:   []contract.PreviewProblem{},
	}
	if pkg != nil {
		out.Kind = string(pkg.Kind)
		out.Name = pkg.Name
		out.Version = pkg.Semver
		for _, entry := range pkg.Layout.Entries {
			out.Entries = append(out.Entries, contract.PreviewEntry{
				Path: entry.Path,
				Note: entry.Note,
				Kept: entry.Kept,
				Mark: mark(entry.Kept, err != nil && entry.Path == pkg.ManifestObject),
			})
		}
		for _, component := range pkg.Components {
			out.Components = append(out.Components, contract.PreviewComponent{
				Kind: string(component.Kind),
				Name: component.Name,
				Path: component.Path,
				Note: component.Note,
			})
		}
		for _, capability := range pkg.ExpectedCapabilities() {
			out.Expected = append(out.Expected, contract.PreviewCapability{
				Name:   capability.Name,
				Level:  capability.Level,
				Detail: capability.Detail,
			})
		}
		if len(pkg.Keywords) > 0 {
			out.Tags = pkg.Keywords
		}
		if len(pkg.Layout.Dropped) > 0 {
			out.Dropped = pkg.Layout.Dropped
		}
	}

	var manifestErr *pkgspec.ManifestError
	switch {
	case err == nil:
	case errors.As(err, &manifestErr):
		// US1 scenario 3: the failure is reported against the specific schema path,
		// which is why the validator keeps the keyword location rather than
		// flattening every problem into one sentence.
		for _, problem := range manifestErr.Problems {
			out.Problems = append(out.Problems, contract.PreviewProblem{
				Manifest:     manifestErr.Manifest,
				SchemaID:     manifestErr.SchemaID,
				SchemaPath:   problem.SchemaPath,
				InstancePath: problem.InstancePath,
				Message:      problem.Message,
			})
		}
	default:
		out.Problems = append(out.Problems, contract.PreviewProblem{Message: err.Error()})
	}
	return out
}

func mark(kept, invalid bool) string {
	switch {
	case invalid:
		return contract.MarkInvalid
	case kept:
		return contract.MarkKept
	default:
		return contract.MarkDropped
	}
}

// previewRefusal turns a refused preview into the 422 body, carrying the schema
// paths rather than a summary.
func previewRefusal(preview contract.PackagePreview) error {
	details := make([]error, 0, len(preview.Problems))
	for _, problem := range preview.Problems {
		details = append(details, &huma.ErrorDetail{
			Message:  problem.Message,
			Location: strings.TrimSpace(problem.Manifest + problem.InstancePath),
			Value:    problem.SchemaPath,
		})
	}
	return huma.Error422UnprocessableEntity("the archive was refused before any version was created", details...)
}

// archiveProblem states which R3 cap or malformation refused an archive, without
// echoing an extractor message that names an internal limit constant.
func archiveProblem(err error) string {
	switch {
	case errors.Is(err, bundle.ErrTooLarge):
		return "the archive exceeds this hub's extraction limits: " + err.Error()
	case errors.Is(err, bundle.ErrRejectedMember):
		return "the archive holds a member this hub refuses: " + err.Error()
	case errors.Is(err, bundle.ErrTimeout):
		return "the archive took too long to extract"
	default:
		return "the archive could not be read: " + err.Error()
	}
}

// readFormFile reads an uploaded part into memory, refusing an absent one.
//
// It buffers rather than streams because every consumer of these bytes needs
// them whole: the extractor reads a zip's central directory from the end, and the
// outbox payload is a single value. The cap is the operation's MaxBodyBytes, so
// this read is already bounded when it starts.
func readFormFile(file huma.FormFile) ([]byte, error) {
	if !file.IsSet || file.File == nil {
		return nil, huma.Error422UnprocessableEntity("no archive was attached")
	}
	defer func() { _ = file.Close() }()

	body, err := io.ReadAll(io.LimitReader(file, maxUploadBytes))
	if err != nil {
		return nil, huma.Error422UnprocessableEntity("the attached archive could not be read: " + err.Error())
	}
	if len(body) == 0 {
		return nil, huma.Error422UnprocessableEntity("the attached archive is empty")
	}
	if int64(len(body)) >= maxUploadBytes {
		return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"an uploaded archive may be at most %d bytes", bundle.DefaultMaxCompressedBytes))
	}
	return body, nil
}
