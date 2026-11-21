package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/domain/signer"
	"agent-manager/internal/fetch"
	"agent-manager/internal/logging"
	"agent-manager/internal/signing"
	"agent-manager/internal/store/models"
)

// The registration surface. The archive is a real multipart file, not a base64
// string, because huma decodes a string body into memory; that is also why these
// request types live here: a contract type may not name huma.FormFile.
type uploadForm struct {
	Archive huma.FormFile `form:"archive" contentType:"application/zip,application/gzip,application/x-gzip,application/x-tar,application/octet-stream" required:"true" doc:"A .zip or .tar.gz of the whole tree, with the manifest at its root."`
}

// registrationForm carries `publisher`, `name` and `version` because for a URL
// source the api has no outbound client and has not seen the manifest. For an
// upload they are checked against the manifest rather than trusted.
type registrationForm struct {
	Source string `form:"source" required:"false" enum:"upload,git,archive-url" doc:"Which of the three source shapes this is." example:"git"`

	URL          string `form:"url" required:"false" doc:"Repository or archive URL. Required unless source is upload." example:"https://github.com/org/plugin"`
	Ref          string `form:"ref" required:"false" doc:"Branch, tag or commit. Defaults to the remote's HEAD." example:"v1.3.0"`
	Subdirectory string `form:"subdirectory" required:"false" doc:"Path inside the tree holding the manifest." example:"plugins/platform-toolkit"`

	Publisher string `form:"publisher" required:"true" doc:"The publisher, as <namespace> or <namespace>/<team>. Required: no source carries one — a repository has an owner and an archive URL has a host, and neither is a namespace this hub chose. The namespace is the first segment, and it is what the object key and the package id are built from." example:"example/platform"`
	Name      string `form:"name" required:"false" doc:"The package name. Derived from the repository name when omitted, and always checked against the manifest." example:"platform-toolkit"`
	Version   string `form:"version" required:"false" doc:"The exact version. Derived from the ref when omitted." example:"1.3.0"`

	Kind       string `form:"kind" required:"false" enum:"plugin,skill" doc:"Provisional only. Kind is decided by which manifest is at the tree root, so the fetcher overwrites this once it has the bytes." example:"plugin"`
	Category   string `form:"category" required:"false" doc:"A category name or slug from the admin-curated vocabulary." example:"Infrastructure"`
	Visibility string `form:"visibility" required:"false" enum:"organisation,team,private" doc:"Who may see the package in the catalog." example:"organisation"`

	Tags string `form:"tags" required:"false" doc:"Comma-separated tags. Added to whatever the manifest's own keywords contribute at publish — this does not replace them, and is not replaced by them." example:"terraform,aws,guardrails"`

	Archive huma.FormFile `form:"archive" required:"false" contentType:"application/zip,application/gzip,application/x-gzip,application/x-tar,application/octet-stream" doc:"Required when source is upload, and refused otherwise. huma treats a form field as required unless told otherwise, which is what required:\"false\" is doing on every optional field here."`

	SigstoreBundle huma.FormFile `form:"sigstoreBundle" required:"false" contentType:"application/json,application/octet-stream" doc:"Optional, upload only: a Sigstore bundle (.sigstore.json) over the archive's exact bytes, as cosign sign-blob --bundle writes it. The fetcher verifies it and records the signer; a git or archive-url source is checked for a bundle published beside it instead."`
}

// maxUploadBytes caps the whole request body, not the file part: a part cap is
// enforced only after the bytes are already in memory.
const maxUploadBytes = bundle.DefaultMaxCompressedBytes + (1 << 20)

type previewInput struct {
	RawBody huma.MultipartFormFiles[uploadForm]
}

type previewOutput struct {
	Body contract.PackagePreview
}

// previewPackage writes nothing. It runs the same pkgspec pass as the fetcher, so
// the panel a user approves is the tree that gets stored.
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

// registerPackage writes in one transaction; the fetch happens elsewhere. The api
// holds no blob writer, so the archive's bytes travel to `worker fetcher` in the
// outbox payload.
func (s *Server) registerPackage(ctx context.Context, in *registerInput) (*registerOutput, error) {
	log := logging.From(ctx)
	principal, _ := PrincipalFrom(ctx)

	// Refused here rather than by a grant: am_api holds grants for every caller.
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
		// A 409, not a 422: the request is well formed; republishing is what is refused.
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

type setPackageVisibilityInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
	Body      contract.PackageVisibilityUpdate
}

// setPackageVisibility re-reads the package rather than echoing the request, since
// the read is the authority on what actually changed.
func (s *Server) setPackageVisibility(ctx context.Context, in *setPackageVisibilityInput) (*getPackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	err := commands.SetPackageVisibility(ctx, s.deps.DB, principal, in.Namespace, in.Name,
		models.PackageVisibility(in.Body.Visibility))
	if err != nil {
		return nil, packageFailure(ctx, err)
	}

	detail, err := queries.Package(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, packageFailure(ctx, err)
	}
	return &getPackageOutput{Body: detail}, nil
}

type setPackageTrackingInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
	Body      contract.PackageTrackingUpdate
}

func (s *Server) setPackageTracking(ctx context.Context, in *setPackageTrackingInput) (*getPackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	err := commands.SetPackageTracking(ctx, s.deps.DB, principal, in.Namespace, in.Name,
		in.Body.TrackUpstream, in.Body.TagPattern)
	if err != nil {
		return nil, packageFailure(ctx, err)
	}

	detail, err := queries.Package(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, packageFailure(ctx, err)
	}
	return &getPackageOutput{Body: detail}, nil
}

type setPackageSignerInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
	Body      contract.PackageSignerUpdate
}

func (s *Server) setPackageSigner(ctx context.Context, in *setPackageSignerInput) (*getPackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	err := commands.SetPackageSigner(ctx, s.deps.DB, principal, in.Namespace, in.Name,
		signer.Expected{Issuer: in.Body.Issuer, Identity: in.Body.Identity})
	if err != nil {
		return nil, packageFailure(ctx, err)
	}

	detail, err := queries.Package(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, packageFailure(ctx, err)
	}
	return &getPackageOutput{Body: detail}, nil
}

// packageFailure maps package command refusals onto the wire. Unreadable packages
// become a 404, indistinguishable from missing; a role/ownership refusal is a 403.
func packageFailure(ctx context.Context, err error) error {
	var notPermitted *commands.PackageNotPermittedError
	switch {
	case errors.As(err, &notPermitted):
		return huma.Error403Forbidden(notPermitted.Error())
	case errors.Is(err, commands.ErrRegistration):
		return huma.Error422UnprocessableEntity(err.Error())
	default:
		return fail(logging.From(ctx), err)
	}
}

func registrationFrom(ctx context.Context, form *registrationForm) (commands.Registration, error) {
	kind := fetch.SourceKind(strings.TrimSpace(form.Source))
	if kind == "" {
		// Infer the shape: a file means an upload, a URL means git or archive-url by URL shape.
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
		// Normalising tags is commands.Registration.normalise's job.
		Tags: strings.Split(form.Tags, ","),
	}

	switch kind {
	case fetch.SourceUpload:
		archive, err := readFormFile(form.Archive)
		if err != nil {
			return commands.Registration{}, err
		}
		out.Archive = archive
		out.ArchiveName = form.Archive.Filename
		if form.SigstoreBundle.IsSet {
			if out.SigstoreBundle, err = readSigstoreBundle(form.SigstoreBundle); err != nil {
				return commands.Registration{}, err
			}
		}

		// On upload the api has the manifest before writing a row, so the manifest
		// decides kind, name and version, and a tree that would fail the fetch writes no row.
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
		if form.SigstoreBundle.IsSet {
			return commands.Registration{}, huma.Error422UnprocessableEntity(
				"a " + string(kind) + " registration carries no signature: the hub looks for a .sigstore.json beside the source")
		}

	default:
		return commands.Registration{}, huma.Error422UnprocessableEntity(
			"a registration needs either an archive or a url")
	}

	return out, nil
}

// inspectArchive extracts and inspects an archive without writing anything. The
// preview is filled even when the tree is refused: it is what tells the user why.
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
		for i := range pkg.Components {
			component := &pkg.Components[i]
			out.Components = append(out.Components, contract.PreviewComponent{
				Kind: string(component.Kind),
				Name: component.Name,
				Path: component.Path,
				Note: component.Note,
				ComponentSurface: contract.ComponentSurface{
					Event: component.Event, Matcher: component.Matcher,
					Transport: component.Transport, Target: component.Target,
				},
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
		// Each problem keeps its schema path rather than being flattened into one sentence.
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

// archiveProblem states which extraction cap or malformation refused an archive.
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

// readSigstoreBundle reads the optional bundle part; the fetcher verifies it.
func readSigstoreBundle(file huma.FormFile) ([]byte, error) {
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, signing.MaxBundleBytes+1))
	switch {
	case err != nil:
		return nil, huma.Error422UnprocessableEntity("the attached sigstore bundle could not be read: " + err.Error())
	case len(body) > signing.MaxBundleBytes:
		return nil, huma.Error422UnprocessableEntity(fmt.Sprintf(
			"a sigstore bundle may be at most %d bytes", signing.MaxBundleBytes))
	case !json.Valid(body):
		return nil, huma.Error422UnprocessableEntity("the attached sigstore bundle is not JSON")
	}
	return body, nil
}

// readFormFile reads an uploaded part into memory, refusing an absent one. It
// buffers because consumers need the bytes whole (zip's central directory is at the end).
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
