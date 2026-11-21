package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/bundle"
	"agent-manager/internal/logging"
)

// maxRenderableFileBytes bounds getPackageFile's answer. A larger file is refused
// rather than truncated: a half-read SKILL.md that looks complete is worse.
const maxRenderableFileBytes = 256 << 10

// errVersionRejected: a rejected version is never served.
var errVersionRejected = errors.New("this version was rejected and is never served")

// packageTree resolves a package's latest visible version and unpacks its bundle
// under the fetcher's extraction caps: stored bytes are still untrusted. Nothing is
// cached; every call re-unpacks.
func (s *Server) packageTree(ctx context.Context, p auth.Principal, namespace, name string) (*bundle.Bundle, error) {
	ref, err := queries.LatestBundle(ctx, s.deps.DB, p, namespace, name)
	if err != nil {
		return nil, err
	}
	if !ref.Distributable() {
		return nil, errVersionRejected
	}
	if s.deps.Bundles == nil {
		return nil, fmt.Errorf("no bundle reader is configured")
	}

	reader, err := s.deps.Bundles.NewReader(ctx, ref.ObjectKey)
	if err != nil {
		return nil, fmt.Errorf("read bundle at %s: %w", ref.ObjectKey, err)
	}
	defer func() { _ = reader.Close() }()

	tree, err := bundle.Unpack(ctx, reader, bundle.Limits{})
	if err != nil {
		return nil, fmt.Errorf("unpack bundle at %s: %w", ref.ObjectKey, err)
	}
	return tree, nil
}

func packageTreeError(ctx context.Context, err error) error {
	if errors.Is(err, errVersionRejected) {
		return huma.Error403Forbidden(errVersionRejected.Error())
	}
	return fail(logging.From(ctx), err)
}

// classifyFile splits files into markdown, text and binary by content (NUL byte or
// invalid UTF-8, as grep and git do), not by extension alone.
func classifyFile(path string, data []byte) string {
	sample := data
	if len(sample) > 8000 {
		sample = sample[:8000]
	}
	if bytes.IndexByte(sample, 0) >= 0 || !utf8.Valid(sample) {
		return "binary"
	}
	if strings.EqualFold(pathpkg.Ext(path), ".md") {
		return "markdown"
	}
	return "text"
}

type listPackageFilesInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
}

type listPackageFilesOutput struct {
	Body contract.PackageFileList
}

// listPackageFiles answers the files panel: every regular file in the latest visible version.
func (s *Server) listPackageFiles(ctx context.Context, in *listPackageFilesInput) (*listPackageFilesOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	tree, err := s.packageTree(ctx, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, packageTreeError(ctx, err)
	}

	files := tree.Files()
	body := contract.PackageFileList{Files: make([]contract.PackageFile, 0, len(files))}
	for _, f := range files {
		size := int64(len(f.Data))
		body.Files = append(body.Files, contract.PackageFile{
			Path: f.Path, Kind: classifyFile(f.Path, f.Data), SizeBytes: size,
			OverLimit: size > maxRenderableFileBytes,
		})
	}
	// A plugin's own manifest is JSON, not the document a person reads first.
	for _, candidate := range []string{"SKILL.md", "plugin.json"} {
		if tree.Has(candidate) {
			body.Default = candidate
			break
		}
	}
	return &listPackageFilesOutput{Body: body}, nil
}

type getPackageFileInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
	Path      string `query:"path" required:"true" doc:"The file's path exactly as listPackageFiles named it." example:"SKILL.md"`
}

type getPackageFileOutput struct {
	Body contract.PackageFileContent
}

// getPackageFile answers one file's content. Path is untrusted and only matched
// against the archive's member list, never joined into a filesystem path.
func (s *Server) getPackageFile(ctx context.Context, in *getPackageFileInput) (*getPackageFileOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	tree, err := s.packageTree(ctx, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, packageTreeError(ctx, err)
	}

	file, ok := tree.Lookup(in.Path)
	if !ok {
		return nil, huma.Error404NotFound("no such file in this version")
	}

	kind := classifyFile(file.Path, file.Data)
	if kind == "binary" {
		return nil, huma.Error415UnsupportedMediaType("this member is binary and is not rendered")
	}
	if size := int64(len(file.Data)); size > maxRenderableFileBytes {
		return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
			"this file is %d bytes, over the %d this hub renders", size, maxRenderableFileBytes))
	}

	return &getPackageFileOutput{Body: contract.PackageFileContent{
		Path: file.Path, Kind: kind, Content: string(file.Data),
	}}, nil
}
