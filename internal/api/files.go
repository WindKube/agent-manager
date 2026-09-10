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

// The package files operations (US3/US5's "read before using it"): a file
// listing and a separate content read, both scoped to a package's LATEST
// VISIBLE version — the one every other panel on the detail screen
// describes. Neither is cached: each answers from a fresh unpack of the
// stored bundle, which is the cost of reading files nothing here stores a
// byte-level list of.

// maxRenderableFileBytes bounds getPackageFile's answer. 256 KiB is
// generous for hand-written documentation — the largest seeded SKILL.md is
// a few KB — while still bounding a worst-case render; a file over it is
// refused outright rather than truncated, because a half-read SKILL.md that
// looks complete is worse than an honest refusal.
const maxRenderableFileBytes = 256 << 10

// errVersionRejected is packageTree's answer for FR-029: a rejected version
// is never served, exactly as getBundle refuses one.
var errVersionRejected = errors.New("this version was rejected and is never served")

// packageTree resolves a package's latest visible version and unpacks its
// bundle, under the same extraction caps the fetcher enforces on ingestion
// (bundle.Limits{} takes its defaults) — a bundle read back out of object
// storage is still bytes off a network, and what could not be extracted
// must not become unpackable either.
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

// packageTreeError is the mapping packageTree's two named outcomes share
// with fail's generic one, so listPackageFiles and getPackageFile answer
// the same way to the same failures.
func packageTreeError(ctx context.Context, err error) error {
	if errors.Is(err, errVersionRejected) {
		return huma.Error403Forbidden(errVersionRejected.Error())
	}
	return fail(logging.From(ctx), err)
}

// classifyFile is the three-way split the screen renders differently:
// markdown goes through the sanitised markdown pipeline, text is shown
// verbatim and escaped, binary is listed and never rendered. A NUL byte or
// invalid UTF-8 in the first bytes is the same heuristic grep and git use to
// tell text from binary; this hub renders text, so the classification is
// read from the content once, not guessed from the extension.
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

// listPackageFiles answers the files panel: every regular file the latest
// visible version's bundle holds. It reads and re-unpacks that bundle on
// every call — see the package doc comment — because nothing here stores a
// byte-level file list to answer from instead.
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
	// SKILL.md before plugin.json: a plugin's OWN manifest is JSON and not
	// the document a person reads to understand what the package does: a
	// standalone skill has only the first candidate, and a plugin bundled
	// with a root SKILL.md of its own — not one of its skills' — should
	// still open on it.
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

// getPackageFile answers one file's content. Path is untrusted input off a
// URL and is resolved against the archive's OWN member list (tree.Lookup, an
// exact map lookup) — nothing here builds a filesystem path from it, so a
// traversal or absolute path simply matches nothing and is a 404.
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
