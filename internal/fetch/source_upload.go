package fetch

import (
	"context"
	"errors"
	"fmt"

	"agent-manager/internal/bundle"
)

// UploadSource extracts an archive the user uploaded (FR-001: `.zip` or
// `.tar.gz`, at most 25 MB).
//
// It touches no network at all, which is why it holds no Client. That is the one
// registration path that works with no outbound access, and quickstart.md points
// at it for exactly that reason.
type UploadSource struct{}

func NewUploadSource() UploadSource { return UploadSource{} }

var _ Source = UploadSource{}

func (UploadSource) Name() string { return string(SourceUpload) }

func (UploadSource) Handles(ref SourceRef) bool { return ref.Kind == SourceUpload }

func (UploadSource) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	if ref.Archive == nil {
		return Tree{}, errors.New("upload source: no archive")
	}

	// Every cap is internal/bundle's. Extract sniffs zip versus tar.gz, enforces
	// the compressed cap before extraction begins and the ratio continuously as
	// bytes stream, and rejects absolute paths, traversal, symlinks, hardlinks,
	// device nodes and duplicates outright (R3, FR-003).
	files, err := bundle.Extract(ctx, ref.Archive, ref.Limits)
	if err != nil {
		return Tree{}, fmt.Errorf("extract uploaded archive %s: %w", displayName(ref.ArchiveName), err)
	}

	return Tree{
		Files:  files,
		Root:   packageRoot(files, "", ref.Subdirectory),
		Origin: "upload " + displayName(ref.ArchiveName),
	}, nil
}

func displayName(name string) string {
	if name == "" {
		return "(unnamed archive)"
	}
	return name
}
