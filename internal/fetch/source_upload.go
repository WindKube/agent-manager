package fetch

import (
	"context"
	"errors"
	"fmt"

	"agent-manager/internal/bundle"
)

// UploadSource extracts an archive the user uploaded (`.zip` or `.tar.gz`,
// at most 25 MB). It touches no network, so it holds no Client.
type UploadSource struct{}

func NewUploadSource() UploadSource { return UploadSource{} }

var _ Source = UploadSource{}

func (UploadSource) Name() string { return string(SourceUpload) }

func (UploadSource) Handles(ref SourceRef) bool { return ref.Kind == SourceUpload }

func (UploadSource) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	if ref.Archive == nil {
		return Tree{}, errors.New("upload source: no archive")
	}

	// Extract enforces the compressed-size cap and the decompression ratio
	// as bytes stream, and rejects traversal, symlinks and device nodes.
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
