package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// The Source contract from contracts/worker.md section 3. The three
// implementations (upload, git, archive-url) are T039 and live in their own
// files; nothing here knows they exist.

// SourceKind names the three shapes FR-001 accepts.
type SourceKind string

const (
	SourceUpload     SourceKind = "upload"
	SourceGit        SourceKind = "git"
	SourceArchiveURL SourceKind = "archive-url"
)

// SourceRef is a registration request as a Source sees it.
type SourceRef struct {
	Kind SourceKind

	// URL, Ref and Subdirectory are set for the git and archive-url kinds.
	URL          string
	Ref          string
	Subdirectory string

	// Archive and ArchiveName are set for the upload kind only. The reader is not
	// size-bounded here on purpose: the caps are internal/bundle's (R3), and a
	// Source that enforced its own would give three chances to get them wrong.
	Archive     io.Reader
	ArchiveName string
}

// Tree is what a Source produces: the fetched bytes and where they came from.
//
// It is an fs.FS and nothing else because a Source's job ends at "here are the
// bytes". Every cap, every rejected member kind and the digest belong to
// internal/bundle, which walks this under the R3 limits.
type Tree struct {
	FS fs.FS

	// Root is the path within FS holding the package root, after
	// SourceRef.Subdirectory is applied. "." when the tree is already rooted.
	Root string

	// Origin is human-readable provenance for the audit row, e.g.
	// "git https://github.com/org/plugin@v1.3.0 (plugins/platform-toolkit)".
	Origin string
}

// Source turns a SourceRef into a Tree. A Source that touches the network uses
// the Client it was given; constructing an http.Client inside one is a defect
// (constitution principle III).
type Source interface {
	Name() string
	Handles(SourceRef) bool
	Fetch(ctx context.Context, ref SourceRef) (Tree, error)
}

// ErrNoSource means no registered Source claimed the reference.
var ErrNoSource = errors.New("no source handles this reference")

// Registry resolves a SourceRef to the one Source that handles it. Adding a
// source later is a new file plus a line at the construction site.
type Registry struct {
	sources []Source
}

func NewRegistry(sources ...Source) *Registry {
	return &Registry{sources: sources}
}

func (r *Registry) Register(s Source) { r.sources = append(r.sources, s) }

// Sources returns the registered sources in registration order.
func (r *Registry) Sources() []Source { return r.sources }

// For returns the first Source claiming ref.
func (r *Registry) For(ref SourceRef) (Source, error) {
	for _, s := range r.sources {
		if s.Handles(ref) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%w: kind %q", ErrNoSource, ref.Kind)
}
