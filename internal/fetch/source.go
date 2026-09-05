package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"agent-manager/internal/bundle"
)

// SourceKind names the three shapes a registration accepts.
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

	// Archive and ArchiveName are set for the upload kind only. The reader is
	// not size-bounded here: the extraction caps are internal/bundle's.
	Archive     io.Reader
	ArchiveName string

	// Limits overrides the extraction caps; zero takes the defaults.
	Limits bundle.Limits
}

// Tree is what a Source produces: the extracted file tree and where it came
// from.
type Tree struct {
	Files *bundle.Bundle

	// Root is the path within Files holding the package root. "." when the
	// tree is already rooted.
	Root string

	// Origin is human-readable provenance for the audit row.
	Origin string
}

// Source turns a SourceRef into a Tree.
type Source interface {
	Name() string
	Handles(SourceRef) bool
	Fetch(ctx context.Context, ref SourceRef) (Tree, error)
}

var (
	// ErrNoSource means no registered Source claimed the reference.
	ErrNoSource = errors.New("no source handles this reference")

	// ErrRefNotFound is a ref, branch or tag the remote does not have.
	ErrRefNotFound = errors.New("the remote has no such ref")

	// ErrCredentialsRequired is a repository the hub holds no credential for.
	ErrCredentialsRequired = errors.New("the repository requires credentials the hub does not hold")

	// ErrUnsupportedHost is a forge this build cannot talk to.
	ErrUnsupportedHost = errors.New("repository host is not supported")

	// ErrRemote is any other non-success answer from the remote.
	ErrRemote = errors.New("the remote refused the request")
)

// Registry resolves a SourceRef to the one Source that handles it.
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

// Fetch resolves the reference and fetches it.
func (r *Registry) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	source, err := r.For(ref)
	if err != nil {
		return Tree{}, err
	}
	return source.Fetch(ctx, ref)
}

// The two file names that mark a package root, duplicated from
// internal/domain/pkgspec since that package must not depend on this one.
const (
	pluginManifestName = "plugin.json"
	skillManifestName  = "SKILL.md"
)

// packageRoot decides which directory inside an extracted archive holds the
// package. An explicit subdirectory always wins. Otherwise the root is the
// archive root, unless it wraps everything in exactly one directory that
// holds a manifest.
func packageRoot(files *bundle.Bundle, base, subdirectory string) string {
	join := func(parts ...string) string {
		kept := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.Trim(part, "/")
			if part != "" && part != "." {
				kept = append(kept, part)
			}
		}
		if len(kept) == 0 {
			return "."
		}
		return strings.Join(kept, "/")
	}

	if subdirectory != "" {
		return join(base, subdirectory)
	}
	if base != "" {
		return join(base)
	}
	if files.Has(pluginManifestName) || files.Has(skillManifestName) {
		return "."
	}
	if wrapper, ok := singleTopLevelDirectory(files); ok {
		if files.Has(wrapper+"/"+pluginManifestName) || files.Has(wrapper+"/"+skillManifestName) {
			return wrapper
		}
	}
	return "."
}

// singleTopLevelDirectory returns the one directory every path in the tree
// sits under, if there is exactly one and no file sits beside it.
func singleTopLevelDirectory(files *bundle.Bundle) (string, bool) {
	tops := make(map[string]struct{})
	for _, path := range files.Paths() {
		segments := strings.SplitN(path, "/", 2)
		if len(segments) == 1 {
			return "", false
		}
		tops[segments[0]] = struct{}{}
	}
	if len(tops) != 1 {
		return "", false
	}
	names := make([]string, 0, 1)
	for name := range tops {
		names = append(names, name)
	}
	sort.Strings(names)
	return names[0], true
}
