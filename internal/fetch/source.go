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

// The Source contract from contracts/worker.md section 3. The three
// implementations (upload, git, archive-url) live in their own files; nothing
// here knows they exist.

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

	// Limits overrides the R3 extraction caps. The zero value takes the defaults,
	// which is what production uses; tests shrink them to prove a cap fires.
	Limits bundle.Limits
}

// Tree is what a Source produces: the extracted file tree and where it came from.
//
// It carries a *bundle.Bundle rather than raw archive bytes because the caps and
// the member rules are internal/bundle's alone (R3) and a Source calls them
// rather than reimplementing them — three sources with three readings of "reject
// a symlink" is the defect this shape prevents. What a Source adds on top is only
// provenance and the knowledge of where the package root sits inside the archive,
// which no general extractor can know: a GitHub tarball wraps everything in one
// `owner-repo-<sha>/` directory whose name is unpredictable.
type Tree struct {
	Files *bundle.Bundle

	// Root is the path within Files holding the package root, after
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

// The failures a Source reports, distinct from every scan outcome. US1 scenario 5
// and the spec's ingestion edge cases require these to be tellable apart from a
// finding: a refused address, an absent ref, a missing subdirectory and a
// repository the hub has no credential for are all fetch errors, and none of them
// says anything about what the package does.
var (
	// ErrNoSource means no registered Source claimed the reference.
	ErrNoSource = errors.New("no source handles this reference")

	// ErrRefNotFound is a ref, branch or tag the remote does not have.
	ErrRefNotFound = errors.New("the remote has no such ref")

	// ErrCredentialsRequired is a repository the hub holds no credential for. It
	// is reported as itself rather than as "not found", because the operator's next
	// action is different.
	ErrCredentialsRequired = errors.New("the repository requires credentials the hub does not hold")

	// ErrUnsupportedHost is a forge this build cannot talk to.
	ErrUnsupportedHost = errors.New("repository host is not supported")

	// ErrRemote is any other non-success answer from the remote.
	ErrRemote = errors.New("the remote refused the request")
)

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

// Fetch resolves the reference and fetches it.
func (r *Registry) Fetch(ctx context.Context, ref SourceRef) (Tree, error) {
	source, err := r.For(ref)
	if err != nil {
		return Tree{}, err
	}
	return source.Fetch(ctx, ref)
}

// The two file names that mark a package root. They are duplicated from
// internal/domain/pkgspec rather than imported: internal/domain must not depend on
// internal/fetch and the reverse dependency would make the layering a matter of
// which file you read first. What is needed here is only "which directory is the
// root", not what a manifest means.
const (
	pluginManifestName = "plugin.json"
	skillManifestName  = "SKILL.md"
)

// packageRoot decides which directory inside an extracted archive holds the
// package.
//
// An explicit subdirectory always wins and is never second-guessed: a caller who
// typed one meant it, and silently fetching a different directory publishes bytes
// they did not ask for. Otherwise the root is the archive root, unless the archive
// wraps everything in exactly one directory that holds a manifest — which is what
// every "Download ZIP" and every forge tarball produces. The gate is deliberately
// narrow: the wrapper must be the ONLY top-level directory AND must hold a
// manifest, so a tree whose root legitimately contains just `skills/` is not
// mistaken for one.
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

// singleTopLevelDirectory returns the one directory every path in the tree sits
// under, if there is exactly one and no file sits beside it.
func singleTopLevelDirectory(files *bundle.Bundle) (string, bool) {
	tops := make(map[string]struct{})
	for _, path := range files.Paths() {
		segments := strings.SplitN(path, "/", 2)
		if len(segments) == 1 {
			// A file at the archive root means the archive is not wrapped.
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
