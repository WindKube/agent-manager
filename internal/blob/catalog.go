package blob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Index is skills/<publisher>/<name>/index.json, the commit-last pointer. A
// version's objects exist the moment their bytes land, but the version is
// not readable until this file names it, so every read goes through the
// index instead of guessing a key: object storage gives no transaction, so
// the last write is the commit.
type Index struct {
	// Namespace, not the publisher slug: this is the first key segment, so
	// it is `example`, never `example/platform`.
	Namespace string       `json:"namespace"`
	Name      string       `json:"name"`
	Latest    string       `json:"latest,omitempty"`
	Versions  []IndexEntry `json:"versions"`
	UpdatedAt time.Time    `json:"updatedAt"`
}

// IndexEntry is one committed version. Digest is the hex sha256 of the bundle as
// computed on write, so the catalog row and the index agree by construction.
type IndexEntry struct {
	Semver      string    `json:"semver"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"sizeBytes"`
	Bundle      string    `json:"bundle"`
	Manifest    string    `json:"manifest"`
	Scan        string    `json:"scan,omitempty"`
	Signature   string    `json:"signature,omitempty"`
	CommittedAt time.Time `json:"committedAt"`
}

// Entry returns the named version, or false when the index does not carry it.
func (i Index) Entry(semver string) (IndexEntry, bool) {
	for n := range i.Versions {
		if i.Versions[n].Semver == semver {
			return i.Versions[n], true
		}
	}
	return IndexEntry{}, false
}

// Semvers lists the committed versions in index order.
func (i Index) Semvers() []string {
	out := make([]string, 0, len(i.Versions))
	for n := range i.Versions {
		out = append(out, i.Versions[n].Semver)
	}
	return out
}

// Catalog is the read half of the object store. It holds a Reader and
// nothing else: the entire read path is expressible without a writer, which
// is what makes handing the scanner role a bare Reader possible.
type Catalog struct {
	read Reader
}

func NewCatalog(read Reader) *Catalog { return &Catalog{read: read} }

// Index reads a package's pointer. ErrNotFound means no version of the package
// has ever been committed.
func (c *Catalog) Index(ctx context.Context, pkg PackageRef) (Index, error) {
	if err := pkg.Validate(); err != nil {
		return Index{}, err
	}

	raw, err := c.read.ReadAll(ctx, pkg.IndexKey())
	if err != nil {
		return Index{}, err
	}

	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return Index{}, fmt.Errorf("decode %s: %w", pkg.IndexKey(), err)
	}
	return idx, nil
}

// Entry resolves one version through the index. A version the index does not
// name is not readable, whatever bytes happen to sit under its prefix.
func (c *Catalog) Entry(ctx context.Context, ref VersionRef) (IndexEntry, error) {
	if err := ref.Validate(); err != nil {
		return IndexEntry{}, err
	}

	idx, err := c.Index(ctx, ref.Package())
	if err != nil {
		return IndexEntry{}, err
	}
	entry, ok := idx.Entry(ref.Semver)
	if !ok {
		return IndexEntry{}, fmt.Errorf("%w: %s is not named by %s", ErrNotFound, ref, ref.Package().IndexKey())
	}
	return entry, nil
}

// Visible reports whether a version is committed and therefore readable.
func (c *Catalog) Visible(ctx context.Context, ref VersionRef) (bool, error) {
	_, err := c.Entry(ctx, ref)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// Latest resolves the index's latest pointer.
func (c *Catalog) Latest(ctx context.Context, pkg PackageRef) (IndexEntry, error) {
	idx, err := c.Index(ctx, pkg)
	if err != nil {
		return IndexEntry{}, err
	}
	if idx.Latest == "" {
		return IndexEntry{}, fmt.Errorf("%w: %s has no latest version", ErrNotFound, pkg)
	}
	entry, ok := idx.Entry(idx.Latest)
	if !ok {
		return IndexEntry{}, fmt.Errorf("%s names latest %q but does not list it", pkg.IndexKey(), idx.Latest)
	}
	return entry, nil
}

// OpenBundle streams a committed version's bundle.
func (c *Catalog) OpenBundle(ctx context.Context, ref VersionRef) (io.ReadCloser, error) {
	entry, err := c.Entry(ctx, ref)
	if err != nil {
		return nil, err
	}
	return c.read.NewReader(ctx, entry.Bundle)
}

// ReadManifest reads a committed version's manifest, whichever of plugin.json or
// SKILL.md the publisher shipped.
func (c *Catalog) ReadManifest(ctx context.Context, ref VersionRef) ([]byte, error) {
	entry, err := c.Entry(ctx, ref)
	if err != nil {
		return nil, err
	}
	return c.read.ReadAll(ctx, entry.Manifest)
}

// ReadScan reads a committed version's scan report.
func (c *Catalog) ReadScan(ctx context.Context, ref VersionRef) ([]byte, error) {
	entry, err := c.Entry(ctx, ref)
	if err != nil {
		return nil, err
	}
	if entry.Scan == "" {
		return nil, fmt.Errorf("%w: %s has no scan report", ErrNotFound, ref)
	}
	return c.read.ReadAll(ctx, entry.Scan)
}

// ReadSignature reads a committed version's signature blob: registry-side
// metadata, unverified until sigstore-go lands.
func (c *Catalog) ReadSignature(ctx context.Context, ref VersionRef) ([]byte, error) {
	entry, err := c.Entry(ctx, ref)
	if err != nil {
		return nil, err
	}
	if entry.Signature == "" {
		return nil, fmt.Errorf("%w: %s has no signature", ErrNotFound, ref)
	}
	return c.read.ReadAll(ctx, entry.Signature)
}
