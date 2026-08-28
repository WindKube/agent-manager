package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// VersionParts is one version's four objects as the fetcher hands them over.
type VersionParts struct {
	// Bundle is streamed, never buffered: it is the only part that can be large.
	Bundle io.Reader

	// ManifestObjectName is plugin.json for a plugin and SKILL.md for a standalone
	// skill. Empty means plugin.json.
	ManifestObjectName string
	Manifest           []byte

	// Scan and Signature are optional. A version is committed before it is
	// scanned — the design renders "Scanning" as a visible state — and a signature
	// is only present when the publisher supplied one (R9).
	Scan      []byte
	Signature []byte

	// Latest moves the index's latest pointer onto this version.
	Latest bool
}

// stagedPart is one object on its way through the staging prefix.
type stagedPart struct {
	object string
	body   io.Reader
}

// Commit is the outcome of one publish.
type Commit struct {
	Ref    VersionRef
	Entry  IndexEntry
	Bundle Object

	// AlreadyCommitted marks a redelivery: the version's bytes were on record
	// before this call, so nothing was written.
	AlreadyCommitted bool
}

// Committer publishes versions commit-last (FR-008).
//
// It holds both halves because appending to index.json means reading the existing
// index first — and because only the fetcher role, which declares
// Blob: AccessReadWrite, ever constructs one.
type Committer struct {
	read  Reader
	write Writer

	// Seams, so the tests can pin the timestamps and the staging prefix.
	now     func() time.Time
	attempt func() string
}

func NewCommitter(read Reader, write Writer) *Committer {
	return &Committer{read: read, write: write, now: time.Now, attempt: uuid.NewString}
}

// Commit writes one version and makes it visible, in that order.
//
// The sequence is the guarantee, so it is spelled out rather than inlined:
//
//  1. Every part goes to a staging prefix. Nothing under it is reachable through
//     the index, so a crash anywhere below leaves the version unreadable rather
//     than half-published.
//  2. The parts are promoted to their final, semver-scoped keys. A version is
//     write-once (principle IV), so this can never overwrite live bytes.
//  3. index.json is written LAST. Until that write lands, Catalog refuses to
//     resolve the version, and that refusal is what FR-008 asks for.
//  4. Staging is deleted. It is garbage by then, so a failed cleanup must not fail
//     a publish that has already committed.
func (c *Committer) Commit(ctx context.Context, ref VersionRef, parts VersionParts) (Commit, error) {
	if err := ref.Validate(); err != nil {
		return Commit{}, err
	}
	if parts.Bundle == nil {
		return Commit{}, fmt.Errorf("commit %s: bundle reader is nil", ref)
	}
	if len(parts.Manifest) == 0 {
		return Commit{}, fmt.Errorf("commit %s: manifest is empty", ref)
	}

	// The manifest is plugin.json or SKILL.md and nothing else (FR-006). An
	// arbitrary name here would let a manifest be promoted over the bundle key.
	manifestName := parts.ManifestObjectName
	if manifestName == "" {
		manifestName = ManifestObject
	}
	if manifestName != ManifestObject && manifestName != SkillManifestObject {
		return Commit{}, fmt.Errorf("commit %s: manifest object %q is neither %s nor %s",
			ref, manifestName, ManifestObject, SkillManifestObject)
	}

	index, err := c.loadIndex(ctx, ref.Package())
	if err != nil {
		return Commit{}, err
	}

	// A fetch is delivered at least once (principle IX). A version the index
	// already names has committed bytes, so the redelivery is a no-op rather than
	// a second upload — the pointer naming it IS the record that the bytes landed.
	if entry, ok := index.Entry(ref.Semver); ok {
		return Commit{Ref: ref, Entry: entry, AlreadyCommitted: true}, nil
	}

	attempt := c.attempt()
	staged := []stagedPart{
		{object: BundleObject, body: parts.Bundle},
		{object: manifestName, body: bytes.NewReader(parts.Manifest)},
	}
	if len(parts.Scan) > 0 {
		staged = append(staged, stagedPart{object: ScanObject, body: bytes.NewReader(parts.Scan)})
	}
	if len(parts.Signature) > 0 {
		staged = append(staged, stagedPart{object: SignatureObject, body: bytes.NewReader(parts.Signature)})
	}

	// Step 1 — staging.
	var (
		bundle     Object
		stagedKeys = make([]string, 0, len(staged))
	)
	for _, part := range staged {
		key := stagingKey(ref, attempt, part.object)
		obj, writeErr := c.write.Write(ctx, key, part.body)
		if writeErr != nil {
			return Commit{}, fmt.Errorf("stage %s for %s: %w", part.object, ref, writeErr)
		}
		stagedKeys = append(stagedKeys, key)
		if part.object == BundleObject {
			bundle = Object{Key: ref.BundleKey(), Size: obj.Size, Digest: obj.Digest}
		}
	}

	// Step 2 — promote.
	for i, part := range staged {
		if err := c.write.Copy(ctx, ref.Key(part.object), stagedKeys[i]); err != nil {
			return Commit{}, fmt.Errorf("promote %s for %s: %w", part.object, ref, err)
		}
	}

	entry := IndexEntry{
		Semver:      ref.Semver,
		Digest:      bundle.Hex(),
		SizeBytes:   bundle.Size,
		Bundle:      ref.BundleKey(),
		Manifest:    ref.Key(manifestName),
		CommittedAt: c.now().UTC(),
	}
	if len(parts.Scan) > 0 {
		entry.Scan = ref.Key(ScanObject)
	}
	if len(parts.Signature) > 0 {
		entry.Signature = ref.Key(SignatureObject)
	}

	// Step 3 — the pointer, last.
	index.Namespace = ref.Namespace
	index.Name = ref.Name
	index.Versions = append(index.Versions, entry)
	index.UpdatedAt = c.now().UTC()
	// A package's first version always becomes latest: an index that named no
	// version would leave the CLI's "floating latest" policy with nothing to
	// resolve. Which of several versions is latest is a catalog decision the caller
	// makes (dist_tag), never a semver comparison here.
	if parts.Latest || index.Latest == "" {
		index.Latest = ref.Semver
	}
	if err := c.writeIndex(ctx, ref.Package(), index); err != nil {
		return Commit{}, err
	}

	// Step 4 — cleanup, deliberately not fatal.
	for _, key := range stagedKeys {
		_ = c.write.Delete(ctx, key)
	}

	return Commit{Ref: ref, Entry: entry, Bundle: bundle}, nil
}

// SetLatest moves a package's latest pointer without publishing anything. Which
// version is latest is a catalog decision (dist_tag), not an object-store one, so
// the caller names it.
func (c *Committer) SetLatest(ctx context.Context, pkg PackageRef, semver string) error {
	index, err := c.loadIndex(ctx, pkg)
	if err != nil {
		return err
	}
	if _, ok := index.Entry(semver); !ok {
		return fmt.Errorf("%w: %s@%s is not committed", ErrNotFound, pkg, semver)
	}
	index.Latest = semver
	index.UpdatedAt = c.now().UTC()
	return c.writeIndex(ctx, pkg, index)
}

// loadIndex reads the current pointer, treating "never published" as an empty
// index rather than an error.
func (c *Committer) loadIndex(ctx context.Context, pkg PackageRef) (Index, error) {
	idx, err := NewCatalog(c.read).Index(ctx, pkg)
	if errors.Is(err, ErrNotFound) {
		return Index{Namespace: pkg.Namespace, Name: pkg.Name}, nil
	}
	if err != nil {
		return Index{}, err
	}
	return idx, nil
}

func (c *Committer) writeIndex(ctx context.Context, pkg PackageRef, index Index) error {
	encoded, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", pkg.IndexKey(), err)
	}
	if _, err := c.write.Write(ctx, pkg.IndexKey(), bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("write %s: %w", pkg.IndexKey(), err)
	}
	return nil
}
