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

	// ManifestObjectName is plugin.json for a plugin and SKILL.md for a
	// standalone skill. Empty means plugin.json.
	ManifestObjectName string
	Manifest           []byte

	// Scan and Signature are optional: versions are committed before scanning.
	Scan      []byte
	Signature []byte

	// Latest moves the index's latest pointer onto this version.
	Latest bool
}

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

// Committer publishes versions commit-last. It holds both halves because
// appending to index.json requires reading it; only the fetcher role builds one.
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

// Commit writes one version and makes it visible: stage every part, promote to
// the write-once semver keys, write index.json last, then best-effort delete
// staging. A crash before the index write leaves the version unreadable, never
// half-published.
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

	// The manifest is plugin.json or SKILL.md and nothing else: an arbitrary
	// name here would let a manifest be promoted over the bundle key.
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

	// Fetches are delivered at least once; a version the index already names is
	// committed, so a redelivery is a no-op.
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

	index.Namespace = ref.Namespace
	index.Name = ref.Name
	index.Versions = append(index.Versions, entry)
	index.UpdatedAt = c.now().UTC()
	// The first version always becomes latest so floating latest resolves; which
	// later version is latest is the caller's catalog decision, not semver order.
	if parts.Latest || index.Latest == "" {
		index.Latest = ref.Semver
	}
	if err := c.writeIndex(ctx, ref.Package(), index); err != nil {
		return Commit{}, err
	}

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
