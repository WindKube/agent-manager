// These tests run against memblob, so they need no container (R13). Everything
// asserted here is a guarantee this package adds on top of gocloud: the key
// layout, sha256-on-write, and commit-last visibility.
package blob_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/blob"
)

func newBucket(t *testing.T) *blob.Bucket {
	t.Helper()

	b, err := blob.Open(context.Background(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	return b
}

var ref = blob.VersionRef{Publisher: "example", Name: "terraform-module-review", Semver: "2.4.1"}

func parts(bundle []byte) blob.VersionParts {
	return blob.VersionParts{
		Bundle:    strings.NewReader(string(bundle)),
		Manifest:  []byte(`{"name":"terraform-module-review"}`),
		Scan:      []byte(`{"verdict":"clean"}`),
		Signature: []byte("not-a-real-signature"),
		Latest:    true,
	}
}

// ---------------------------------------------------------------------------
// Principle II, Go half — the reader has no writer to assert back to
// ---------------------------------------------------------------------------

// The scanner role is handed Deps.BlobRead and nothing else. If the value behind
// that interface also satisfied blob.Writer, one type assertion would hand the
// scanner a publish credential, and the contract's claim that the Go type system
// enforces this boundary would be false.
func TestTheReadHalfCannotBeAssertedBackToTheWriteHalf(t *testing.T) {
	bucket := newBucket(t)

	read := bucket.Reader()

	_, isWriter := read.(blob.Writer)
	require.False(t, isWriter,
		"blob.Reader's dynamic type must not implement blob.Writer, or the scanner can assert its way to a writer")

	// The mirror case, so the split is not accidentally one-directional.
	_, isReader := bucket.Writer().(blob.Reader)
	require.False(t, isReader, "blob.Writer's dynamic type must not implement blob.Reader")

	// And the read path is complete on its own: a Catalog is constructible from a
	// Reader alone, which is what a scanner-shaped construction looks like.
	catalog := blob.NewCatalog(read)
	require.NotNil(t, catalog)

	_, err := catalog.Index(context.Background(), ref.Package())
	require.ErrorIs(t, err, blob.ErrNotFound)
}

// ---------------------------------------------------------------------------
// FR-007 — sha256 on write, streaming
// ---------------------------------------------------------------------------

// The digest must come from the bytes as they pass, not from re-reading the
// object: a re-read doubles the transfer and hashes whatever the bucket holds at
// that moment rather than what this call wrote. The source here is read exactly
// once and is neither an io.Seeker nor an io.ReaderAt, so a rewind was not
// available to the implementation.
func TestSha256IsComputedWhileTheBytesStreamPastAndTheSourceIsReadExactlyOnce(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)

	payload := []byte(strings.Repeat("bundle bytes ", 4096))
	src := &countingReader{data: payload}

	obj, err := bucket.Writer().Write(ctx, ref.BundleKey(), src)
	require.NoError(t, err)

	want := sha256.Sum256(payload)
	require.Equal(t, hex.EncodeToString(want[:]), obj.Hex())
	require.EqualValues(t, len(payload), obj.Size)

	require.Equal(t, len(payload), src.consumed, "the source must be consumed exactly once")

	require.NotImplements(t, (*io.Seeker)(nil), src, "a seekable source would let the digest come from a second pass")
	require.NotImplements(t, (*io.ReaderAt)(nil), src)
}

// ---------------------------------------------------------------------------
// FR-008 — commit-last visibility
// ---------------------------------------------------------------------------

// The load-bearing test. It does not merely check that the version is readable at
// the end: it watches every object write and asserts that the write which made
// the version visible was index.json, and that the bundle was fully readable the
// instant that happened. Writing the pointer first flips visibility on a version
// whose bytes are not there yet, which is exactly what this catches.
func TestAVersionBecomesVisibleOnlyOnTheIndexWriteAndIsFullyReadableTheInstantItDoes(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)

	payload := []byte("the bundle bytes")
	catalog := blob.NewCatalog(bucket.Reader())

	watch := &visibilityWatcher{t: t, inner: bucket.Writer(), catalog: catalog, ref: ref}
	committer := blob.NewCommitter(bucket.Reader(), watch)

	require.False(t, mustVisible(t, ctx, catalog, ref), "nothing is visible before the commit starts")

	commit, err := committer.Commit(ctx, ref, parts(payload))
	require.NoError(t, err)
	require.False(t, commit.AlreadyCommitted)

	require.NotEmpty(t, watch.steps, "the committer must have written something")

	firstVisible := -1
	for i, step := range watch.steps {
		if step.visible {
			firstVisible = i
			break
		}
	}
	require.GreaterOrEqual(t, firstVisible, 0, "the version never became visible")
	require.Equal(t, ref.Package().IndexKey(), watch.steps[firstVisible].key,
		"the write that made the version visible must be index.json, not one of its parts")
	require.Equal(t, "write", watch.steps[firstVisible].op)

	for _, step := range watch.steps[:firstVisible] {
		require.False(t, step.visible, "%s %s made the version visible before index.json did", step.op, step.key)
	}

	require.NoError(t, watch.readErr, "the bundle must be readable the instant the version becomes visible")
	require.Equal(t, payload, watch.readBytes,
		"a version that is visible but whose bytes are absent or partial is exactly what FR-008 forbids")

	// And the whole tree is where the design says it is.
	entry, err := catalog.Entry(ctx, ref)
	require.NoError(t, err)
	require.Equal(t, "skills/example/terraform-module-review/2.4.1/bundle.tar.zst", entry.Bundle)
	require.Equal(t, "skills/example/terraform-module-review/2.4.1/plugin.json", entry.Manifest)
	require.Equal(t, "skills/example/terraform-module-review/2.4.1/scan.json", entry.Scan)
	require.Equal(t, "skills/example/terraform-module-review/2.4.1/signature.sig", entry.Signature)

	digest := sha256.Sum256(payload)
	require.Equal(t, hex.EncodeToString(digest[:]), entry.Digest)

	latest, err := catalog.Latest(ctx, ref.Package())
	require.NoError(t, err)
	require.Equal(t, ref.Semver, latest.Semver)

	// Staging is gone once the pointer is live, so a listing of the catalog holds
	// only committed objects.
	staged, err := bucket.Reader().List(ctx, blob.StagingPrefix)
	require.NoError(t, err)
	require.Empty(t, staged, "the staging prefix must be empty after a successful commit")
}

// An interrupted write must leave nothing readable. Each case interrupts for
// real — a cancelled context, a source that dies mid-stream, a failed promote, a
// failed pointer write — rather than skipping a step, and the last case is the
// dangerous one: every part has landed and only index.json is missing.
func TestAnInterruptedCommitLeavesNothingReadable(t *testing.T) {
	payload := []byte("the bundle bytes")

	for _, tc := range []struct {
		name string
		// interrupt returns the writer to commit through and the parts to commit.
		interrupt func(t *testing.T, cancel context.CancelFunc, w blob.Writer) (blob.Writer, blob.VersionParts)
	}{
		{
			name: "the context is cancelled while the bundle streams",
			interrupt: func(_ *testing.T, cancel context.CancelFunc, w blob.Writer) (blob.Writer, blob.VersionParts) {
				p := parts(payload)
				p.Bundle = &cancellingReader{data: payload, cancelAfter: 4, cancel: cancel}
				return w, p
			},
		},
		{
			name: "the bundle source dies mid-stream",
			interrupt: func(_ *testing.T, _ context.CancelFunc, w blob.Writer) (blob.Writer, blob.VersionParts) {
				p := parts(payload)
				p.Bundle = io.MultiReader(strings.NewReader("half"), errReader{})
				return w, p
			},
		},
		{
			name: "the manifest fails to promote out of staging",
			interrupt: func(_ *testing.T, _ context.CancelFunc, w blob.Writer) (blob.Writer, blob.VersionParts) {
				return &failingWriter{inner: w, failOn: func(op, key string) bool {
					return op == "copy" && strings.HasSuffix(key, blob.ManifestObject)
				}}, parts(payload)
			},
		},
		{
			name: "index.json fails after every part has landed",
			interrupt: func(_ *testing.T, _ context.CancelFunc, w blob.Writer) (blob.Writer, blob.VersionParts) {
				return &failingWriter{inner: w, failOn: func(op, key string) bool {
					return op == "write" && key == ref.Package().IndexKey()
				}}, parts(payload)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			bucket := newBucket(t)
			catalog := blob.NewCatalog(bucket.Reader())

			write, p := tc.interrupt(t, cancel, bucket.Writer())
			_, err := blob.NewCommitter(bucket.Reader(), write).Commit(ctx, ref, p)
			require.Error(t, err, "the interruption must be reported, not swallowed")

			// Readability is defined by the pointer, so this is the assertion that
			// matters: whatever bytes did land, no read path can reach the version.
			probe := context.Background()

			visible, err := catalog.Visible(probe, ref)
			require.NoError(t, err)
			require.False(t, visible, "an interrupted version must not be visible")

			_, err = catalog.OpenBundle(probe, ref)
			require.ErrorIs(t, err, blob.ErrNotFound)

			_, err = catalog.ReadManifest(probe, ref)
			require.ErrorIs(t, err, blob.ErrNotFound)

			_, err = catalog.Index(probe, ref.Package())
			require.ErrorIs(t, err, blob.ErrNotFound,
				"the pointer is the commit; an interrupted first publish must not have written one")
		})
	}
}

// The second half of the same guarantee: an interrupted publish must not damage
// what is already committed. A reader holding v1.0.0 keeps reading it while
// v2.4.1 fails.
func TestAnInterruptedCommitLeavesAnAlreadyCommittedVersionReadable(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)
	catalog := blob.NewCatalog(bucket.Reader())

	first := blob.VersionRef{Publisher: ref.Publisher, Name: ref.Name, Semver: "1.0.0"}
	firstBytes := []byte("the first bundle")

	_, err := blob.NewCommitter(bucket.Reader(), bucket.Writer()).Commit(ctx, first, parts(firstBytes))
	require.NoError(t, err)

	failing := &failingWriter{inner: bucket.Writer(), failOn: func(op, key string) bool {
		return op == "write" && key == ref.Package().IndexKey()
	}}
	_, err = blob.NewCommitter(bucket.Reader(), failing).Commit(ctx, ref, parts([]byte("the second bundle")))
	require.Error(t, err)

	visible, err := catalog.Visible(ctx, ref)
	require.NoError(t, err)
	require.False(t, visible, "the interrupted version must still be invisible")

	rc, err := catalog.OpenBundle(ctx, first)
	require.NoError(t, err)
	defer func() { require.NoError(t, rc.Close()) }()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, firstBytes, got, "the committed version must be byte-identical after a failed publish")

	idx, err := catalog.Index(ctx, ref.Package())
	require.NoError(t, err)
	require.Equal(t, []string{"1.0.0"}, idx.Semvers())
	require.Equal(t, "1.0.0", idx.Latest)
}

// ---------------------------------------------------------------------------
// Principle IX — at-least-once delivery reaches the object store too
// ---------------------------------------------------------------------------

// A fetch job is delivered at least once, so the fetcher may be asked to publish
// a version whose bytes are already on record. The index naming it IS that
// record, so the redelivery writes nothing at all.
func TestARedeliveredCommitForAVersionWithCommittedBytesIsANoOp(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)

	payload := []byte("the bundle bytes")
	committer := blob.NewCommitter(bucket.Reader(), bucket.Writer())

	first, err := committer.Commit(ctx, ref, parts(payload))
	require.NoError(t, err)
	require.False(t, first.AlreadyCommitted)

	before, err := bucket.Reader().List(ctx, "")
	require.NoError(t, err)

	// The redelivery carries different bytes on purpose: if the committer wrote
	// anything, the digest on record would move and FR-007's "never republish with
	// different bytes" would be broken here rather than in the database.
	counted := &countingWriter{inner: bucket.Writer()}
	redelivered, err := blob.NewCommitter(bucket.Reader(), counted).
		Commit(ctx, ref, parts([]byte("tampered bytes")))
	require.NoError(t, err)

	require.True(t, redelivered.AlreadyCommitted)
	require.Equal(t, first.Entry, redelivered.Entry)
	require.Zero(t, counted.writes, "a redelivery must not write an object")
	require.Zero(t, counted.copies)
	require.Zero(t, counted.deletes)

	after, err := bucket.Reader().List(ctx, "")
	require.NoError(t, err)
	require.Equal(t, keysOf(before), keysOf(after), "the object set must be unchanged by a redelivery")

	catalog := blob.NewCatalog(bucket.Reader())
	entry, err := catalog.Entry(ctx, ref)
	require.NoError(t, err)

	digest := sha256.Sum256(payload)
	require.Equal(t, hex.EncodeToString(digest[:]), entry.Digest, "the original digest must survive the redelivery")
}

// R13 — the three drivers this project ships with must all be linked. A dropped
// blank import compiles, passes every memblob test, and then fails at run time in
// compose with "no driver registered for s3", which is the worst place to find
// out. Opening a bucket contacts nothing, so this stays a unit test.
func TestEveryShippedDriverSchemeOpens(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"memblob, for the unit tests", "mem://"},
		{"fileblob, for the container-free dev mode", "file://" + dir},
		{"s3blob, for MinIO and S3", "s3://example-bucket?region=eu-central-1&endpoint=http://127.0.0.1:9000&hostname_immutable=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket, err := blob.Open(ctx, tc.url)
			require.NoError(t, err)
			require.NoError(t, bucket.Close())
		})
	}

	t.Run("an empty url is refused rather than defaulted", func(t *testing.T) {
		_, err := blob.Open(ctx, "   ")
		require.Error(t, err)
	})

	// fileblob is a deployment mode, not just a scheme, so it gets a round trip.
	t.Run("fileblob round-trips a committed version", func(t *testing.T) {
		bucket, err := blob.Open(ctx, "file://"+dir)
		require.NoError(t, err)
		defer func() { require.NoError(t, bucket.Close()) }()

		payload := []byte("the bundle bytes")
		_, err = blob.NewCommitter(bucket.Reader(), bucket.Writer()).Commit(ctx, ref, parts(payload))
		require.NoError(t, err)

		rc, err := blob.NewCatalog(bucket.Reader()).OpenBundle(ctx, ref)
		require.NoError(t, err)
		defer func() { require.NoError(t, rc.Close()) }()

		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})
}

// ---------------------------------------------------------------------------
// The key layout, and the fact that it is built from untrusted strings
// ---------------------------------------------------------------------------

func TestTheKeyLayoutIsTheDesignsLayout(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"bundle", ref.BundleKey(), "skills/example/terraform-module-review/2.4.1/bundle.tar.zst"},
		{"manifest", ref.Key(blob.ManifestObject), "skills/example/terraform-module-review/2.4.1/plugin.json"},
		{"skill manifest", ref.Key(blob.SkillManifestObject), "skills/example/terraform-module-review/2.4.1/SKILL.md"},
		{"scan report", ref.Key(blob.ScanObject), "skills/example/terraform-module-review/2.4.1/scan.json"},
		{"signature", ref.Key(blob.SignatureObject), "skills/example/terraform-module-review/2.4.1/signature.sig"},
		{"index", ref.Package().IndexKey(), "skills/example/terraform-module-review/index.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.got)
		})
	}

	revision, err := blob.ProfileRevisionKey("example/platform-engineer", 14)
	require.NoError(t, err)
	require.Equal(t, "profiles/example/platform-engineer/r14.json", revision)

	head, err := blob.ProfileHeadKey("example/platform-engineer")
	require.NoError(t, err)
	require.Equal(t, "profiles/example/platform-engineer/head.json", head)
}

// A publisher slug, a package name and a semver all reach this package from a
// user-supplied manifest or repository URL, so a key built from them is untrusted
// input (principle III). Every one of these would climb out of its prefix.
func TestAKeySegmentThatCouldEscapeItsPrefixIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		segment string
		// legalSlug marks the one shape a profile slug may legitimately carry: the
		// design's profiles/example/platform-engineer/ is a two-segment slug, so a
		// slash is validated per segment there rather than refused outright.
		legalSlug bool
	}{
		{name: "parent directory", segment: ".."},
		{name: "parent directory inside a name", segment: "a../b"},
		{name: "absolute path", segment: "/etc/passwd"},
		{name: "a slash", segment: "example/other", legalSlug: true},
		{name: "a leading dot", segment: ".hidden"},
		{name: "empty", segment: ""},
		{name: "a space", segment: "two words"},
		{name: "a newline", segment: "name\nother"},
		{name: "a null byte", segment: "name\x00"},
		{name: "a backslash", segment: "name\\sibling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, blob.PackageRef{Publisher: tc.segment, Name: "ok"}.Validate())
			require.Error(t, blob.PackageRef{Publisher: "ok", Name: tc.segment}.Validate())
			require.Error(t, blob.VersionRef{Publisher: "ok", Name: "ok", Semver: tc.segment}.Validate())

			_, err := blob.ProfileHeadKey(tc.segment)
			if tc.legalSlug {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}

	// The shapes that must keep working, or the rule is too tight to publish with.
	for _, tc := range []struct {
		name string
		ref  blob.VersionRef
	}{
		{"a plain semver", blob.VersionRef{Publisher: "example", Name: "pii-redactor", Semver: "1.4.2"}},
		{"a prerelease", blob.VersionRef{Publisher: "example", Name: "pii-redactor", Semver: "2.0.0-rc.1"}},
		{"build metadata", blob.VersionRef{Publisher: "example", Name: "pii-redactor", Semver: "2.0.0+build.7"}},
		{"a dotted name", blob.VersionRef{Publisher: "community", Name: "slack.digest", Semver: "0.5.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.ref.Validate())
		})
	}
}

func TestCommitRejectsAnIncompleteVersion(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)
	committer := blob.NewCommitter(bucket.Reader(), bucket.Writer())

	for _, tc := range []struct {
		name  string
		ref   blob.VersionRef
		parts blob.VersionParts
	}{
		{
			name:  "no bundle",
			ref:   ref,
			parts: blob.VersionParts{Manifest: []byte("{}")},
		},
		{
			name:  "no manifest",
			ref:   ref,
			parts: blob.VersionParts{Bundle: strings.NewReader("bytes")},
		},
		{
			name:  "a traversing semver",
			ref:   blob.VersionRef{Publisher: "example", Name: "p", Semver: "../../etc"},
			parts: parts([]byte("bytes")),
		},
		{
			// An arbitrary manifest name would let the manifest be promoted over the
			// bundle key, which is a version overwriting its own bytes.
			name: "a manifest object that is neither plugin.json nor SKILL.md",
			ref:  ref,
			parts: blob.VersionParts{
				Bundle:             strings.NewReader("bytes"),
				Manifest:           []byte("{}"),
				ManifestObjectName: blob.BundleObject,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := committer.Commit(ctx, tc.ref, tc.parts)
			require.Error(t, err)

			objects, listErr := bucket.Reader().List(ctx, "")
			require.NoError(t, listErr)
			require.Empty(t, objects, "a rejected commit must not have written anything")
		})
	}
}

func TestAStandaloneSkillCommitsItsManifestAsSkillMD(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)

	p := parts([]byte("the bundle bytes"))
	p.ManifestObjectName = blob.SkillManifestObject

	_, err := blob.NewCommitter(bucket.Reader(), bucket.Writer()).Commit(ctx, ref, p)
	require.NoError(t, err)

	entry, err := blob.NewCatalog(bucket.Reader()).Entry(ctx, ref)
	require.NoError(t, err)
	require.Equal(t, "skills/example/terraform-module-review/2.4.1/SKILL.md", entry.Manifest)
}

func TestSetLatestMovesThePointerOnlyToACommittedVersion(t *testing.T) {
	ctx := context.Background()
	bucket := newBucket(t)

	committer := blob.NewCommitter(bucket.Reader(), bucket.Writer())
	catalog := blob.NewCatalog(bucket.Reader())

	older := blob.VersionRef{Publisher: ref.Publisher, Name: ref.Name, Semver: "2.4.0"}
	_, err := committer.Commit(ctx, older, parts([]byte("older")))
	require.NoError(t, err)
	_, err = committer.Commit(ctx, ref, parts([]byte("newer")))
	require.NoError(t, err)

	latest, err := catalog.Latest(ctx, ref.Package())
	require.NoError(t, err)
	require.Equal(t, "2.4.1", latest.Semver)

	require.NoError(t, committer.SetLatest(ctx, ref.Package(), "2.4.0"))
	latest, err = catalog.Latest(ctx, ref.Package())
	require.NoError(t, err)
	require.Equal(t, "2.4.0", latest.Semver)

	err = committer.SetLatest(ctx, ref.Package(), "9.9.9")
	require.ErrorIs(t, err, blob.ErrNotFound)
}

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

type countingReader struct {
	data     []byte
	off      int
	consumed int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	r.consumed += n
	return n, nil
}

type cancellingReader struct {
	data        []byte
	off         int
	cancelAfter int
	cancel      context.CancelFunc
}

func (r *cancellingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:min(r.off+1, len(r.data))])
	r.off += n
	if r.off >= r.cancelAfter {
		r.cancel()
	}
	return n, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

type step struct {
	op      string
	key     string
	visible bool
}

// visibilityWatcher checks, after every single object write, whether the version
// has become readable. That is the only way to test an ordering guarantee: the
// end state of a correct and an incorrect implementation is identical.
type visibilityWatcher struct {
	t       *testing.T
	inner   blob.Writer
	catalog *blob.Catalog
	ref     blob.VersionRef

	steps     []step
	readBytes []byte
	readErr   error
	read      bool
}

func (w *visibilityWatcher) record(op, key string) {
	visible := mustVisible(w.t, context.Background(), w.catalog, w.ref)
	w.steps = append(w.steps, step{op: op, key: key, visible: visible})

	if visible && !w.read {
		w.read = true
		rc, err := w.catalog.OpenBundle(context.Background(), w.ref)
		if err != nil {
			w.readErr = err
			return
		}
		defer func() { _ = rc.Close() }()
		w.readBytes, w.readErr = io.ReadAll(rc)
	}
}

func (w *visibilityWatcher) Write(ctx context.Context, key string, src io.Reader) (blob.Object, error) {
	obj, err := w.inner.Write(ctx, key, src)
	if err == nil {
		w.record("write", key)
	}
	return obj, err
}

func (w *visibilityWatcher) Copy(ctx context.Context, dstKey, srcKey string) error {
	err := w.inner.Copy(ctx, dstKey, srcKey)
	if err == nil {
		w.record("copy", dstKey)
	}
	return err
}

func (w *visibilityWatcher) Delete(ctx context.Context, key string) error {
	err := w.inner.Delete(ctx, key)
	if err == nil {
		w.record("delete", key)
	}
	return err
}

type failingWriter struct {
	inner  blob.Writer
	failOn func(op, key string) bool
}

func (w *failingWriter) Write(ctx context.Context, key string, src io.Reader) (blob.Object, error) {
	if w.failOn("write", key) {
		return blob.Object{}, fmt.Errorf("injected failure writing %s", key)
	}
	return w.inner.Write(ctx, key, src)
}

func (w *failingWriter) Copy(ctx context.Context, dstKey, srcKey string) error {
	if w.failOn("copy", dstKey) {
		return fmt.Errorf("injected failure copying to %s", dstKey)
	}
	return w.inner.Copy(ctx, dstKey, srcKey)
}

func (w *failingWriter) Delete(ctx context.Context, key string) error {
	if w.failOn("delete", key) {
		return fmt.Errorf("injected failure deleting %s", key)
	}
	return w.inner.Delete(ctx, key)
}

type countingWriter struct {
	inner   blob.Writer
	writes  int
	copies  int
	deletes int
}

func (w *countingWriter) Write(ctx context.Context, key string, src io.Reader) (blob.Object, error) {
	w.writes++
	return w.inner.Write(ctx, key, src)
}

func (w *countingWriter) Copy(ctx context.Context, dstKey, srcKey string) error {
	w.copies++
	return w.inner.Copy(ctx, dstKey, srcKey)
}

func (w *countingWriter) Delete(ctx context.Context, key string) error {
	w.deletes++
	return w.inner.Delete(ctx, key)
}

func mustVisible(t *testing.T, ctx context.Context, c *blob.Catalog, r blob.VersionRef) bool {
	t.Helper()

	visible, err := c.Visible(ctx, r)
	require.NoError(t, err)

	return visible
}

func keysOf(attrs []blob.Attributes) []string {
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a.Key)
	}
	return out
}
