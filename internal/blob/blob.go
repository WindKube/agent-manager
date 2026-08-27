// Package blob is this project's object store.
//
// gocloud.dev/blob is the data path — s3blob against MinIO/S3, memblob in unit
// tests, fileblob for a container-free dev mode — and this package owns the three
// things gocloud does not model: the key layout from the design, sha256 digesting
// on write, and commit-last visibility (FR-008).
//
// Reader and Writer are separate interfaces AND separate implementations. That is
// the Go half of constitution principle II: the scanner is handed a Reader whose
// dynamic type has no write method, so there is no Writer to type-assert back to.
// One interface with both halves, or a Reader backed by a type that also satisfies
// Writer, hands that assertion straight back.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	gcblob "gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	// The three drivers this project supports, registered for blob.OpenBucket by
	// their URL scheme: s3:// in compose and production, mem:// in unit tests,
	// file:// for a container-free dev mode (R13).
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

// ErrNotFound is returned for a key the bucket does not hold. Callers match on
// this rather than on a driver's error type, which is the whole reason the
// gocloud error codes are translated here.
var ErrNotFound = errors.New("object not found")

// Attributes is the subset of an object's metadata this project reads.
type Attributes struct {
	Key     string
	Size    int64
	ModTime time.Time
}

// Reader is read-only access to the object store. It has no write method, by
// design: see the package comment.
type Reader interface {
	NewReader(ctx context.Context, key string) (io.ReadCloser, error)
	ReadAll(ctx context.Context, key string) ([]byte, error)
	Exists(ctx context.Context, key string) (bool, error)
	Attributes(ctx context.Context, key string) (Attributes, error)
	List(ctx context.Context, prefix string) ([]Attributes, error)
}

// Writer is write-only access to the object store. It has no read method, so
// nothing on the write path can be tempted to verify a digest by re-reading the
// object it just wrote.
type Writer interface {
	Write(ctx context.Context, key string, src io.Reader) (Object, error)
	Copy(ctx context.Context, dstKey, srcKey string) error
	Delete(ctx context.Context, key string) error
}

// Object is what one write produced.
//
// Digest is computed while the bytes stream past (FR-007). Hashing by re-reading
// the object afterwards would double the transfer and — worse — would hash
// whatever the bucket holds at that moment rather than what this call wrote.
type Object struct {
	Key    string
	Size   int64
	Digest [sha256.Size]byte
}

// Hex is the digest as the 64-character lowercase string the catalog stores.
func (o Object) Hex() string { return hex.EncodeToString(o.Digest[:]) }

// Bucket is the bootstrap's handle on one bucket. A role never holds this: the
// bootstrap opens it and hands out the halves the role declared (see
// internal/worker.Build).
type Bucket struct {
	bucket *gcblob.Bucket
}

// Open dials the bucket named by a gocloud URL: s3://…, mem://, file:///….
func Open(ctx context.Context, bucketURL string) (*Bucket, error) {
	if strings.TrimSpace(bucketURL) == "" {
		return nil, errors.New("blob url is empty")
	}
	b, err := gcblob.OpenBucket(ctx, bucketURL)
	if err != nil {
		return nil, fmt.Errorf("open bucket: %w", err)
	}
	return &Bucket{bucket: b}, nil
}

// Reader returns the read half. The returned value's dynamic type implements
// Reader and nothing else.
func (b *Bucket) Reader() Reader { return reader{bucket: b.bucket} }

// Writer returns the write half. Only the fetcher role is ever handed one
// (constitution principle II).
func (b *Bucket) Writer() Writer { return writer{bucket: b.bucket} }

// As reaches the driver's own client — R13's escape hatch, used by the Storage
// screen's bucket-settings report (versioning, object lock, SSE-KMS, retention)
// so no second S3 client is constructed.
//
// It lives on *Bucket and not on Reader deliberately: a raw *s3.Client can write,
// so exposing it through the read interface would hand every read-only role a way
// around the credential split this package exists to enforce.
func (b *Bucket) As(i any) bool { return b.bucket.As(i) }

func (b *Bucket) Close() error {
	if err := b.bucket.Close(); err != nil {
		return fmt.Errorf("close bucket: %w", err)
	}
	return nil
}

type reader struct {
	bucket *gcblob.Bucket
}

func (r reader) NewReader(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := r.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, translate(key, err)
	}
	return rc, nil
}

func (r reader) ReadAll(ctx context.Context, key string) ([]byte, error) {
	b, err := r.bucket.ReadAll(ctx, key)
	if err != nil {
		return nil, translate(key, err)
	}
	return b, nil
}

func (r reader) Exists(ctx context.Context, key string) (bool, error) {
	ok, err := r.bucket.Exists(ctx, key)
	if err != nil {
		return false, translate(key, err)
	}
	return ok, nil
}

func (r reader) Attributes(ctx context.Context, key string) (Attributes, error) {
	attrs, err := r.bucket.Attributes(ctx, key)
	if err != nil {
		return Attributes{}, translate(key, err)
	}
	return Attributes{Key: key, Size: attrs.Size, ModTime: attrs.ModTime}, nil
}

func (r reader) List(ctx context.Context, prefix string) ([]Attributes, error) {
	it := r.bucket.List(&gcblob.ListOptions{Prefix: prefix})

	var out []Attributes
	for {
		obj, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		if obj.IsDir {
			continue
		}
		out = append(out, Attributes{Key: obj.Key, Size: obj.Size, ModTime: obj.ModTime})
	}
}

type writer struct {
	bucket *gcblob.Bucket
}

// Write streams src into key and digests it on the way past.
//
// The per-call context is cancellable so a failed copy can abort the write rather
// than commit a truncated object: gocloud's contract is that cancelling the
// context passed to NewWriter aborts, and Close must be called either way.
func (w writer) Write(ctx context.Context, key string, src io.Reader) (Object, error) {
	if src == nil {
		return Object{}, fmt.Errorf("write %s: source reader is nil", key)
	}

	wctx, abort := context.WithCancel(ctx)
	defer abort()

	wc, err := w.bucket.NewWriter(wctx, key, nil)
	if err != nil {
		return Object{}, fmt.Errorf("open writer for %s: %w", key, err)
	}

	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(wc, hash), src)
	if copyErr != nil {
		abort()
		_ = wc.Close()
		return Object{}, fmt.Errorf("write %s: %w", key, copyErr)
	}
	if err := wc.Close(); err != nil {
		return Object{}, fmt.Errorf("commit %s: %w", key, err)
	}

	obj := Object{Key: key, Size: size}
	copy(obj.Digest[:], hash.Sum(nil))
	return obj, nil
}

func (w writer) Copy(ctx context.Context, dstKey, srcKey string) error {
	if err := w.bucket.Copy(ctx, dstKey, srcKey, nil); err != nil {
		return fmt.Errorf("copy %s to %s: %w", srcKey, dstKey, translate(srcKey, err))
	}
	return nil
}

func (w writer) Delete(ctx context.Context, key string) error {
	if err := w.bucket.Delete(ctx, key); err != nil {
		return translate(key, err)
	}
	return nil
}

func translate(key string, err error) error {
	if gcerrors.Code(err) == gcerrors.NotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return fmt.Errorf("object %s: %w", key, err)
}
