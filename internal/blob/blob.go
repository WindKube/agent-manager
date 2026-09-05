// Package blob is this project's object store. gocloud.dev/blob is the data
// path — s3blob against MinIO/S3, memblob in unit tests, fileblob for a
// container-free dev mode — and this package owns what gocloud does not
// model: the key layout, sha256 digesting on write, and commit-last
// visibility.
//
// Reader and Writer are separate interfaces and separate implementations:
// the scanner is handed a Reader whose dynamic type has no write method, so
// there is no Writer to type-assert back to. One interface with both
// halves, or a Reader backed by a type that also satisfies Writer, hands
// that assertion straight back.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	gcblob "gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	// The three drivers this project supports, registered for blob.OpenBucket
	// by their URL scheme: s3:// in compose and production, mem:// in unit
	// tests, file:// for a container-free dev mode.
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

// Object is what one write produced. Digest is computed while the bytes
// stream past: hashing by re-reading the object afterwards would double the
// transfer and — worse — would hash whatever the bucket holds at that
// moment rather than what this call wrote.
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
	// name and region come off the URL Open was given: the host is the bucket
	// name and `region` is the one query parameter compose.yaml's s3:// URL
	// carries. Both are "" for mem:// and file://, which the Storage screen
	// renders as unknown rather than guessing one.
	name, region string
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
	name, region := "", ""
	if parsed, parseErr := url.Parse(bucketURL); parseErr == nil {
		name = parsed.Host
		region = parsed.Query().Get("region")
	}
	return &Bucket{bucket: b, name: name, region: region}, nil
}

// Reader returns the read half. The returned value's dynamic type implements
// Reader and nothing else.
func (b *Bucket) Reader() Reader { return reader{bucket: b.bucket} }

// Writer returns the write half. Only the fetcher role is ever handed one
// (constitution principle II).
func (b *Bucket) Writer() Writer { return writer{bucket: b.bucket} }

// As reaches the driver's own client — an escape hatch used by the Storage
// screen's bucket-settings report so no second S3 client is constructed. It
// lives on *Bucket, not on Reader: a raw *s3.Client can write, so exposing
// it through the read interface would hand every read-only role a way
// around the credential split this package exists to enforce.
func (b *Bucket) As(i any) bool { return b.bucket.As(i) }

// Inspector is read access plus the raw-client escape hatch, Name and Region —
// handed only to the Storage screen's query, the one caller that needs to
// describe the bucket itself rather than merely read its objects. It excludes
// Writer: holding this cannot reach a write, whatever As's driver client can do.
type Inspector interface {
	Reader
	As(i any) bool
	Name() string
	Region() string
	ListLimited(ctx context.Context, prefix string, limit int) ([]Attributes, bool, error)
}

// Inspector returns the read-and-describe half.
func (b *Bucket) Inspector() Inspector {
	return inspector{reader: reader{bucket: b.bucket}, bucket: b, name: b.name, region: b.region}
}

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

type inspector struct {
	reader
	bucket       *Bucket
	name, region string
}

func (i inspector) As(v any) bool  { return i.bucket.As(v) }
func (i inspector) Name() string   { return i.name }
func (i inspector) Region() string { return i.region }

// ListLimited lists at most limit objects under prefix and reports whether the
// bucket held more. It exists beside List for the one caller with no bound on
// the bucket it is describing: a production bucket can hold far more objects
// than a report should ever hold in memory at once.
func (r reader) ListLimited(ctx context.Context, prefix string, limit int) ([]Attributes, bool, error) {
	it := r.bucket.List(&gcblob.ListOptions{Prefix: prefix})

	var out []Attributes
	for {
		if len(out) >= limit {
			return out, true, nil
		}
		obj, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("list %s: %w", prefix, err)
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

// Write streams src into key and digests it on the way past. The per-call
// context is cancellable so a failed copy can abort the write rather than
// commit a truncated object: gocloud's contract is that cancelling the
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
