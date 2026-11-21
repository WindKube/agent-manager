package hub

// The only place bundle bytes are fetched; cache.PutReader keeps only bytes matching the digest. Always
// fetch via h.Raw()/h.HTTPClient(), since a fresh http.Client's redirect default leaks Authorization.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/cache"
)

const digestHeader = "Digest" // RFC 3230's instance-digest header

var (
	ErrBundleRef      = errors.New("unusable bundle reference") // a refusal, not a skip
	ErrDigestMismatch = errors.New("bundle digest does not match the digest the hub locked")

	ErrOffline = errors.New("bundle is not in the cache and fetching is disabled")
)

// BundleRef is one lockfile entry reduced to what addressing its bundle needs. The path's
// `{publisher}` segment actually holds the namespace, not a publisher slug.
type BundleRef struct {
	ID        string       // the lockfile entry id verbatim, `namespace/name`
	Namespace string       // ID's first segment; the value the `publisher` param takes
	Name      string       // ID's second segment
	Version   string       // exact, verbatim from the hub; never parsed or substituted
	Digest    cache.Digest // both the cache key and what downloaded bytes are checked against
}

// ParseBundleRef refuses an id that is not exactly two non-empty segments; any repair would address
// a different package.
func ParseBundleRef(e LockfileEntry) (BundleRef, error) {
	ns, name, ok := strings.Cut(e.Id, "/")
	switch {
	case !ok:
		return BundleRef{}, fmt.Errorf("%w: entry id %q has one segment, want exactly two (namespace/name); a "+
			"publisher slug is not an id", ErrBundleRef, e.Id)
	case ns == "" || name == "":
		return BundleRef{}, fmt.Errorf("%w: entry id %q has an empty segment, want exactly two non-empty "+
			"segments (namespace/name)", ErrBundleRef, e.Id)
	case strings.Contains(name, "/"):
		return BundleRef{}, fmt.Errorf("%w: entry id %q has more than two segments, want exactly two "+
			"(namespace/name); the first segment is the namespace, not the publisher slug", ErrBundleRef, e.Id)
	}
	digest, err := cache.ParseLockfileDigest(e.Digest)
	if err != nil {
		return BundleRef{}, fmt.Errorf("%w: entry %q: %w", ErrBundleRef, e.Id, err)
	}
	ref := BundleRef{ID: e.Id, Namespace: ns, Name: name, Version: e.Version, Digest: digest}
	if err := ref.validate(); err != nil {
		return BundleRef{}, err
	}
	return ref, nil
}

// Path is for messages/errors only; the actual request goes through the generated client.
func (r BundleRef) Path() string {
	return "/v1/bundles/" + r.Namespace + "/" + r.Name + "/" + r.Version
}

func (r BundleRef) String() string { return r.ID + "@" + r.Version }

// validate also covers a hand-built BundleRef: NewGetBundleRequest does not
// escape path parameters, so `/` or `..` would silently address elsewhere.
func (r BundleRef) validate() error {
	if r.ID == "" || r.ID != r.Namespace+"/"+r.Name {
		return fmt.Errorf("%w: id %q is not namespace %q plus name %q", ErrBundleRef, r.ID, r.Namespace, r.Name)
	}
	if err := validBundleSegment("namespace", r.ID, r.Namespace); err != nil {
		return err
	}
	if err := validBundleSegment("name", r.ID, r.Name); err != nil {
		return err
	}
	if err := validBundleSegment("version", r.ID, r.Version); err != nil {
		return err
	}
	if r.Digest.IsZero() { // zero is never a real hash, only an uninitialised field
		return fmt.Errorf("%w: entry %q carries no digest", ErrBundleRef, r.ID)
	}
	return nil
}

// validBundleSegment restates the hub's object-key charset `^[A-Za-z0-9][A-Za-z0-9._+-]*$`.
func validBundleSegment(what, id, seg string) error {
	if seg == "" {
		return fmt.Errorf("%w: entry %q has an empty %s", ErrBundleRef, id, what)
	}
	for i, r := range seg {
		if i == 0 && !isBundleAlnum(r) { // rules out "", ".", ".." and a leading separator
			return fmt.Errorf("%w: %s %q of entry %q must start with a letter or digit",
				ErrBundleRef, what, seg, id)
		}
		if !isBundleAlnum(r) && r != '.' && r != '_' && r != '+' && r != '-' {
			return fmt.Errorf("%w: %s %q of entry %q contains %q, which is not a valid object-key "+
				"character (allowed: letters, digits, and . _ + -)", ErrBundleRef, what, seg, id, r)
		}
	}
	if strings.Contains(seg, "..") {
		return fmt.Errorf("%w: %s %q of entry %q contains a parent-directory reference",
			ErrBundleRef, what, seg, id)
	}
	return nil
}

func isBundleAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// DigestSource says which of the two digests disagreed with the lockfile.
type DigestSource string

const (
	DigestSourceHeader DigestSource = "Digest response header"
	DigestSourceBody   DigestSource = "response body"
)

// DigestMismatchError names both digests. No Class: the HTTP exchange itself didn't fail.
type DigestMismatchError struct {
	Ref    BundleRef
	Want   cache.Digest
	Got    cache.Digest
	Source DigestSource
	Bytes  int64 // read before the verdict; zero for the header source
}

func (e *DigestMismatchError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bundle %s: the %s hashes to %s but the lockfile locked %s",
		e.Ref, e.Source, e.Got, e.Want)
	if e.Bytes > 0 {
		fmt.Fprintf(&b, " (%d bytes)", e.Bytes)
	}
	b.WriteString("; nothing was written")
	return b.String()
}

func (e *DigestMismatchError) Is(target error) bool { return errors.Is(target, ErrDigestMismatch) }

// BundleCache is the narrow view of internal/cache this file needs. No
// method returns a path: that would be a TOCTOU making the re-hash decorative.
type BundleCache interface {
	Get(cache.Digest) ([]byte, error)        // re-hashes first; wraps cache.ErrMiss on failure
	PutReader(cache.Digest, io.Reader) error // refuses bytes that don't hash to the digest
	Root() string                            // for messages only
}

// Downloader holds no per-download state, so one instance serves a whole sync from several goroutines.
type Downloader struct {
	hub     *Hub
	cache   BundleCache
	offline bool
}

// NewDownloader pairs a hub with a bundle cache.
func NewDownloader(h *Hub, c BundleCache) (*Downloader, error) {
	if h == nil {
		return nil, errors.New("bundle downloader: no hub given")
	}
	if c == nil {
		return nil, errors.New("bundle downloader: no bundle cache given")
	}
	return &Downloader{hub: h, cache: c}, nil
}

// Offline returns a new Downloader so one caller's mode cannot leak into another's.
func (d *Downloader) Offline() *Downloader {
	c := *d
	c.offline = true
	return &c
}

func (d *Downloader) IsOffline() bool { return d.offline }

type Bundle struct {
	Ref       BundleRef
	Bytes     []byte
	FromCache bool // no request was made
}

// Fetch's bytes are already verified, but a caller must not skip the extractor's own caps: a bundle
// can be exactly what the hub promised and still hostile.
func (d *Downloader) Fetch(ctx context.Context, ref BundleRef) (*Bundle, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}

	b, err := d.cache.Get(ref.Digest)
	switch {
	case err == nil:
		return &Bundle{Ref: ref, Bytes: b, FromCache: true}, nil
	case !errors.Is(err, cache.ErrMiss):
		// The cache dir itself is unusable; downloading would only fail again at the write.
		return nil, fmt.Errorf("reading bundle %s from the cache at %s: %w", ref, d.cache.Root(), err)
	}
	missErr := err

	if d.offline {
		// missErr stays in the chain so a caller can tell an absent entry from
		// a discarded corrupt one (cache.ErrCorrupt).
		return nil, fmt.Errorf("bundle %s (%s) is not in the cache at %s: %w: %w",
			ref, ref.Digest, d.cache.Root(), ErrOffline, missErr)
	}

	if derr := d.download(ctx, ref); derr != nil {
		return nil, derr
	}

	// Read back through Get on purpose; see the file comment.
	b, err = d.cache.Get(ref.Digest)
	if err != nil {
		return nil, fmt.Errorf("bundle %s was fetched and cached but did not read back from %s: %w",
			ref, d.cache.Root(), err)
	}
	return &Bundle{Ref: ref, Bytes: b}, nil
}

// download returns nil only when ref.Digest is now addressable in the cache.
func (d *Downloader) download(ctx context.Context, ref BundleRef) error {
	target := d.hub.opURL(ref.Path())

	resp, err := d.hub.Raw().GetBundle(ctx, ref.Namespace, ref.Name, ref.Version) // Raw(): 307 must follow Hub's redirect protection
	if err != nil {
		return ClassifyTransport(OpGetBundle, target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Classified, so a scan-gate 403 can become a reported skip.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		if e := ClassifyStatus(OpGetBundle, resp, body, http.StatusOK); e != nil {
			return attributeOffload(e, resp)
		}
		return &OpError{
			Class: ClassProtocol, Op: OpGetBundle, URL: responseURL(resp, target),
			Status: resp.StatusCode, Detail: "status was not classified",
		}
	}

	// An early exit only; a missing header is tolerated since the body's own hash is the authority.
	if raw := strings.TrimSpace(resp.Header.Get(digestHeader)); raw != "" {
		if got, perr := cache.ParseHeaderDigest(raw); perr == nil && got != ref.Digest {
			return &DigestMismatchError{Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceHeader}
		}
	}

	// This reader only names the digest that arrived; cache.PutReader decides whether it's kept.
	hr := &hashingReader{r: resp.Body, h: sha256.New()}
	putErr := d.cache.PutReader(ref.Digest, hr)
	switch {
	case hr.readErr != nil:
		// Connection failed mid-body: not a digest mismatch.
		return fmt.Errorf("bundle %s: %w", ref, ClassifyTransport(OpGetBundle, target, hr.readErr))
	case putErr == nil:
		return nil
	case errors.Is(putErr, cache.ErrTooLarge):
		return fmt.Errorf("bundle %s: the hub served more than the %d-byte cap this client accepts: %w",
			ref, cache.MaxBundleBytes, putErr)
	}

	if got, derr := hr.digest(); derr == nil && hr.complete && got != ref.Digest {
		return &DigestMismatchError{
			Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceBody, Bytes: hr.n,
		}
	}
	return fmt.Errorf("bundle %s could not be cached in %s: %w", ref, d.cache.Root(), putErr)
}

// attributeOffload re-classifies an object-store 403/404 as ClassOffload, since the sync verb skips on
// ClassForbidden/ClassNotFound. It checks whether a redirect happened, as the origin may match.
func attributeOffload(err error, resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Request.Response == nil {
		return err
	}
	var e *OpError
	if !errors.As(err, &e) {
		return err
	}
	out := *e
	out.Class = ClassOffload
	return &out
}

// responseURL falls back to target; SafeURL not u.String(), since a 307's
// pre-signed URL carries its signature in the query string.
func responseURL(resp *http.Response, target string) string {
	if resp != nil && resp.Request != nil {
		return SafeURL(resp.Request.URL)
	}
	return target
}

// hashingReader lets a mismatch name the digest that arrived. Without `complete`, a dropped
// connection would be reported as a tampered bundle.
type hashingReader struct {
	r io.Reader
	h hash.Hash

	n        int64
	complete bool
	readErr  error
}

func (r *hashingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.n += int64(n)
		_, _ = r.h.Write(p[:n]) // hash.Hash never errors, by its documented contract
	}
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		r.complete = true
	default:
		r.readErr = err
	}
	return n, err
}

// digest round-trips through the lockfile encoding since cache.Digest has no raw-bytes constructor.
func (r *hashingReader) digest() (cache.Digest, error) {
	return cache.ParseLockfileDigest("sha256:" + hex.EncodeToString(r.h.Sum(nil)))
}
