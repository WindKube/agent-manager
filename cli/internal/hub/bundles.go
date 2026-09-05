package hub

// This file is the only place bundle bytes are fetched: a miss GETs and
// streams to a temp file while hashing (never buffered in full), and
// cache.PutReader renames temp->sha256-<hex> only on a matching hash, so no
// unverified byte reaches the install tree. Redirect token safety is NOT
// reimplemented here: use h.Raw()/h.HTTPClient(), whose 307-following
// preserves bearerTransport's protections (hub.go); a fresh http.Client
// would reinstate net/http's Authorization-preserving redirect default.

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

// BundleRef is one lockfile entry reduced to what addressing its bundle
// needs.
//
// THE TRAP: the bundle path is GET /v1/bundles/{publisher}/{name}/{version},
// but `{publisher}` actually holds the NAMESPACE (the param's NAME is wrong;
// its description is right). A publisher slug is itself `namespace/name`, so
// it can't fit in one path segment — hence this type stores Namespace, never
// a publisher, and the lockfile schema's `"publisher/name"` label on the
// entry id is wrong the same way: the id is `namespace/name`.
type BundleRef struct {
	ID        string       // the lockfile entry id verbatim, `namespace/name`
	Namespace string       // ID's first segment; the value the `publisher` param takes
	Name      string       // ID's second segment
	Version   string       // exact, verbatim from the hub; never parsed or substituted
	Digest    cache.Digest // both the cache key and what downloaded bytes are checked against
}

// ParseBundleRef refuses an id that is not exactly two non-empty segments;
// it is never joined, truncated or padded, since any repair would address a
// different package than the lockfile named.
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

// validBundleSegment hand-derives the hub's object-key charset
// (`^[A-Za-z0-9][A-Za-z0-9._+-]*$`; restated, not imported: hub is a
// separate module). NOT internal/layout's stricter filesystem validation.
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

// Offline returns a NEW Downloader (not a flag flip): --offline is per-run,
// and a mutable shared flag would leak one caller's mode into another's.
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

// Fetch's bytes are already hashed by internal/cache. A caller may stage
// them without further checking, but must not skip the extractor's own
// caps — a separate defence for a bundle that is exactly what the hub
// promised and still hostile.
func (d *Downloader) Fetch(ctx context.Context, ref BundleRef) (*Bundle, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}

	b, err := d.cache.Get(ref.Digest)
	switch {
	case err == nil:
		return &Bundle{Ref: ref, Bytes: b, FromCache: true}, nil
	case !errors.Is(err, cache.ErrMiss):
		// Not a miss: the cache dir itself is unusable, and downloading would
		// only fail again at the write.
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
		// Classified, not discarded: carries the hub's own reason (e.g. a
		// scan-gate 403 the sync verb turns into a reported skip).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		if e := ClassifyStatus(OpGetBundle, resp, body, http.StatusOK); e != nil {
			return attributeOffload(e, resp)
		}
		return &OpError{
			Class: ClassProtocol, Op: OpGetBundle, URL: responseURL(resp, target),
			Status: resp.StatusCode, Detail: "status was not classified",
		}
	}

	// Checked before any body byte is read: disagreeing fails fast.
	// Missing/unreadable is tolerated — the body's own hash is the
	// authority — this is only an early exit, never a skipped check.
	if raw := strings.TrimSpace(resp.Header.Get(digestHeader)); raw != "" {
		if got, perr := cache.ParseHeaderDigest(raw); perr == nil && got != ref.Digest {
			return &DigestMismatchError{Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceHeader}
		}
	}

	// Hashed twice: this reader just names the digest that arrived,
	// cache.PutReader's hash is what actually decides whether it's kept.
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

	// PutReader refused: a complete read hashing to the wrong digest is a
	// mismatch (nothing written); anything else is a cache-write failure.
	if got, derr := hr.digest(); derr == nil && hr.complete && got != ref.Digest {
		return &DigestMismatchError{
			Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceBody, Bytes: hr.n,
		}
	}
	return fmt.Errorf("bundle %s could not be cached in %s: %w", ref, d.cache.Root(), putErr)
}

// attributeOffload re-classifies a status from the 307's object-store
// target: its 403/404 must not read as ClassForbidden/ClassNotFound, which
// the sync verb answers by skipping the entry and exiting 0. Origin
// comparison doesn't work (the offload URL may share host/subdomain/port),
// so this checks whether a redirect happened at all (Request.Response set).
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

// hashingReader hashes what it passes through so a mismatch can name the
// digest that arrived (cache.PutReader enforces but only reports as text).
// `complete` is load-bearing: without it a dropped connection would produce
// a prefix hash reported as a tampered bundle.
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

// digest is the sha256 of everything read so far. It round-trips through the
// lockfile encoding on purpose: cache.Digest exposes no raw-bytes
// constructor, so a value only ever comes from Compute or a parser.
func (r *hashingReader) digest() (cache.Digest, error) {
	return cache.ParseLockfileDigest("sha256:" + hex.EncodeToString(r.h.Sum(nil)))
}
