package hub

// This file is the ONLY place bundle bytes are fetched, and the order of
// operations in Fetch is what makes every guarantee below hold. Read the
// order before changing anything here.
//
//	cache.Get  ->  hit: return the bytes the cache re-hashed. No request.
//	           ->  miss and --offline: refuse, naming the digest.
//	           ->  miss: GET the bundle, stream it into a temp file INSIDE the
//	               cache directory while hashing it, and let cache.PutReader
//	               rename that temp to `sha256-<hex>` only if the hash it
//	               computed equals the digest the lockfile locked. Then read
//	               the entry back through cache.Get.
//
// WHERE VERIFICATION HAPPENS RELATIVE TO THE WRITE. The bytes are written to
// a temp file whose name no
// reader looks up, in a directory that is not part of any agent's tree, and
// the digest is computed on the bytes as they are written, not by re-reading
// the file afterwards. The temp becomes an addressable cache entry only after
// the computed digest matches. So no byte of an unverified bundle ever
// reaches the installation tree, and none ever reaches a path the installer
// could find by accident either.
//
// WHAT IS LEFT ON DISK IF THE BODY IS TRUNCATED MID-STREAM: nothing. The
// partial bytes are in the temp file, and cache.PutReader's own deferred
// cleanup removes it on every path that does not reach the rename. If that
// removal itself fails, the leftover is a
// `.amctl-tmp-` file that Cache.CollectTemps sweeps on the next download; it
// is never readable as an entry, because entry lookup is by the
// `sha256-<hex>` name only.
//
// WHY THE BYTES ARE READ BACK THROUGH cache.Get RATHER THAN RETURNED FROM THE
// STREAM. It costs one re-read and one re-hash of at most 25 MiB, and it buys
// the property actually needed: the bytes handed to the installer are
// bytes that were hashed AFTER they were durable, by the same code path that
// serves them on every later run. A "we just wrote it, so it is fine" fast
// path would make the first run the one run that trusts memory instead of the
// disk, which is the run where a filesystem lie is least likely to be caught.
//
// STREAMING, AND WHAT IS NEVER BUFFERED. The download path holds no more than
// one 32 KiB io.Copy buffer: the body goes to the temp file, never into a
// []byte. Exactly one full copy of the bundle exists in memory at a time, the
// one cache.Get returns for the installer to extract.
//
// TOKEN PROTECTION ON REDIRECT IS NOT IMPLEMENTED HERE, DELIBERATELY. The 307 to a pre-signed
// object-store URL is followed by Hub's own http.Client, whose two defences
// (bearerTransport and stripAuthorizationOnRedirect, both in hub.go) are what
// keep the bearer token off the second hop. Building a request with
// http.NewRequest and a fresh http.Client here — the obvious way to "follow
// the redirect ourselves" — reinstates net/http's default, which PRESERVES
// Authorization on a same-host, subdomain or port-only redirect. That is the
// commonest self-hosted layout there is. Use h.Raw() or h.HTTPClient(), never
// a client of your own.
//
// WHAT THIS FILE DOES NOT DO:
//
//   - It does not build a URL from the entry's objectKey. The contract's
//     endpoint takes namespace, name and version as path parameters; objectKey
//     is the hub's own storage layout, and addressing the store directly would
//     be a second addressing scheme that skips the gate the endpoint enforces.
//   - It does not extract, stage or write anything into an agent's tree. That
//     is internal/apply, which reads only the verified local bytes this
//     returns.
//   - It does not decide what a failure means for the sync. A 403 skips one
//     entry and the sync continues; a digest mismatch abandons that
//     entry AND makes the run exit non-zero. Both are per-entry and
//     they are not the same outcome, so the policy belongs to the sync verb
//     and this file only makes them distinguishable: ClassOf(err) ==
//     ClassForbidden for the first, errors.Is(err, ErrDigestMismatch) for the
//     second.

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

// digestHeader is RFC 3230's instance-digest header, the one getBundle's 200
// declares. See the Digest-header handling in download for why a missing or
// unreadable one is tolerated and a DISAGREEING one is not.
const digestHeader = "Digest"

var (
	// ErrBundleRef marks a lockfile entry that cannot be turned into a bundle
	// request at all. It is a refusal, not a skip: an id amctl cannot address
	// is a lockfile it does not understand.
	ErrBundleRef = errors.New("unusable bundle reference")

	// ErrDigestMismatch is what every digest-mismatch failure matches. The concrete
	// error is *DigestMismatchError, which names both digests.
	ErrDigestMismatch = errors.New("bundle digest does not match the digest the hub locked")

	// ErrOffline is the --offline refusal: the bundle is not in the cache and this
	// downloader is forbidden to fetch it. The message names the digest,
	// because that is what the user has to obtain.
	ErrOffline = errors.New("bundle is not in the cache and fetching is disabled")
)

// BundleRef is one lockfile entry reduced to what addressing its bundle needs.
//
// THE TRAP, and it has bitten every reader of the contract so far: the bundle
// path is GET /v1/bundles/{publisher}/{name}/{version} and `{publisher}` holds
// the NAMESPACE. The parameter's NAME is wrong and its DESCRIPTION ("the
// publishing namespace, as it appears in the catalog") is right. A publisher
// slug is itself two segments — `example/platform` — so it cannot fit in one
// path segment at all, and a URL built from one has three segments where the
// contract has two. The resulting 404 is indistinguishable from a missing
// package, which is why this type stores Namespace under that name and never
// stores a publisher: there is nothing here for a publisher slug to be
// mistaken for. The lockfile schema's `"description": "publisher/name"` on the
// entry id is wrong in the same way; the id is `namespace/name`.
//
// Two publishers may share one namespace, which is also why the
// distinct-directory requirement is about `namespace/name`: the publisher is
// not the thing that disambiguates, so keying anything off it passes every
// test a one-publisher-per-namespace fixture can write.
type BundleRef struct {
	// ID is the lockfile entry id verbatim, `namespace/name`.
	ID string
	// Namespace is ID's first segment. It is the value the path parameter
	// spelled `publisher` takes.
	Namespace string
	// Name is ID's second segment.
	Name string
	// Version is the exact version the hub resolved. It is carried verbatim and
	// never parsed or compared — the hub resolves, this client does not
	// substituted.
	Version string
	// Digest is the digest the lockfile locked, in the one canonical internal
	// form. It is both the cache key and the thing the downloaded bytes are
	// checked against, and those being the same value is what makes it
	// impossible to file bytes under a digest they do not match.
	Digest cache.Digest
}

// ParseBundleRef turns a lockfile entry into a BundleRef, refusing everything
// it cannot address.
//
// An id that is not exactly two non-empty segments is an ERROR and is never
// joined, truncated or padded (spec.md Edge Cases). Either repair would address
// a different package than the one the lockfile named, and the install would
// then be recorded under an id that does not exist.
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

// Path is the contract path this ref addresses. It is built for messages and
// for the transport-error target; the request itself goes through the generated
// client, which builds the same three segments.
func (r BundleRef) Path() string {
	return "/v1/bundles/" + r.Namespace + "/" + r.Name + "/" + r.Version
}

// String is `namespace/name@version`, the form a user has seen in the lockfile
// and the plan.
func (r BundleRef) String() string { return r.ID + "@" + r.Version }

// validate refuses a ref that could not safely become a URL path.
//
// It is called on a hand-built BundleRef too, not only on one from
// ParseBundleRef, because the generated NewGetBundleRequest does NOT escape its
// path parameters: it interpolates them into a format string and parses the
// result, so a segment containing `/` or `..` would silently address something
// else entirely.
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
	// The zero Digest is not the digest of anything — sha256 of the empty input
	// is e3b0c442… — so it can only come from an uninitialised field, and two
	// uninitialised digests compare EQUAL. That is the one way the check below
	// could pass by accident.
	if r.Digest.IsZero() {
		return fmt.Errorf("%w: entry %q carries no digest", ErrBundleRef, r.ID)
	}
	return nil
}

// validBundleSegment is the charset every path segment must satisfy.
//
// HAND-DERIVED from the hub's own object-key segment pattern,
// `^[A-Za-z0-9][A-Za-z0-9._+-]*$` in the hub module's internal/blob/keys.go,
// which every namespace, package name and version in the catalog must satisfy
// to have a bundle object at all. A segment outside it cannot name a stored
// object, so accepting more here would only widen what this file has to
// defend. The pattern is restated rather than imported because the hub is a
// separate module and importing it would put the server in this binary's
// dependency graph.
//
// This is NOT internal/layout's validation and must not be replaced by it.
// layout is stricter — it additionally refuses a name that cannot become a
// directory, e.g. one containing layout.DirSeparator — because it is deciding
// where bytes land. This function decides only whether a URL can be built, and
// making a download fail with a filesystem-shaped reason would misreport which
// half of the pipeline refused.
func validBundleSegment(what, id, seg string) error {
	if seg == "" {
		return fmt.Errorf("%w: entry %q has an empty %s", ErrBundleRef, id, what)
	}
	for i, r := range seg {
		// The leading-character rule is the hub's, and it alone rules out "",
		// ".", ".." and a leading separator.
		if i == 0 && !isBundleAlnum(r) {
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

// DigestSource says which of the two digests the hub sent disagreed with the
// lockfile. Both are hard failures; the distinction is for the message, because
// the remedies differ — a bad header is a hub or proxy bug, bad bytes are a
// corrupted object or a tampered one.
type DigestSource string

// The two sources.
const (
	// DigestSourceHeader is the RFC 3230 `Digest` response header, checked
	// before the body is streamed.
	DigestSourceHeader DigestSource = "Digest response header"
	// DigestSourceBody is the sha256 of the bytes actually served.
	DigestSourceBody DigestSource = "response body"
)

// DigestMismatchError means the bundle the hub served is not the bundle
// the lockfile locked. It names BOTH digests, which is the requirement — an
// error saying only "digest mismatch" leaves the reader unable to tell a
// corrupted object from a lockfile pointing at the wrong version.
//
// It carries no Class: nothing about the HTTP exchange failed, and classifying
// it as ClassProtocol would file a content failure under "that endpoint is not
// a hub".
type DigestMismatchError struct {
	Ref    BundleRef
	Want   cache.Digest
	Got    cache.Digest
	Source DigestSource
	// Bytes is how many bytes were read before the verdict, for the body
	// source. Zero for the header source, where nothing was read.
	Bytes int64
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

// Is makes errors.Is(err, ErrDigestMismatch) the test, so no caller has to
// learn this type to route the failure.
func (e *DigestMismatchError) Is(target error) bool { return errors.Is(target, ErrDigestMismatch) }

// BundleCache is the narrow view of internal/cache this file needs.
//
// It is an interface so that a test can substitute a store which fails on
// demand, and so that this package does not depend on *cache.Cache's
// construction. It deliberately exposes NO method that returns a path: Get
// returns the bytes it hashed, and verifying a file and then handing back its
// name is a TOCTOU that would make the re-hash decorative.
type BundleCache interface {
	// Get returns the bytes stored under the digest, having re-hashed them
	// first, or an error wrapping cache.ErrMiss.
	Get(cache.Digest) ([]byte, error)
	// PutReader streams a reader into the cache under the digest, refusing
	// bytes that do not hash to it.
	PutReader(cache.Digest, io.Reader) error
	// Root is the cache directory, for messages only.
	Root() string
}

// Downloader fetches verified bundle bytes for a hub and a cache.
//
// It holds no per-download state, so one Downloader serves a whole sync and is
// safe to use from several goroutines; the cache's own write path is what
// arbitrates two fetches of the same digest.
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

// Offline returns a Downloader that completes from the cache alone and refuses
// otherwise, naming the digest that is missing.
//
// It returns a NEW Downloader rather than setting a flag on this one: --offline
// is a property of a run, and a mutable flag on a shared value is how one
// caller's mode leaks into another's.
func (d *Downloader) Offline() *Downloader {
	c := *d
	c.offline = true
	return &c
}

// IsOffline reports whether this Downloader will dial.
func (d *Downloader) IsOffline() bool { return d.offline }

// Bundle is verified local bytes plus where they came from.
type Bundle struct {
	Ref   BundleRef
	Bytes []byte
	// FromCache says the bytes were already local and no request was made. It
	// is what an idempotent second run reports and what a test asserts
	// to prove the cache is actually consulted.
	FromCache bool
}

// Fetch returns the verified bytes for ref.
//
// The bytes it returns have been hashed by internal/cache and are the slice
// that was hashed, so nothing can change between the check and the extraction.
// A caller may write them into a staging tree without checking anything
// further — and must not skip the extractor's own caps, which are a separate
// defence against a bundle that is exactly what the hub promised and still
// hostile.
func (d *Downloader) Fetch(ctx context.Context, ref BundleRef) (*Bundle, error) {
	if err := ref.validate(); err != nil {
		return nil, err
	}

	b, err := d.cache.Get(ref.Digest)
	switch {
	case err == nil:
		return &Bundle{Ref: ref, Bytes: b, FromCache: true}, nil
	case !errors.Is(err, cache.ErrMiss):
		// Not a miss: the cache directory itself is unusable. Downloading would
		// only fail again at the write, and hiding a broken cache behind a
		// working sync is how it stays broken.
		return nil, fmt.Errorf("reading bundle %s from the cache at %s: %w", ref, d.cache.Root(), err)
	}
	missErr := err

	if d.offline {
		// The digest is named because that is what the user has to obtain, and
		// the cache root because that is where to put it. The underlying miss
		// is kept in the chain so a caller can tell an absent entry from a
		// discarded corrupt one (cache.ErrCorrupt).
		return nil, fmt.Errorf("bundle %s (%s) is not in the cache at %s: %w: %w",
			ref, ref.Digest, d.cache.Root(), ErrOffline, missErr)
	}

	if derr := d.download(ctx, ref); derr != nil {
		return nil, derr
	}

	// Read back through Get on purpose. See the file comment: no "we just wrote
	// it, so it is fine" fast path.
	b, err = d.cache.Get(ref.Digest)
	if err != nil {
		return nil, fmt.Errorf("bundle %s was fetched and cached but did not read back from %s: %w",
			ref, d.cache.Root(), err)
	}
	return &Bundle{Ref: ref, Bytes: b}, nil
}

// download performs one getBundle and streams the body into the cache.
//
// It returns nil only when an entry addressable as ref.Digest exists in the
// cache, which by cache.PutReader's contract means bytes that hashed to it.
func (d *Downloader) download(ctx context.Context, ref BundleRef) error {
	target := d.hub.opURL(ref.Path())

	// Namespace, name, version — in that order, into a parameter the contract
	// spells `publisher`. See BundleRef's comment.
	//
	// Raw() and not a hand-built request: the 307 must be followed by the
	// Hub's own client, which is where the redirect protection lives.
	resp, err := d.hub.Raw().GetBundle(ctx, ref.Namespace, ref.Name, ref.Version)
	if err != nil {
		return ClassifyTransport(OpGetBundle, target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// The problem+json body carries the hub's own reason — "version
		// rejected by the organisation's scan gate" for the 403 that the sync
		// verb turns into a reported skip — so it is read and classified rather
		// than discarded in favour of the bare status.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		if e := ClassifyStatus(OpGetBundle, resp, body, http.StatusOK); e != nil {
			return attributeOffload(e, resp)
		}
		// Unreachable — 200 is the only wanted status and this is not it — but
		// failing closed here is the difference between a bug and a silently
		// unverified install.
		return &OpError{
			Class: ClassProtocol, Op: OpGetBundle, URL: responseURL(resp, target),
			Status: resp.StatusCode, Detail: "status was not classified",
		}
	}

	// The Digest header, checked BEFORE a byte of the body is read.
	//
	// A DISAGREEING header is a hard failure: the hub has just said it is about
	// to serve bytes other than the ones the lockfile locked, and there is no
	// reason to spend 25 MiB confirming it. A MISSING or UNREADABLE header is
	// tolerated, which is deliberate and is not a hole: the body's own hash is
	// the authority, and the 307's pre-signed object store is not a hub — real
	// object stores send no RFC 3230 Digest at all, or send another algorithm
	// (`crc32c=…`), and refusing those would break the offload path the
	// contract explicitly offers. Verification is never skipped either way;
	// only this early exit is.
	if raw := strings.TrimSpace(resp.Header.Get(digestHeader)); raw != "" {
		if got, perr := cache.ParseHeaderDigest(raw); perr == nil && got != ref.Digest {
			return &DigestMismatchError{Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceHeader}
		}
	}

	// The body goes to a temp file inside the cache directory while being
	// hashed twice: once by this reader, whose only job is to be able to NAME
	// the digest that arrived (both digests belong in the message),
	// and once by cache.PutReader, whose hash is the one that actually decides
	// whether the temp becomes an entry. The second is the enforcement; the
	// first is the diagnosis, and it is computed on the same byte stream so the
	// two cannot disagree.
	hr := &hashingReader{r: resp.Body, h: sha256.New()}
	putErr := d.cache.PutReader(ref.Digest, hr)
	switch {
	case hr.readErr != nil:
		// The status line arrived and the body did not finish. That is the
		// connection failing rather than a bad bundle, so it must not be
		// reported as a digest mismatch — a truncated read hashes to something
		// that will never match, and blaming the bytes would send the user
		// hunting a tampered object instead of a dropped connection.
		return fmt.Errorf("bundle %s: %w", ref, ClassifyTransport(OpGetBundle, target, hr.readErr))
	case putErr == nil:
		return nil
	case errors.Is(putErr, cache.ErrTooLarge):
		return fmt.Errorf("bundle %s: the hub served more than the %d-byte cap this client accepts: %w",
			ref, cache.MaxBundleBytes, putErr)
	}

	// PutReader refused. If the body was read to completion and its hash is not
	// the locked digest, that is a digest mismatch and nothing was written; anything else
	// is a cache-write failure and is reported as itself.
	if got, derr := hr.digest(); derr == nil && hr.complete && got != ref.Digest {
		return &DigestMismatchError{
			Ref: ref, Want: ref.Digest, Got: got, Source: DigestSourceBody, Bytes: hr.n,
		}
	}
	return fmt.Errorf("bundle %s could not be cached in %s: %w", ref, d.cache.Root(), putErr)
}

// attributeOffload re-classifies a status that came from the 307's target
// rather than from the hub itself.
//
// getBundle may answer 307 to a pre-signed object-store URL, and the status the
// download ends on is then the STORE's. Class's whole table is written for the
// hub's own answers, and none of its readings survive the move: an object store
// answers 403 for an expired signature, for clock skew and for a proxy refusing
// on its behalf — S3, GCS and MinIO all do — and 404 for an object that has been
// garbage-collected. Passing those through as ClassForbidden and ClassNotFound
// tells the sync verb that the organisation's GATE refused this version, which
// the sync verb answers by skipping the entry and exiting 0. That is the
// "installs nothing and reports success" outcome this exists to prevent, over an
// infrastructure failure a retry would have fixed.
//
// COMPARING ORIGINS DOES NOT WORK, and it is the obvious thing to reach for.
// The contract's own offload is a redirect to a URL that may be on the hub's
// host, a subdomain of it, or another port — CLI-CONTRACT.md calls the same-host
// layout "the commonest self-hosted layout there is", and the fake's fixture is
// deliberately same-host because a cross-host redirect is the case net/http
// already handles. So an origin comparison would say "this is the hub" for
// exactly the deployments the check exists for.
//
// What IS reliable is whether a redirect was followed at all. net/http sets
// Request.Response on the request it generates from a redirect (the same field
// bearerTransport reads to identify the first hop), so a non-nil one means this
// answer is not the hub's. The frozen contract gives getBundle exactly one
// redirect and it is the object-store offload, so "a redirect happened" and
// "this came from the store" are the same statement here.
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

// responseURL is the sanitised URL a response came from, falling back to the
// requested target. SafeURL is mandatory here rather than u.String(): after a
// 307 this URL is a pre-signed object-store URL whose SIGNATURE IS IN THE
// QUERY STRING, and a message carrying it hands a working download credential
// to whatever reads the log.
func responseURL(resp *http.Response, target string) string {
	if resp != nil && resp.Request != nil {
		return SafeURL(resp.Request.URL)
	}
	return target
}

// hashingReader hashes what it passes through and remembers how the stream
// ended.
//
// It exists only so that a mismatch can name the digest that ARRIVED.
// cache.PutReader already refuses bytes that do not hash to their key — that
// is the enforcement — but it reports the refusal as text, and the caller needs the
// value. The `complete` flag is the load-bearing part: without it a connection
// that dropped mid-body would produce a prefix hash and be reported as a
// tampered bundle.
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
		// hash.Hash never returns an error, by its own documented contract.
		_, _ = r.h.Write(p[:n])
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

// digest is the sha256 of everything read so far.
//
// The round trip through the lockfile encoding is deliberate: cache.Digest
// exposes no constructor from raw bytes on purpose — a value of that type can
// only come from Compute or one of the two parsers, which is what guarantees it
// always holds something measured or parsed rather than assembled. Re-encoding
// 32 bytes to hex and parsing them back costs nothing and keeps that
// guarantee, instead of widening the type's API for one error message.
func (r *hashingReader) digest() (cache.Digest, error) {
	return cache.ParseLockfileDigest("sha256:" + hex.EncodeToString(r.h.Sum(nil)))
}
