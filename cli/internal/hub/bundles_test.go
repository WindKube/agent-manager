package hub_test

// The redirect-leak test redirects to the same host, because net/http drops Authorization across hosts
// by itself, and asserts on what the target received on the wire, not what the client meant to send.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/cache"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/hub/fake"
)

type wireHit struct {
	Method   string
	Host     string
	Path     string
	Auth     string
	HasQuery bool
}

type wireSpy struct {
	base http.RoundTripper
	mu   sync.Mutex
	hits []wireHit
}

func (s *wireSpy) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.hits = append(s.hits, wireHit{
		Method:   req.Method,
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		Auth:     req.Header.Get("Authorization"),
		HasQuery: req.URL.RawQuery != "",
	})
	s.mu.Unlock()
	return s.base.RoundTrip(req)
}

func (s *wireSpy) all() []wireHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wireHit(nil), s.hits...)
}

func (s *wireSpy) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = nil
}

type rig struct {
	target fake.Target
	hub    *hub.Hub
	cache  *cache.Cache
	dir    string
	wire   *wireSpy
	dl     *hub.Downloader
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := fake.New(fake.Options{})
	t.Cleanup(f.Close)
	return rigFor(t, f.Target())
}

func rigFor(t *testing.T, target fake.Target) *rig {
	t.Helper()

	base := target.HTTPClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	spy := &wireSpy{base: base}
	client := *target.HTTPClient
	client.Transport = spy

	h, err := hub.New(hub.Config{
		URL:            target.BaseURL,
		Token:          target.Token,
		AllowPlaintext: true,
		HTTPClient:     &client,
	})
	require.NoError(t, err)

	dir := filepath.Join(t.TempDir(), "cache")
	c := cache.New(dir)
	dl, err := hub.NewDownloader(h, c)
	require.NoError(t, err)

	return &rig{target: target, hub: h, cache: c, dir: dir, wire: spy, dl: dl}
}

// refs keeps lockfile order, since the fake puts the 403 in the middle on purpose.
func (r *rig) refs(t *testing.T, slug string) []hub.BundleRef {
	t.Helper()
	lf, err := r.hub.GetRevision(t.Context(), slug, "head")
	require.NoError(t, err)
	require.NotEmpty(t, lf.Entries, "fixture %q has no entries to fetch", slug)
	out := make([]hub.BundleRef, 0, len(lf.Entries))
	for i := range lf.Entries {
		ref, perr := hub.ParseBundleRef(lf.Entries[i])
		require.NoError(t, perr)
		out = append(out, ref)
	}
	// The lockfile fetch is setup, not the behaviour under test.
	r.wire.reset()
	return out
}

func (r *rig) refByID(t *testing.T, slug, id string) hub.BundleRef {
	t.Helper()
	for _, ref := range r.refs(t, slug) {
		if ref.ID == id {
			return ref
		}
	}
	t.Fatalf("profile %q has no entry %q", slug, id)
	return hub.BundleRef{}
}

func (r *rig) cacheNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(r.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// rawBundle fetches through a plain client: the independent side of the digest assertions.
func rawBundle(t *testing.T, target fake.Target, ref hub.BundleRef) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.BaseURL+ref.Path(), http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+target.Token)
	resp, err := target.HTTPClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

func sha256Lockfile(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestFetchCachesVerifiedBytesAndServesTheSecondCallFromDisk(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")

	got, err := r.dl.Fetch(t.Context(), ref)
	require.NoError(t, err)
	require.False(t, got.FromCache, "the first fetch cannot come from an empty cache")
	require.NotEmpty(t, got.Bytes)

	require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes))
	require.Equal(t, rawBundle(t, r.target, ref), got.Bytes)

	require.Equal(t, []string{"sha256-" + ref.Digest.Hex()}, r.cacheNames(t))

	requests := len(r.wire.all())
	r.wire.reset()

	again, err := r.dl.Fetch(t.Context(), ref)
	require.NoError(t, err)
	require.True(t, again.FromCache, "the second fetch must be served from the cache")
	require.Equal(t, got.Bytes, again.Bytes)
	require.Empty(t, r.wire.all(), "a cached bundle must cost no request at all")
	require.Positive(t, requests, "the first fetch must actually have made a request, or the test above is vacuous")
}

func TestACachedEntryIsRehashedOnEveryReadRatherThanTrusted(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")

	first, err := r.dl.Fetch(t.Context(), ref)
	require.NoError(t, err)

	// Same name, same length, different bytes.
	entry := filepath.Join(r.dir, "sha256-"+ref.Digest.Hex())
	corrupt := append([]byte(nil), first.Bytes...)
	corrupt[len(corrupt)/2] ^= 0xff
	require.NoError(t, os.WriteFile(entry, corrupt, 0o600))

	t.Run("offline cannot use it", func(t *testing.T) {
		_, err := r.dl.Offline().Fetch(t.Context(), ref)
		require.ErrorIs(t, err, cache.ErrCorrupt,
			"a cache entry whose bytes no longer hash to its key must not be served")
		require.ErrorIs(t, err, hub.ErrOffline)
	})

	t.Run("online replaces it and the bytes are right again", func(t *testing.T) {
		r.wire.reset()
		again, err := r.dl.Fetch(t.Context(), ref)
		require.NoError(t, err)
		require.False(t, again.FromCache, "the corrupt entry must have been discarded, forcing a fetch")
		require.Equal(t, first.Bytes, again.Bytes)
		require.NotEmpty(t, r.wire.all())
	})
}

func TestTheBundleURLCarriesTheNamespaceAndNotThePublisher(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	ids := r.target.Fixtures.SharedNamespaceIDs
	require.Len(t, ids, 2, "the fixture must offer two ids in ONE namespace published by TWO publishers")

	seen := map[string]string{}
	for _, id := range ids {
		ref := r.refByID(t, r.target.Fixtures.Profile, id)
		r.wire.reset()
		got, err := r.dl.Fetch(t.Context(), ref)
		require.NoError(t, err, "id %q must be addressable", id)
		require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes))

		hits := r.wire.all()
		require.NotEmpty(t, hits)
		path := hits[0].Path
		seen[id] = path

		// A publisher slug is two segments and would make four here, a 404 that looks like a missing package.
		rest := strings.TrimPrefix(path, "/v1/bundles/")
		require.NotEqual(t, path, rest, "the request must go to the bundle endpoint")
		segs := strings.Split(rest, "/")
		require.Len(t, segs, 3, "want /v1/bundles/{namespace}/{name}/{version}, got %q", path)
		require.Equal(t, ref.Namespace, segs[0], "the first path segment is the NAMESPACE")
		require.Equal(t, ref.Name, segs[1])
		require.Equal(t, ref.Version, segs[2])
	}

	first := strings.Split(strings.TrimPrefix(seen[ids[0]], "/v1/bundles/"), "/")[0]
	second := strings.Split(strings.TrimPrefix(seen[ids[1]], "/v1/bundles/"), "/")[0]
	require.Equal(t, first, second, "the fixture is only a control if the two ids really share a namespace")
	require.NotEqual(t, seen[ids[0]], seen[ids[1]])
}

func TestParseBundleRefRefusesWhatItCannotAddress(t *testing.T) {
	t.Parallel()

	const goodDigest = "sha256:" +
		"9f2d6d0b3d3b62e6b3b4c1b0c0a9f5c1e2d3b4a5960718293a4b5c6d7e8f9012"

	tests := []struct {
		name    string
		entry   hub.LockfileEntry
		wantErr error
		wantMsg string
	}{
		{
			name:  "namespace and name",
			entry: hub.LockfileEntry{Id: "acme/code-review", Version: "2.4.1", Digest: goodDigest},
		},
		{
			name:  "a semver with prerelease and build metadata",
			entry: hub.LockfileEntry{Id: "acme/code-review", Version: "2.4.1-rc.1+build.7", Digest: goodDigest},
		},
		{
			name:    "one segment",
			entry:   hub.LockfileEntry{Id: "code-review", Version: "1.0.0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "one segment",
		},
		{
			name:    "a publisher slug where an id belongs",
			entry:   hub.LockfileEntry{Id: "acme/platform/code-review", Version: "1.0.0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "more than two segments",
		},
		{
			name:    "empty namespace",
			entry:   hub.LockfileEntry{Id: "/code-review", Version: "1.0.0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "empty segment",
		},
		{
			name:    "empty name",
			entry:   hub.LockfileEntry{Id: "acme/", Version: "1.0.0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "empty segment",
		},
		{
			name:    "a parent-directory reference in the namespace",
			entry:   hub.LockfileEntry{Id: "..%2f../code-review", Version: "1.0.0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "must start with a letter or digit",
		},
		{
			name:    "a parent-directory reference in the version",
			entry:   hub.LockfileEntry{Id: "acme/code-review", Version: "1..0", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "parent-directory reference",
		},
		{
			name:    "a query string smuggled into the version",
			entry:   hub.LockfileEntry{Id: "acme/code-review", Version: "1.0.0?x=y", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "not a valid object-key character",
		},
		{
			name:    "no version",
			entry:   hub.LockfileEntry{Id: "acme/code-review", Digest: goodDigest},
			wantErr: hub.ErrBundleRef,
			wantMsg: "empty version",
		},
		{
			name:    "a digest in the wrong encoding",
			entry:   hub.LockfileEntry{Id: "acme/code-review", Version: "1.0.0", Digest: "sha-256=Zm9v"},
			wantErr: cache.ErrDigest,
			wantMsg: "does not start with",
		},
		{
			name:    "no digest at all",
			entry:   hub.LockfileEntry{Id: "acme/code-review", Version: "1.0.0"},
			wantErr: cache.ErrDigest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref, err := hub.ParseBundleRef(tc.entry)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.Equal(t, tc.entry.Id, ref.ID)
				require.Equal(t, tc.entry.Id, ref.Namespace+"/"+ref.Name)
				require.Equal(t, "/v1/bundles/"+ref.Namespace+"/"+ref.Name+"/"+ref.Version, ref.Path())
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantMsg != "" {
				require.Contains(t, err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestFetchRefusesAHandBuiltRefItCannotAddress(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	good := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")

	// The generated request builder does not escape path parameters, so this must be refused before any request.
	bad := good
	bad.Name = "code-review/../../v1/health"
	bad.ID = bad.Namespace + "/" + bad.Name

	_, err := r.dl.Fetch(t.Context(), bad)
	require.ErrorIs(t, err, hub.ErrBundleRef)
	require.Empty(t, r.wire.all(), "an unaddressable ref must not reach the network")
}

func TestACorruptedBundleWritesNothingAndNamesBothDigests(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	slug := r.target.Fixtures.DigestMismatch
	require.NotEmpty(t, slug, "the fixture hub must offer a digest-mismatch profile")

	refs := r.refs(t, slug)
	require.Len(t, refs, 2, "the fixture must pair the bad entry with a good one")

	// The bad entry is derived through a plain GET, independently of the downloader.
	var bad, good *hub.BundleRef
	served := map[string]string{}
	for i := range refs {
		ref := refs[i]
		served[ref.ID] = sha256Lockfile(rawBundle(t, r.target, ref))
		if served[ref.ID] != ref.Digest.Lockfile() {
			bad = &refs[i]
		} else {
			good = &refs[i]
		}
	}
	require.NotNil(t, bad, "no entry in %q actually mismatches", slug)
	require.NotNil(t, good, "the fixture must also carry an entry that installs")

	_, err := r.dl.Fetch(t.Context(), *bad)

	var mismatch *hub.DigestMismatchError
	require.ErrorAs(t, err, &mismatch, "want the typed failure, not a generic error")
	require.ErrorIs(t, err, hub.ErrDigestMismatch)
	// The fake's Digest header catches it before the body is read; the body path is covered elsewhere.
	require.Equal(t, hub.DigestSourceHeader, mismatch.Source)
	require.Zero(t, mismatch.Bytes, "not one byte of a bundle already known to be wrong should be read")

	require.Equal(t, bad.Digest, mismatch.Want)
	require.Equal(t, served[bad.ID], mismatch.Got.Lockfile())
	require.NotEqual(t, mismatch.Want, mismatch.Got)
	require.Contains(t, err.Error(), mismatch.Want.Lockfile(), "the locked digest must be named")
	require.Contains(t, err.Error(), mismatch.Got.Lockfile(), "the served digest must be named")

	require.Empty(t, r.cacheNames(t), "a refused bundle must leave the cache exactly as it was")
	_, statErr := os.Stat(filepath.Join(r.dir, "sha256-"+mismatch.Got.Hex()))
	require.ErrorIs(t, statErr, os.ErrNotExist, "the served bytes must not be filed under their own digest either")

	// The failure is per-entry, not per-profile.
	ok, err := r.dl.Fetch(t.Context(), *good)
	require.NoError(t, err)
	require.Equal(t, good.Digest.Lockfile(), sha256Lockfile(ok.Bytes))
	require.Equal(t, []string{"sha256-" + good.Digest.Hex()}, r.cacheNames(t))
}

func TestADisagreeingDigestHeaderIsRefusedAndAnUnreadableOneIsIgnored(t *testing.T) {
	t.Parallel()

	payload := []byte("pretend-zstd-bundle-bytes")
	sum := sha256.Sum256(payload)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])

	// Two different wrong values, so the reported digest cannot be right by accident.
	headerNames := []byte("the bundle the header claims")
	headerNamesSum := sha256.Sum256(headerNames)
	otherBody := []byte("some other bundle entirely")

	tests := []struct {
		name   string
		header string
		// body reaches the body path with no usable header, as a real pre-signed object store does.
		body []byte
		// wantGotOf is what the header named for the header source, not what was served.
		wantGotOf  []byte
		wantErr    bool
		wantSource hub.DigestSource
	}{
		{
			name:   "no Digest header at all, as a real object store sends",
			header: "",
		},
		{
			name:   "the documented header, agreeing",
			header: "sha-256=" + base64.StdEncoding.EncodeToString(sum[:]),
		},
		{
			name:   "another RFC 3230 algorithm this client cannot read",
			header: "crc32c=1c2d3e4f",
		},
		{
			name:       "a sha-256 header naming other bytes",
			header:     "sha-256=" + base64.StdEncoding.EncodeToString(headerNamesSum[:]),
			wantGotOf:  headerNames,
			wantErr:    true,
			wantSource: hub.DigestSourceHeader,
		},
		{
			name:       "no header and a body that is not the locked bundle",
			body:       otherBody,
			wantGotOf:  otherBody,
			wantErr:    true,
			wantSource: hub.DigestSourceBody,
		},
		{
			name:       "an unreadable header and a body that is not the locked bundle",
			header:     "crc32c=1c2d3e4f",
			body:       otherBody,
			wantGotOf:  otherBody,
			wantErr:    true,
			wantSource: hub.DigestSourceBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			served := tc.body
			if served == nil {
				served = payload
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set("Digest", tc.header)
				}
				w.Header().Set("Content-Type", "application/zstd")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(served)
			}))
			t.Cleanup(srv.Close)

			h, err := hub.New(hub.Config{URL: srv.URL, Token: "t", AllowPlaintext: true, HTTPClient: srv.Client()})
			require.NoError(t, err)
			cacheDir := filepath.Join(t.TempDir(), "cache")
			dl, err := hub.NewDownloader(h, cache.New(cacheDir))
			require.NoError(t, err)

			ref, err := hub.ParseBundleRef(hub.LockfileEntry{
				Id: "acme/code-review", Version: "2.4.1", Digest: wantDigest,
			})
			require.NoError(t, err)

			got, err := dl.Fetch(t.Context(), ref)
			if !tc.wantErr {
				// An unreadable header must not break the 307 offload path; the body's hash is the authority.
				require.NoError(t, err)
				require.Equal(t, payload, got.Bytes)
				return
			}
			var mismatch *hub.DigestMismatchError
			require.ErrorAs(t, err, &mismatch)
			require.ErrorIs(t, err, hub.ErrDigestMismatch)
			require.Equal(t, tc.wantSource, mismatch.Source)
			require.Equal(t, ref.Digest, mismatch.Want)
			require.Equal(t, cache.Compute(tc.wantGotOf), mismatch.Got)
			if tc.wantSource == hub.DigestSourceHeader {
				require.Zero(t, mismatch.Bytes, "the header is checked before the body is read")
			} else {
				require.Equal(t, int64(len(served)), mismatch.Bytes)
			}
			require.Contains(t, err.Error(), mismatch.Want.Lockfile())
			require.Contains(t, err.Error(), mismatch.Got.Lockfile())
			names, rerr := os.ReadDir(cacheDir)
			if !errors.Is(rerr, os.ErrNotExist) {
				require.NoError(t, rerr)
				require.Empty(t, names, "a refused bundle must leave nothing behind")
			}
		})
	}
}

func TestATruncatedBodyIsAConnectionFailureAndNotATamperedBundle(t *testing.T) {
	t.Parallel()

	payload := []byte("pretend-zstd-bundle-bytes-long-enough-to-cut")
	sum := sha256.Sum256(payload)

	// A raw listener, since net/http's server would correct the Content-Length.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/zstd\r\n"+
				"Content-Length: %d\r\n\r\n", len(payload))
			_, _ = conn.Write(payload[:8])
			_ = conn.Close()
		}
	}()
	// Registered first so the listener closes first; otherwise cleanup deadlocks.
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = ln.Close() })

	h, err := hub.New(hub.Config{URL: "http://" + ln.Addr().String(), Token: "t", AllowPlaintext: true})
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "cache")
	dl, err := hub.NewDownloader(h, cache.New(dir))
	require.NoError(t, err)

	ref, err := hub.ParseBundleRef(hub.LockfileEntry{
		Id: "acme/code-review", Version: "2.4.1", Digest: "sha256:" + hex.EncodeToString(sum[:]),
	})
	require.NoError(t, err)

	_, err = dl.Fetch(t.Context(), ref)
	require.Error(t, err)
	// A dropped connection must not read as a tampered object.
	require.NotErrorIs(t, err, hub.ErrDigestMismatch)
	require.ErrorIs(t, err, hub.ErrUnreachable)
	require.Equal(t, hub.ClassUnreachable, hub.ClassOf(err))

	// Any temp left is a `.amctl-tmp-` name that no lookup can reach.
	entries, rerr := os.ReadDir(dir)
	if !errors.Is(rerr, os.ErrNotExist) {
		require.NoError(t, rerr)
		for _, e := range entries {
			require.True(t, strings.HasPrefix(e.Name(), ".amctl-tmp-"),
				"a partial download must not be readable as a cache entry, found %q", e.Name())
		}
	}
}

func TestTheBearerTokenNeverReachesThePresignedRedirectTarget(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	slug := r.target.Fixtures.PresignedBundle
	require.NotEmpty(t, slug, "the fixture hub must offer a profile whose bundle answers 307")
	refs := r.refs(t, slug)
	ref := refs[0]

	got, err := r.dl.Fetch(t.Context(), ref)

	// The wire is asserted before the fetch error so a leak reads as a leak, not as "400 Bad Request".
	hits := r.wire.all()
	require.Len(t, hits, 2,
		"want the bundle request and the object request; fetch error %v, hits %+v", err, hits)
	require.Equal(t, ref.Path(), hits[0].Path)
	require.Equal(t, "Bearer "+r.target.Token, hits[0].Auth, "the hub itself must still be authenticated")

	require.Equal(t, hits[0].Host, hits[1].Host,
		"a cross-host redirect is not a control; net/http already strips there")
	require.NotEqual(t, hits[0].Path, hits[1].Path, "the second hop must be the object, not the hub route")
	require.True(t, hits[1].HasQuery, "the pre-signed URL carries its signature in the query")

	require.Empty(t, hits[1].Auth, "the bearer token must not reach the redirect target")

	// Without a followed redirect every assertion above holds vacuously.
	require.NoError(t, err)
	require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes),
		"the bytes behind the 307 must be the locked bundle")

	t.Run("the object endpoint really does refuse a leaked token", func(t *testing.T) {
		// Negative control: a plain http.Client leaks on a same-host redirect and the fake must answer 400.
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodGet,
			r.target.BaseURL+ref.Path(), http.NoBody)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+r.target.Token)

		resp, derr := r.target.HTTPClient.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)

		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"net/http preserves Authorization on a same-host redirect, and the object store must reject it; body %s", body)
		require.Contains(t, string(body), "must not also carry an Authorization header")
	})
}

func TestAForbiddenBundleFailsOnlyThatEntryAndTheOthersStillFetch(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	slug := r.target.Fixtures.ForbiddenBundle
	forbiddenID := r.target.Fixtures.ForbiddenEntryID
	require.NotEmpty(t, slug)
	require.NotEmpty(t, forbiddenID)

	refs := r.refs(t, slug)
	require.Len(t, refs, 3, "the fixture must put the 403 between two installable entries")
	require.Equal(t, forbiddenID, refs[1].ID, "the refusal must be in the MIDDLE, or continuing is untested")

	fetched := 0
	var skipped []string
	for _, ref := range refs {
		got, err := r.dl.Fetch(t.Context(), ref)
		if err != nil {
			require.Equal(t, hub.ClassForbidden, hub.ClassOf(err),
				"only a 403 skips an entry; %v", err)
			require.ErrorIs(t, err, hub.ErrForbidden)
			require.Contains(t, err.Error(), "scan gate")
			require.NotErrorIs(t, err, hub.ErrDigestMismatch,
				"a gate refusal is not a corrupted bundle; the two exit differently")
			skipped = append(skipped, ref.ID)
			continue
		}
		require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes))
		fetched++
	}

	require.Equal(t, []string{forbiddenID}, skipped)
	require.Equal(t, 2, fetched, "the entries either side of the 403 must both have fetched")
	require.Len(t, r.cacheNames(t), 2, "and exactly those two must be in the cache")
}

// A hub 403 is the scan gate and is skipped; a store 403 is a failed download, and skipping it would
// install nothing while reporting success. Same status, so the classes must differ.
func TestA403FromTheRedirectTargetIsNotTheHubsGate(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	slug := r.target.Fixtures.StalePresignedBundle
	staleID := r.target.Fixtures.StalePresignedEntryID
	require.NotEmpty(t, slug)
	require.NotEmpty(t, staleID)

	refs := r.refs(t, slug)
	require.Len(t, refs, 2, "the fixture must pair the refusal with an entry that serves bytes")

	var stale hub.BundleRef
	fetched := 0
	for _, ref := range refs {
		if ref.ID == staleID {
			stale = ref
			continue
		}
		_, err := r.dl.Fetch(t.Context(), ref)
		require.NoError(t, err, "the other entry must still fetch")
		fetched++
	}
	require.Equal(t, 1, fetched)
	require.NotEmpty(t, stale.ID, "the fixture's stale entry was not found")

	_, err := r.dl.Fetch(t.Context(), stale)
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, statusOf(t, err),
		"the premise: the store really did answer 403, the same status the gate uses")
	require.Equal(t, hub.ClassOffload, hub.ClassOf(err))
	require.ErrorIs(t, err, hub.ErrOffload)
	require.NotErrorIs(t, err, hub.ErrForbidden,
		"a store that refused the pre-signed URL is not the organisation's scan gate; "+
			"the sync verb would skip this entry and exit 0")
	require.True(t, hub.ClassOffload.Retryable(),
		"a pre-signed URL is short-lived, so the next run gets a fresh one")

	// The hub's own 403 must still be ClassForbidden.
	gated := r.refByID(t, r.target.Fixtures.ForbiddenBundle, r.target.Fixtures.ForbiddenEntryID)
	_, gerr := r.dl.Fetch(t.Context(), gated)
	require.ErrorIs(t, gerr, hub.ErrForbidden)
	require.NotErrorIs(t, gerr, hub.ErrOffload)
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var oe *hub.OpError
	require.ErrorAs(t, err, &oe)
	return oe.Status
}

func TestAMissingVersionIsNotSkippableTheWayA403Is(t *testing.T) {
	t.Parallel()
	r := newRig(t)

	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")
	ref.Version = "9.9.9-not-published"

	_, err := r.dl.Fetch(t.Context(), ref)
	// An unservable version is not a gate decision, so the classes must differ.
	require.Equal(t, hub.ClassNotFound, hub.ClassOf(err))
	require.ErrorIs(t, err, hub.ErrNotFound)
	require.NotErrorIs(t, err, hub.ErrForbidden)
	require.Empty(t, r.cacheNames(t))
}

func TestOfflineCompletesFromTheCacheOrNamesTheMissingDigest(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")
	offline := r.dl.Offline()

	require.True(t, offline.IsOffline())
	require.False(t, r.dl.IsOffline(), "Offline must not mutate the downloader it was derived from")

	_, err := offline.Fetch(t.Context(), ref)
	require.ErrorIs(t, err, hub.ErrOffline)
	require.ErrorIs(t, err, cache.ErrMiss)
	require.Contains(t, err.Error(), ref.Digest.Lockfile(), "the refusal must name what is missing")
	require.Contains(t, err.Error(), ref.String())
	require.Empty(t, r.wire.all(), "--offline must not dial at all")

	_, err = r.dl.Fetch(t.Context(), ref)
	require.NoError(t, err)
	r.wire.reset()

	got, err := offline.Fetch(t.Context(), ref)
	require.NoError(t, err)
	require.True(t, got.FromCache)
	require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes))
	require.Empty(t, r.wire.all())
}

func TestNoBundleFailureRendersTheBearerToken(t *testing.T) {
	t.Parallel()

	const token = "bundles-test-bearer-DO-NOT-LEAK-1d4f8b60"

	f := fake.New(fake.Options{})
	t.Cleanup(f.Close)
	target := f.Target()

	h, err := hub.New(hub.Config{
		URL: target.BaseURL, Token: token, AllowPlaintext: true, HTTPClient: target.HTTPClient,
	})
	require.NoError(t, err)
	dl, err := hub.NewDownloader(h, cache.New(filepath.Join(t.TempDir(), "cache")))
	require.NoError(t, err)

	dead, err := hub.New(hub.Config{URL: "http://127.0.0.1:1", Token: token, AllowPlaintext: true})
	require.NoError(t, err)
	deadDL, err := hub.NewDownloader(dead, cache.New(filepath.Join(t.TempDir(), "cache2")))
	require.NoError(t, err)

	someRef := func(id, version, digest string) hub.BundleRef {
		ref, perr := hub.ParseBundleRef(hub.LockfileEntry{Id: id, Version: version, Digest: digest})
		require.NoError(t, perr)
		return ref
	}
	const otherDigest = "sha256:" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	producers := []struct {
		name string
		run  func() error
	}{
		{"unauthorised bundle", func() error {
			bad, nerr := hub.New(hub.Config{URL: target.BaseURL, Token: token + "-wrong", AllowPlaintext: true,
				HTTPClient: target.HTTPClient})
			require.NoError(t, nerr)
			badDL, nerr := hub.NewDownloader(bad, cache.New(filepath.Join(t.TempDir(), "cache3")))
			require.NoError(t, nerr)
			_, e := badDL.Fetch(t.Context(), someRef("acme/code-review", "2.4.1", otherDigest))
			return e
		}},
		{"not found", func() error {
			_, e := dl.Fetch(t.Context(), someRef("acme/code-review", "0.0.1", otherDigest))
			return e
		}},
		{"forbidden", func() error {
			_, e := dl.Fetch(t.Context(), someRef("contoso/gated", "3.1.0", otherDigest))
			return e
		}},
		{"digest mismatch", func() error {
			_, e := dl.Fetch(t.Context(), someRef("acme/code-review", "2.4.1", otherDigest))
			return e
		}},
		{"unreachable", func() error {
			_, e := deadDL.Fetch(t.Context(), someRef("acme/code-review", "2.4.1", otherDigest))
			return e
		}},
		{"offline miss", func() error {
			_, e := dl.Offline().Fetch(t.Context(), someRef("acme/code-review", "2.4.1", otherDigest))
			return e
		}},
		{"unusable ref", func() error {
			_, e := hub.ParseBundleRef(hub.LockfileEntry{Id: "nope", Version: "1.0.0", Digest: otherDigest})
			return e
		}},
	}

	for _, p := range producers {
		t.Run(p.name, func(t *testing.T) {
			err := p.run()
			require.Error(t, err, "this producer must actually fail, or it checks nothing")
			for _, rendered := range []string{
				err.Error(),
				fmt.Sprintf("%v", err),
				fmt.Sprintf("%+v", err),
				fmt.Sprintf("%#v", err),
			} {
				require.NotContains(t, rendered, token)
				require.NotContains(t, rendered, "X-Amz-Signature")
			}
		})
	}
}

func TestNewDownloaderRefusesAnIncompletePairing(t *testing.T) {
	t.Parallel()

	_, err := hub.NewDownloader(nil, cache.New(t.TempDir()))
	require.Error(t, err)

	h, err := hub.New(hub.Config{URL: "https://hub.example.test", Token: "t"})
	require.NoError(t, err)
	_, err = hub.NewDownloader(h, nil)
	require.Error(t, err)
}

// recordingStore is the real cache with a call log, and optionally a Get that fails after the write.
type recordingStore struct {
	inner *cache.Cache

	mu        sync.Mutex
	calls     []string
	failAfter int // when >0, the Nth Get onwards fails
	gets      int
}

func (s *recordingStore) Get(d cache.Digest) ([]byte, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "get")
	s.gets++
	fail := s.failAfter > 0 && s.gets >= s.failAfter
	s.mu.Unlock()
	if fail {
		return nil, errors.New("the cache directory went away")
	}
	return s.inner.Get(d)
}

func (s *recordingStore) PutReader(d cache.Digest, r io.Reader) error {
	s.mu.Lock()
	s.calls = append(s.calls, "put")
	s.mu.Unlock()
	return s.inner.PutReader(d, r)
}

func (s *recordingStore) Root() string { return s.inner.Root() }

func (s *recordingStore) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func TestFetchReadsBackThroughTheCacheRatherThanTrustingWhatItJustWrote(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")

	store := &recordingStore{inner: cache.New(filepath.Join(t.TempDir(), "cache"))}
	dl, err := hub.NewDownloader(r.hub, store)
	require.NoError(t, err)

	got, err := dl.Fetch(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, ref.Digest.Lockfile(), sha256Lockfile(got.Bytes))

	// The read-back Get is what a "we just wrote it" fast path would drop, invisibly to any byte assertion.
	require.Equal(t, []string{"get", "put", "get"}, store.log())

	_, err = dl.Fetch(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, []string{"get", "put", "get", "get"}, store.log(),
		"a cached bundle costs exactly one Get and no write")
}

func TestAFetchWhoseReadBackFailsIsNotReportedAsASuccess(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ref := r.refByID(t, r.target.Fixtures.Profile, "acme/code-review")

	// The second Get is the read-back, and it fails.
	store := &recordingStore{inner: cache.New(filepath.Join(t.TempDir(), "cache")), failAfter: 2}
	dl, err := hub.NewDownloader(r.hub, store)
	require.NoError(t, err)

	got, err := dl.Fetch(t.Context(), ref)
	require.Nil(t, got)
	require.Error(t, err)
	require.Contains(t, err.Error(), "did not read back")
	require.Contains(t, err.Error(), ref.String())
}
