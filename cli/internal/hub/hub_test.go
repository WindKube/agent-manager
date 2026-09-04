package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// testToken is the credential every test uses. It is a single distinctive
// string on purpose: the leak assertions are substring greps, and a token that
// could occur by accident in a message would make them lie.
const testToken = "hub-test-token-DO-NOT-LEAK-4a7f9c2e"

// hit is one request as the server saw it. The header values are recorded
// verbatim — this is the only place in the suite that is allowed to hold the
// credential, and it is what gives the leak-detection greps a non-empty haystack.
type hit struct {
	Method      string
	Path        string
	Host        string
	Auth        string
	RawQuery    string
	UserAgent   string
	ContentType string
	Body        string
}

type spy struct {
	mu   sync.Mutex
	hits []hit
}

func (s *spy) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, hit{
		Method:      r.Method,
		Path:        r.URL.Path,
		Host:        r.Host,
		Auth:        r.Header.Get("Authorization"),
		RawQuery:    r.URL.RawQuery,
		UserAgent:   r.Header.Get("User-Agent"),
		ContentType: r.Header.Get("Content-Type"),
		Body:        string(body),
	})
}

func (s *spy) all() []hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]hit(nil), s.hits...)
}

// newSpyServer starts a plaintext test server that records every request
// before handling it.
func newSpyServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *spy) {
	t.Helper()
	s := &spy{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

// newHub builds a Hub against a plaintext test server. AllowPlaintext is set
// because httptest speaks http; TestNewURLPolicy is what proves the flag is
// actually required.
func newHub(t *testing.T, serverURL, token string) *Hub {
	t.Helper()
	h, err := New(Config{URL: serverURL, Token: token, AllowPlaintext: true})
	require.NoError(t, err)
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Error{Status: int64(status), Title: title, Detail: &detail})
}

// ---------------------------------------------------------------------------
// TLS required, plaintext only behind an explicit flag.
// ---------------------------------------------------------------------------

func TestNewURLPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		url            string
		allowPlaintext bool
		wantErr        error // the sentinel the refusal MUST match
		wantNotErr     error // a sentinel it must NOT match, so a case cannot pass for the wrong reason
		wantContains   []string
		wantAbsent     []string
	}{
		{name: "https is accepted", url: "https://hub.example.com"},
		{name: "https with a port and a base path is accepted", url: "https://hub.example.com:8443/hub"},
		{
			name:         "plaintext is refused without the flag",
			url:          "http://hub.example.com",
			wantErr:      ErrInsecureHub,
			wantNotErr:   ErrHubURL,
			wantContains: []string{"--" + PlaintextFlagName, "cleartext"},
		},
		{
			name:         "plaintext is refused however the scheme is cased",
			url:          "HTTP://hub.example.com",
			wantErr:      ErrInsecureHub,
			wantNotErr:   ErrHubURL,
			wantContains: []string{"--" + PlaintextFlagName},
		},
		{name: "plaintext is accepted with the flag", url: "http://hub.example.com", allowPlaintext: true},
		{
			// A wrong scheme is not an insecurity, it is an unusable URL. If
			// this collapsed into ErrInsecureHub the message would offer a flag
			// that cannot help.
			name:         "another scheme is unusable rather than insecure",
			url:          "ftp://hub.example.com",
			wantErr:      ErrHubURL,
			wantNotErr:   ErrInsecureHub,
			wantContains: []string{"ftp"},
		},
		{
			name:           "the plaintext flag does not rescue another scheme",
			url:            "ftp://hub.example.com",
			allowPlaintext: true,
			wantErr:        ErrHubURL,
			wantNotErr:     ErrInsecureHub,
		},
		{
			name:         "a bare host is refused rather than assumed",
			url:          "hub.example.com",
			wantErr:      ErrHubURL,
			wantNotErr:   ErrInsecureHub,
			wantContains: []string{"no scheme"},
		},
		{
			// cmd.ParseHub is what turns `hub.example.com:8443` into an
			// https URL. net/url reads it as scheme "hub.example.com", so this
			// package refuses it rather than inventing a second opinion.
			name:       "host:port without a scheme is refused",
			url:        "hub.example.com:8443",
			wantErr:    ErrHubURL,
			wantNotErr: ErrInsecureHub,
		},
		{name: "empty is refused", url: "", wantErr: ErrHubURL, wantNotErr: ErrInsecureHub},
		{name: "whitespace is refused", url: "   ", wantErr: ErrHubURL, wantNotErr: ErrInsecureHub},
		{name: "no host is refused", url: "https:///v1", wantErr: ErrHubURL, wantNotErr: ErrInsecureHub},
		{
			// The same shape one layer down: the refusal must not echo the
			// password back into whatever captured stderr.
			name:         "userinfo is refused and the password is not echoed",
			url:          "https://alice:s3cr3t-do-not-echo@hub.example.com",
			wantErr:      ErrHubURL,
			wantNotErr:   ErrInsecureHub,
			wantContains: []string{"amctl login"},
			wantAbsent:   []string{"s3cr3t-do-not-echo", "alice"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, err := New(Config{URL: tc.url, Token: testToken, AllowPlaintext: tc.allowPlaintext})
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.NotNil(t, h)
				return
			}
			require.Error(t, err)
			require.Nil(t, h)
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantNotErr != nil {
				require.NotErrorIs(t, err, tc.wantNotErr)
			}
			for _, want := range tc.wantContains {
				require.Contains(t, err.Error(), want)
			}
			for _, absent := range tc.wantAbsent {
				require.NotContains(t, err.Error(), absent)
			}
			// A URL refusal happens before anything is dialled, so it is not
			// one of the four network classes.
			require.Equal(t, Class(0), ClassOf(err))
		})
	}
}

func TestInsecureIsReportedForAPlaintextHub(t *testing.T) {
	t.Parallel()

	plain, err := New(Config{URL: "http://hub.example.com", AllowPlaintext: true})
	require.NoError(t, err)
	require.True(t, plain.Insecure())

	secure, err := New(Config{URL: "https://hub.example.com"})
	require.NoError(t, err)
	require.False(t, secure.Insecure())
}

// ---------------------------------------------------------------------------
// The token IS sent to the hub.
// ---------------------------------------------------------------------------

func TestBearerTokenIsSentToTheHub(t *testing.T) {
	t.Parallel()

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/profiles":
			writeJSON(w, http.StatusOK, ProfileList{Profiles: []Profile{}})
		case "/v1/health":
			writeJSON(w, http.StatusOK, Health{Status: Ok, Checks: []HealthCheck{}})
		default:
			writeJSON(w, http.StatusOK, Lockfile{})
		}
	}

	t.Run("every hub call carries the bearer header", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, handler)
		h := newHub(t, srv.URL, testToken)

		_, err := h.ListProfiles(t.Context())
		require.NoError(t, err)
		_, err = h.GetRevision(t.Context(), "platform-baseline", "head")
		require.NoError(t, err)

		hits := spy.all()
		require.Len(t, hits, 2)
		for _, got := range hits {
			require.Equal(t, "Bearer "+testToken, got.Auth, "path %s", got.Path)
			require.Equal(t, "amctl", got.UserAgent, "a Go default user agent tells a hub operator nothing")
		}
	})

	t.Run("an empty token sends no header at all", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, handler)
		h := newHub(t, srv.URL, "")

		_, err := h.Health(t.Context())
		require.NoError(t, err)

		hits := spy.all()
		require.Len(t, hits, 1)
		// Not "Bearer " with nothing after it: an empty credential offered as
		// though it were one invites a 401 that means nothing.
		require.Empty(t, hits[0].Auth)
	})

	t.Run("a configured user agent is used", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, handler)
		h, err := New(Config{URL: srv.URL, Token: testToken, AllowPlaintext: true, UserAgent: "amctl/1.2.3 (linux/amd64)"})
		require.NoError(t, err)

		_, err = h.ListProfiles(t.Context())
		require.NoError(t, err)
		require.Equal(t, "amctl/1.2.3 (linux/amd64)", spy.all()[0].UserAgent)
	})
}

// ---------------------------------------------------------------------------
// The token NEVER reaches a redirect target.
//
// Every case here uses a SAME-HOST or SUBDOMAIN redirect. A cross-host
// redirect is included only as a control, and it is marked as such, because
// net/http strips Authorization across hosts by itself — a test built on one
// passes with the defect fully present and proves nothing.
// ---------------------------------------------------------------------------

const bundlePath = "/v1/bundles/acme/code-review/1.4.0"

// redirectHandler answers the bundle path with a 307 to location and serves
// the object at objectPath.
func redirectHandler(location, objectPath, payload string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case bundlePath:
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusTemporaryRedirect)
		case objectPath:
			w.Header().Set("Content-Type", "application/zstd")
			_, _ = io.WriteString(w, payload)
		default:
			http.NotFound(w, r)
		}
	}
}

// mappedClient dials addr no matter which host is asked for, which is what
// makes a genuine subdomain redirect testable against one httptest server.
func mappedClient(addr string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}

func TestTokenNeverReachesARedirectTarget(t *testing.T) {
	t.Parallel()

	const payload = "zstd-bundle-bytes"

	t.Run("same host, relative location", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("/objects/blob", "/objects/blob", payload))
		h := newHub(t, srv.URL, testToken)

		resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Proving the redirect was actually followed matters: if it were not,
		// the "no token on the second hop" assertion would hold vacuously.
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, payload, string(body))

		hits := spy.all()
		require.Len(t, hits, 2, "expected the bundle request and the object request")
		require.Equal(t, bundlePath, hits[0].Path)
		require.Equal(t, "Bearer "+testToken, hits[0].Auth, "the hub itself must still be authenticated")
		require.Equal(t, "/objects/blob", hits[1].Path)
		require.Empty(t, hits[1].Auth, "FR-016: the bearer token must not reach the redirect target")
	})

	t.Run("same host, absolute location", func(t *testing.T) {
		t.Parallel()
		var srvURL string
		s := &spy{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.record(r)
			redirectHandler(srvURL+"/objects/blob", "/objects/blob", payload)(w, r)
		}))
		t.Cleanup(srv.Close)
		srvURL = srv.URL

		h := newHub(t, srv.URL, testToken)
		resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		hits := s.all()
		require.Len(t, hits, 2)
		require.Equal(t, "Bearer "+testToken, hits[0].Auth)
		require.Empty(t, hits[1].Auth, "an absolute same-origin location is the same leak")
	})

	t.Run("subdomain of the hub", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("http://s3.hub.example.test/objects/blob", "/objects/blob", payload))
		h, err := New(Config{
			URL:            "http://hub.example.test",
			Token:          testToken,
			AllowPlaintext: true,
			HTTPClient:     mappedClient(srv.Listener.Addr().String()),
		})
		require.NoError(t, err)

		resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, payload, string(body))

		hits := spy.all()
		require.Len(t, hits, 2)
		require.Equal(t, "hub.example.test", hits[0].Host)
		require.Equal(t, "Bearer "+testToken, hits[0].Auth)
		require.Equal(t, "s3.hub.example.test", hits[1].Host)
		require.Empty(t, hits[1].Auth, "FR-016 has no subdomain exception; net/http's default does")
	})

	t.Run("same host, different port", func(t *testing.T) {
		t.Parallel()
		object, objectSpy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, payload)
		})
		srv, spy := newSpyServer(t, redirectHandler(object.URL+"/objects/blob", "/never", payload))
		h := newHub(t, srv.URL, testToken)

		resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		require.Equal(t, "Bearer "+testToken, spy.all()[0].Auth)
		require.Empty(t, objectSpy.all()[0].Auth,
			"a hub on :8443 fronting an object store on :9000 is the commonest self-hosted layout, and net/http leaks it")
	})

	t.Run("genuinely cross host is only a control", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("http://objects.example.net/objects/blob", "/objects/blob", payload))
		h, err := New(Config{
			URL:            "http://hub.example.test",
			Token:          testToken,
			AllowPlaintext: true,
			HTTPClient:     mappedClient(srv.Listener.Addr().String()),
		})
		require.NoError(t, err)

		resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)

		hits := spy.all()
		require.Len(t, hits, 2)
		require.Equal(t, "Bearer "+testToken, hits[0].Auth)
		require.Empty(t, hits[1].Auth)
	})
}

// TestStandardLibraryLeaksOnSameHostAndSubdomainRedirects is the negative
// control for the test above, and the justification for bearerTransport
// existing at all.
//
// It asserts what net/http does with NO help from this package: it copies
// Authorization onto a same-host redirect target, and onto a subdomain one.
// If a future Go release fixes that, this test fails — which is the signal to
// revisit bearerTransport's comment, not to delete the defence.
func TestStandardLibraryLeaksOnSameHostAndSubdomainRedirects(t *testing.T) {
	t.Parallel()

	const payload = "object-bytes"

	get := func(t *testing.T, client *http.Client, target string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
	}

	t.Run("same host", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("/objects/blob", "/objects/blob", payload))
		get(t, &http.Client{}, srv.URL+bundlePath)

		hits := spy.all()
		require.Len(t, hits, 2)
		require.Equal(t, "Bearer "+testToken, hits[1].Auth,
			"net/http is expected to leak here; that is why bearerTransport exists")
	})

	t.Run("subdomain", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("http://s3.hub.example.test/objects/blob", "/objects/blob", payload))
		get(t, mappedClient(srv.Listener.Addr().String()), "http://hub.example.test"+bundlePath)

		hits := spy.all()
		require.Len(t, hits, 2)
		require.Equal(t, "s3.hub.example.test", hits[1].Host)
		require.Equal(t, "Bearer "+testToken, hits[1].Auth,
			"shouldCopyHeaderOnRedirect deliberately permits subdomains; FR-016 does not")
	})

	// MEASURED, and not what the plan's reading of client.go predicted:
	// shouldCopyHeaderOnRedirect compares idnaASCIIFromURL(u), which is
	// u.Hostname() — the PORT IS NOT PART OF THE COMPARISON. The outer guard
	// `reqs[0].URL.Host != req.URL.Host` does include the port, so a
	// port-only change reaches shouldCopyHeaderOnRedirect and is then
	// permitted as an "exact match". A hub on :8443 redirecting to an object
	// store on :9000 of the same host therefore leaks the token by default,
	// which is the commonest self-hosted layout there is.
	t.Run("same host, different port", func(t *testing.T) {
		t.Parallel()
		object, objectSpy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, payload)
		})
		srv, _ := newSpyServer(t, redirectHandler(object.URL+"/objects/blob", "/never", payload))
		get(t, &http.Client{}, srv.URL+bundlePath)

		require.Equal(t, "Bearer "+testToken, objectSpy.all()[0].Auth,
			"net/http compares hostnames, not origins, so a port change alone does not strip")
	})

	t.Run("genuinely cross host is stripped by the standard library", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, redirectHandler("http://objects.example.net/objects/blob", "/objects/blob", payload))
		get(t, mappedClient(srv.Listener.Addr().String()), "http://hub.example.test"+bundlePath)

		hits := spy.all()
		require.Len(t, hits, 2)
		require.Equal(t, "objects.example.net", hits[1].Host)
		require.Empty(t, hits[1].Auth,
			"this is the ONLY case a cross-host test exercises, and it passes with the defect fully present")
	})
}

// stubRoundTripper records the request it was handed and answers 204.
type stubRoundTripper struct {
	mu   sync.Mutex
	last *http.Request
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.last = req
	s.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// TestEachRedirectDefenceWorksAlone exercises bearerTransport and
// stripAuthorizationOnRedirect separately. Together they are belt and braces;
// tested only together, either one could be dead and the suite would stay
// green.
func TestEachRedirectDefenceWorksAlone(t *testing.T) {
	t.Parallel()

	hubURL := "https://hub.example.com"
	newTransport := func() (*bearerTransport, *stubRoundTripper) {
		stub := &stubRoundTripper{}
		return &bearerTransport{
			base:      stub,
			origin:    "https://hub.example.com:443",
			token:     func() string { return testToken },
			userAgent: "amctl",
		}, stub
	}

	tests := []struct {
		name       string
		target     string
		isRedirect bool
		preset     string
		wantAuth   string
	}{
		{name: "first hop to the hub is authenticated", target: hubURL + "/v1/profiles", wantAuth: "Bearer " + testToken},
		{name: "host casing does not matter", target: "https://HUB.example.com/v1/profiles", wantAuth: "Bearer " + testToken},
		{name: "explicit default port does not matter", target: "https://hub.example.com:443/v1/profiles", wantAuth: "Bearer " + testToken},
		{name: "same host redirect gets nothing", target: hubURL + "/objects/blob", isRedirect: true, wantAuth: ""},
		{name: "same host redirect with the header already copied is stripped", target: hubURL + "/objects/blob", isRedirect: true, preset: "Bearer " + testToken, wantAuth: ""},
		{name: "subdomain gets nothing", target: "https://s3.hub.example.com/objects/blob", preset: "Bearer " + testToken, wantAuth: ""},
		{name: "scheme downgrade on the same host gets nothing", target: "http://hub.example.com/v1/profiles", wantAuth: ""},
		{name: "different port gets nothing", target: "https://hub.example.com:8443/v1/profiles", wantAuth: ""},
		{name: "trailing dot is a different origin and fails closed", target: "https://hub.example.com./v1/profiles", wantAuth: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			transport, stub := newTransport()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.target, http.NoBody)
			require.NoError(t, err)
			if tc.preset != "" {
				req.Header.Set("Authorization", tc.preset)
			}
			if tc.isRedirect {
				// Exactly what net/http does: Request.Response is set on every
				// request a redirect created.
				req.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
			}

			resp, err := transport.RoundTrip(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, tc.wantAuth, stub.last.Header.Get("Authorization"))
			// A RoundTripper must not mutate the request it was given.
			require.Equal(t, tc.preset, req.Header.Get("Authorization"))
		})
	}

	t.Run("check redirect deletes the header and keeps a redirect limit", func(t *testing.T) {
		t.Parallel()
		check := stripAuthorizationOnRedirect(nil)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, hubURL+"/objects/blob", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testToken)
		require.NoError(t, check(req, nil))
		require.Empty(t, req.Header.Get("Authorization"))

		// Replacing CheckRedirect removes net/http's own limit, so the limit
		// has to come back or a redirect loop never ends.
		via := make([]*http.Request, maxRedirects)
		err = check(req, via)
		require.Error(t, err)
		require.Contains(t, err.Error(), "redirects")
	})

	t.Run("a caller's own check redirect still runs", func(t *testing.T) {
		t.Parallel()
		called := false
		check := stripAuthorizationOnRedirect(func(*http.Request, []*http.Request) error {
			called = true
			return nil
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, hubURL, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testToken)
		require.NoError(t, check(req, nil))
		require.True(t, called)
		require.Empty(t, req.Header.Get("Authorization"))
	})
}

func TestNewDoesNotMutateTheCallersHTTPClient(t *testing.T) {
	t.Parallel()

	caller := &http.Client{}
	_, err := New(Config{URL: "https://hub.example.com", Token: testToken, HTTPClient: caller})
	require.NoError(t, err)

	require.Nil(t, caller.Transport, "New must wrap a copy, not the caller's client")
	require.Nil(t, caller.CheckRedirect)
}

// ---------------------------------------------------------------------------
// unreachable / unauthorised / forbidden / not-found, and the answers
// that are none of the four.
// ---------------------------------------------------------------------------

// wantSentinel is the expected Class -> sentinel mapping, written out by hand.
// It deliberately does NOT read classSentinel: comparing that map to itself
// would prove only that a map equals itself.
func wantSentinel(t *testing.T, c Class) error {
	t.Helper()
	switch c {
	case ClassUnreachable:
		return ErrUnreachable
	case ClassTLS:
		return ErrTLS
	case ClassUnauthorised:
		return ErrUnauthorised
	case ClassForbidden:
		return ErrForbidden
	case ClassNotFound:
		return ErrNotFound
	case ClassRateLimited:
		return ErrRateLimited
	case ClassRequest:
		return ErrRequest
	case ClassUnimplemented:
		return ErrUnimplemented
	case ClassUnavailable:
		return ErrUnavailable
	case ClassServer:
		return ErrServer
	case ClassProtocol:
		return ErrProtocol
	case ClassOffload:
		return ErrOffload
	default:
		t.Fatalf("no sentinel expectation written for class %d", int(c))
		return nil
	}
}

// requireClass asserts the class, and asserts that NO other class matches.
// "Distinguishable" is a claim about every pair, not about one lucky hit.
func requireClass(t *testing.T, err error, want Class) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, want, ClassOf(err), "wrong class for %v", err)
	require.ErrorIs(t, err, wantSentinel(t, want))
	for _, other := range Classes() {
		if other == want {
			continue
		}
		require.NotErrorIs(t, err, wantSentinel(t, other),
			"class %s must not also match %s", want, other)
	}
}

func TestStatusClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		status       int
		body         any
		wantClass    Class
		wantContains []string
		wantRetry    int
	}{
		{
			name: "401 is unauthorised", status: http.StatusUnauthorized,
			body:      Error{Status: 401, Title: "Unauthorized", Detail: ptr("token has expired")},
			wantClass: ClassUnauthorised, wantContains: []string{"401", "token has expired", "listProfiles"},
		},
		{
			name: "403 is forbidden", status: http.StatusForbidden,
			body:      Error{Status: 403, Title: "Forbidden", Detail: ptr("not a member of this profile")},
			wantClass: ClassForbidden, wantContains: []string{"403", "not a member of this profile"},
		},
		{
			name: "404 is not found", status: http.StatusNotFound,
			body:      Error{Status: 404, Title: "Not Found"},
			wantClass: ClassNotFound, wantContains: []string{"404"},
		},
		{
			name: "422 is an invalid request and names the field", status: http.StatusUnprocessableEntity,
			body: Error{Status: 422, Title: "Unprocessable Entity", Errors: &[]ErrorDetail{
				{Location: ptr("path.revision"), Message: "must match ^(head|[0-9]+)$"},
			}},
			wantClass: ClassRequest, wantContains: []string{"422", "path.revision", "must match"},
		},
		{
			name: "400 is an invalid request", status: http.StatusBadRequest,
			body: Error{Status: 400, Title: "Bad Request"}, wantClass: ClassRequest,
		},
		{
			name: "429 is rate limited", status: http.StatusTooManyRequests,
			body: Error{Status: 429, Title: "Too Many Requests"}, wantClass: ClassRateLimited, wantRetry: 30,
			wantContains: []string{"retry after 30s"},
		},
		{
			// The hub answers 501 for an operation it does not implement, and
			// internal/api/api_test.go asserts that as intended. Calling it
			// unreachable would tell the user to check their network while the
			// hub is answering perfectly.
			name: "501 is unimplemented and not unreachable", status: http.StatusNotImplemented,
			body:      Error{Status: 501, Title: "Not Implemented", Detail: ptr("device flow is not enabled on this hub")},
			wantClass: ClassUnimplemented, wantContains: []string{"501", "device flow is not enabled"},
		},
		{
			name: "503 is unavailable", status: http.StatusServiceUnavailable,
			body: Error{Status: 503, Title: "Service Unavailable"}, wantClass: ClassUnavailable,
		},
		{
			name: "500 is a server error and not unreachable", status: http.StatusInternalServerError,
			body:      Error{Status: 500, Title: "Internal Server Error", CorrelationId: ptr("01JCORRELATION")},
			wantClass: ClassServer, wantContains: []string{"500", "01JCORRELATION"},
		},
		{
			name: "502 is a server error", status: http.StatusBadGateway,
			body: Error{Status: 502, Title: "Bad Gateway"}, wantClass: ClassServer,
		},
		{
			// An undeclared 2xx. Treating it as success would hand the caller a
			// zero-valued lockfile.
			name: "an undeclared success status is not a hub", status: http.StatusNoContent,
			wantClass: ClassProtocol,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.wantRetry > 0 {
					w.Header().Set("Retry-After", fmt.Sprint(tc.wantRetry))
				}
				w.Header().Set("X-Correlation-ID", "01JHEADER")
				if tc.body == nil {
					w.WriteHeader(tc.status)
					return
				}
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(tc.body)
			})
			h := newHub(t, srv.URL, testToken)

			_, err := h.ListProfiles(t.Context())
			requireClass(t, err, tc.wantClass)
			for _, want := range tc.wantContains {
				require.Contains(t, err.Error(), want)
			}

			var oe *OpError
			require.ErrorAs(t, err, &oe)
			require.Equal(t, tc.status, oe.Status)
			require.Equal(t, opListProfiles, oe.Op)
			require.Equal(t, tc.wantRetry, oe.RetryAfter)
			require.Contains(t, oe.URL, "/v1/profiles")
			require.NotEmpty(t, oe.CorrelationID, "the correlation id is the only thing worth quoting at a hub operator")
		})
	}
}

func TestTransportFailuresAreDistinguishable(t *testing.T) {
	t.Parallel()

	t.Run("a refused connection is unreachable", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {})
		addr := srv.URL
		srv.Close()

		h := newHub(t, addr, testToken)
		_, err := h.ListProfiles(t.Context())
		requireClass(t, err, ClassUnreachable)
	})

	t.Run("an untrusted certificate is a TLS failure, not a network one", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, ProfileList{Profiles: []Profile{}})
		}))
		t.Cleanup(srv.Close)

		// Deliberately NOT srv.Client(): the point is an unverifiable chain.
		h, err := New(Config{URL: srv.URL, Token: testToken})
		require.NoError(t, err)
		_, err = h.ListProfiles(t.Context())
		requireClass(t, err, ClassTLS)
	})

	t.Run("https against a plaintext hub is a TLS failure", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {})
		h, err := New(Config{URL: "https://" + srv.Listener.Addr().String(), Token: testToken})
		require.NoError(t, err)

		_, err = h.ListProfiles(t.Context())
		requireClass(t, err, ClassTLS)
	})

	t.Run("a cancelled context is unreachable and still unwraps", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, ProfileList{})
		})
		h := newHub(t, srv.URL, testToken)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := h.ListProfiles(ctx)
		requireClass(t, err, ClassUnreachable)
		require.ErrorIs(t, err, context.Canceled, "the cause must survive the classification")
	})

	t.Run("verified TLS works", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, ProfileList{Profiles: []Profile{{Slug: "platform-baseline"}}})
		}))
		t.Cleanup(srv.Close)

		h, err := New(Config{URL: srv.URL, Token: testToken, HTTPClient: srv.Client()})
		require.NoError(t, err)
		list, err := h.ListProfiles(t.Context())
		require.NoError(t, err)
		require.Len(t, list.Profiles, 1)
	})
}

// TestGarbageIsNotAHubRatherThanUnreachable is the regression this package is
// shaped around: the generated ParseXxx helpers return a plain error when
// json.Unmarshal fails, indistinguishable at the call site from the error they
// return when nothing answered. Routed through them, an HTML error page from a
// load balancer would be reported as "unreachable" and send the user hunting a
// network fault that does not exist.
func TestGarbageIsNotAHubRatherThanUnreachable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "an html error page", contentType: "text/html", body: "<html><body>502 Bad Gateway</body></html>"},
		{name: "json that is not the documented shape", contentType: "application/json", body: `{"profiles":"not-an-array"}`},
		{name: "an empty body on a 200", contentType: "application/json", body: ""},
		{name: "no content type at all", body: `{"profiles":[]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.body)
			})
			h := newHub(t, srv.URL, testToken)

			_, err := h.ListProfiles(t.Context())
			if tc.name == "no content type at all" {
				// A well-formed body with no content type IS the documented
				// one; the generated parser would have discarded it.
				require.NoError(t, err)
				return
			}
			requireClass(t, err, ClassProtocol)
		})
	}

	t.Run("a body over the cap is refused rather than allocated", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, maxBodyBytes+1)
		})
		h := newHub(t, srv.URL, testToken)

		_, err := h.ListProfiles(t.Context())
		requireClass(t, err, ClassProtocol)
		require.Contains(t, err.Error(), "cap")
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// TestHealthIsTheAuthFreeDiscriminator is the classification's whole point: /v1/health
// needs no credential, so "the hub is unreachable" and "your token is no good"
// are separable facts rather than one shrug.
func TestHealthIsTheAuthFreeDiscriminator(t *testing.T) {
	t.Parallel()

	t.Run("reachable hub with a bad credential is unauthorised, not unreachable", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/health" {
				writeJSON(w, http.StatusOK, Health{Status: Ok, Checks: []HealthCheck{{Name: "database", Ok: true}}})
				return
			}
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "token has expired")
		})
		h := newHub(t, srv.URL, testToken)

		require.True(t, h.Reachable(t.Context()))
		_, err := h.ListProfiles(t.Context())
		requireClass(t, err, ClassUnauthorised)
	})

	t.Run("an unreachable hub is not reachable", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {})
		addr := srv.URL
		srv.Close()

		h := newHub(t, addr, testToken)
		require.False(t, h.Reachable(t.Context()))
	})

	t.Run("a degraded hub is reachable and returns the failing check", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, Health{
				Status: Unavailable,
				Checks: []HealthCheck{{Name: "database", Ok: false, Error: ptr("dependency unreachable")}},
			})
		})
		h := newHub(t, srv.URL, testToken)

		got, err := h.Health(t.Context())
		requireClass(t, err, ClassUnavailable)
		require.NotNil(t, got, "the 503 body names the dependency that is down; dropping it leaves an unactionable diagnosis")
		require.Equal(t, Unavailable, got.Status)
		require.Len(t, got.Checks, 1)
		require.False(t, got.Checks[0].Ok)

		require.True(t, h.Reachable(t.Context()), "a 503 means the hub is there and a dependency is not")
	})

	t.Run("health needs no credential", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, Health{Status: Ok})
		})
		h := newHub(t, srv.URL, "")

		_, err := h.Health(t.Context())
		require.NoError(t, err)
		require.Empty(t, spy.all()[0].Auth)
	})
}

func ptr[T any](v T) *T { return &v }

// ---------------------------------------------------------------------------
// No token in any output, including error messages.
// ---------------------------------------------------------------------------

// errorProducer names a way to make this package emit an error, so the leak
// grep runs over every error value the wrapper can produce rather than over
// one convenient example.
type errorProducer struct {
	name string
	make func(t *testing.T) error
}

func errorProducers() []errorProducer {
	authFail := func(status int, body any) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()
			srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(status)
				if body != nil {
					_ = json.NewEncoder(w).Encode(body)
				}
			})
			_, err := newHub(t, srv.URL, testToken).ListProfiles(t.Context())
			require.Error(t, err)
			return err
		}
	}

	return []errorProducer{
		{"unauthorised", authFail(http.StatusUnauthorized, Error{Status: 401, Title: "Unauthorized", Detail: ptr("token has expired")})},
		{"forbidden", authFail(http.StatusForbidden, Error{Status: 403, Title: "Forbidden"})},
		{"not found", authFail(http.StatusNotFound, Error{Status: 404, Title: "Not Found"})},
		{"rate limited", authFail(http.StatusTooManyRequests, Error{Status: 429, Title: "Too Many Requests"})},
		{"invalid request", authFail(http.StatusBadRequest, Error{Status: 400, Title: "Bad Request"})},
		{"unimplemented", authFail(http.StatusNotImplemented, Error{Status: 501, Title: "Not Implemented"})},
		{"unavailable", authFail(http.StatusServiceUnavailable, Error{Status: 503, Title: "Service Unavailable"})},
		{"server error", authFail(http.StatusInternalServerError, Error{Status: 500, Title: "Internal Server Error"})},
		{
			// The realistic self-inflicted echo: problem+json's per-field
			// detail carries the offending VALUE, and a hub that validated the
			// Authorization header would put the token there. joinDetails
			// drops Value for exactly this reason.
			name: "a 422 whose per-field detail echoes the credential back",
			make: func(t *testing.T) error {
				t.Helper()
				srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(Error{Status: 422, Title: "Unprocessable Entity", Errors: &[]ErrorDetail{
						{Location: ptr("header.authorization"), Message: "malformed credential", Value: r.Header.Get("Authorization")},
					}})
				})
				_, err := newHub(t, srv.URL, testToken).ListProfiles(t.Context())
				require.Error(t, err)
				return err
			},
		},
		{
			name: "not a hub",
			make: func(t *testing.T) error {
				t.Helper()
				srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					_, _ = io.WriteString(w, "<html>nope</html>")
				})
				_, err := newHub(t, srv.URL, testToken).ListProfiles(t.Context())
				require.Error(t, err)
				return err
			},
		},
		{
			name: "unreachable",
			make: func(t *testing.T) error {
				t.Helper()
				srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {})
				addr := srv.URL
				srv.Close()
				_, err := newHub(t, addr, testToken).ListProfiles(t.Context())
				require.Error(t, err)
				return err
			},
		},
		{
			name: "tls",
			make: func(t *testing.T) error {
				t.Helper()
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				t.Cleanup(srv.Close)
				h, err := New(Config{URL: srv.URL, Token: testToken})
				require.NoError(t, err)
				_, err = h.ListProfiles(t.Context())
				require.Error(t, err)
				return err
			},
		},
		{
			name: "device flow refusal",
			make: func(t *testing.T) error {
				t.Helper()
				srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusBadRequest, DeviceTokenError{Error: ptr(AccessDenied)})
				})
				_, err := newHub(t, srv.URL, "").DeviceToken(t.Context(), DeviceTokenRequest{
					ClientId: "amctl", DeviceCode: testToken, GrantType: UrnIetfParamsOauthGrantTypeDeviceCode,
				})
				require.Error(t, err)
				return err
			},
		},
		{
			name: "plaintext refusal",
			make: func(t *testing.T) error {
				t.Helper()
				_, err := New(Config{URL: "http://hub.example.com", Token: testToken})
				require.Error(t, err)
				return err
			},
		},
		{
			name: "unusable url refusal",
			make: func(t *testing.T) error {
				t.Helper()
				_, err := New(Config{URL: "ftp://hub.example.com", Token: testToken})
				require.Error(t, err)
				return err
			},
		},
		{
			name: "local revision refusal",
			make: func(t *testing.T) error {
				t.Helper()
				h, err := New(Config{URL: "https://hub.example.com", Token: testToken})
				require.NoError(t, err)
				_, err = h.GetRevision(t.Context(), "platform-baseline", "latest")
				require.Error(t, err)
				return err
			},
		},
	}
}

func TestNoCredentialInAnyErrorValue(t *testing.T) {
	t.Parallel()

	// The verbs a careless caller actually reaches for. %+v is the one that
	// matters: it is what a structured logger uses, and it is what would print
	// a wrapped *http.Request's headers.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q"}

	for _, p := range errorProducers() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			err := p.make(t)
			for _, verb := range verbs {
				rendered := fmt.Sprintf(verb, err)
				require.NotContains(t, rendered, testToken,
					"FR-007: the credential appeared under %s", verb)
				require.NotContains(t, rendered, "Bearer ",
					"FR-007: an Authorization header value appeared under %s", verb)
			}
		})
	}

	// The negative control. Without this the greps above could be running over
	// an empty haystack and nobody would know.
	t.Run("the grep would catch a real leak", func(t *testing.T) {
		t.Parallel()
		leak := fmt.Errorf("listProfiles: request failed with header %q", "Bearer "+testToken)
		require.Contains(t, fmt.Sprintf("%v", leak), testToken)
	})
}

// TestNoCredentialInAFormattedHub is the measurement the token-as-a-closure
// comment in New rests on.
//
// The control case is the whole point: fmt CANNOT call String() on an
// unexported struct field — reflect.Value.CanInterface() is false for a field
// reached through reflection, so fmt prints the underlying value and the usual
// "wrap the secret in a redacting Stringer" defence silently does nothing. A
// func field prints as an address, which is why the token is held in a
// closure.
func TestNoCredentialInAFormattedHub(t *testing.T) {
	t.Parallel()

	h, err := New(Config{URL: "https://hub.example.com", Token: testToken})
	require.NoError(t, err)

	for _, verb := range []string{"%v", "%+v", "%#v"} {
		require.NotContains(t, fmt.Sprintf(verb, h), testToken)
		// The transport is where the credential actually lives, so format it
		// directly rather than relying on fmt not following the pointer.
		require.NotContains(t, fmt.Sprintf(verb, h.httpc.Transport), testToken)
		require.NotContains(t, fmt.Sprintf(verb, *h.httpc.Transport.(*bearerTransport)), testToken)
	}

	t.Run("control: a redacting Stringer in an unexported field does not redact", func(t *testing.T) {
		t.Parallel()
		type holder struct{ token redactingSecret }
		leaky := &holder{token: redactingSecret(testToken)}

		require.Contains(t, fmt.Sprintf("%+v", leaky), testToken,
			"if this ever stops being true, the closure in New may be replaced by a Stringer")
		var operand any = redactingSecret(testToken)
		require.NotContains(t, fmt.Sprintf("%v", operand), testToken,
			"the same type redacts fine when it is the operand itself, which is what makes the trap convincing")
	})
}

type redactingSecret string

func (redactingSecret) String() string   { return "[redacted]" }
func (redactingSecret) GoString() string { return `"[redacted]"` }

// TestPresignedQueryIsNotInAnError covers the credential one layer below the
// bearer token: getBundle's 307 points at an object-store URL whose signature
// IS the query string.
func TestPresignedQueryIsNotInAnError(t *testing.T) {
	t.Parallel()

	const signature = "PRESIGNED-SIGNATURE-DO-NOT-LEAK"
	srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case bundlePath:
			w.Header().Set("Location", "/objects/blob?X-Amz-Signature="+signature)
			w.WriteHeader(http.StatusTemporaryRedirect)
		default:
			writeProblem(w, http.StatusForbidden, "Forbidden", "the pre-signed URL has expired")
		}
	})
	h := newHub(t, srv.URL, testToken)

	resp, err := h.Raw().GetBundle(t.Context(), "acme", "code-review", "1.4.0")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// This is the call bundles.go makes, on the same table.
	classified := ClassifyStatus(OpGetBundle, resp, body, http.StatusOK)
	requireClass(t, classified, ClassForbidden)

	rendered := fmt.Sprintf("%v %+v", classified, classified)
	require.Contains(t, rendered, "/objects/blob", "the path is what makes the error diagnosable")
	require.NotContains(t, rendered, signature)
	require.NotContains(t, rendered, "X-Amz-Signature")

	hits := spy.all()
	require.Len(t, hits, 2)
	require.Empty(t, hits[1].Auth, "FR-016 again, on the path T038 will actually take")
	require.Contains(t, hits[1].RawQuery, signature, "the signature really was on the wire")
}

// ---------------------------------------------------------------------------
// The class table itself, the local argument checks, and the remaining verbs.
// ---------------------------------------------------------------------------

func TestClassTableIsComplete(t *testing.T) {
	t.Parallel()

	seenSlug := map[string]Class{}
	seenSentinel := map[error]Class{}
	for _, c := range Classes() {
		slug := c.String()
		require.NotEqual(t, "unclassified", slug, "class %d has no slug", int(c))
		if prev, dup := seenSlug[slug]; dup {
			t.Fatalf("classes %d and %d share the slug %q", int(prev), int(c), slug)
		}
		seenSlug[slug] = c

		sentinel := wantSentinel(t, c)
		if prev, dup := seenSentinel[sentinel]; dup {
			t.Fatalf("classes %d and %d share a sentinel", int(prev), int(c))
		}
		seenSentinel[sentinel] = c

		// The production mapping is compared to the hand-written expectation,
		// not to itself.
		require.ErrorIs(t, &OpError{Class: c}, sentinel)
	}
	require.Len(t, seenSlug, 12, "a new class needs a slug, a sentinel and a Retryable answer")

	require.Equal(t, Class(0), ClassOf(nil))
	require.Equal(t, Class(0), ClassOf(fmt.Errorf("something else entirely")))
	require.Equal(t, "unclassified", Class(0).String())

	// Retryable, hand-written rather than derived.
	wantRetryable := map[Class]bool{
		ClassUnreachable: true, ClassRateLimited: true, ClassUnavailable: true, ClassServer: true,
		// A pre-signed URL is short-lived, so the commonest offload refusal is
		// an expired signature the next run replaces.
		ClassOffload: true,
		ClassTLS:     false, ClassUnauthorised: false, ClassForbidden: false, ClassNotFound: false,
		ClassRequest: false, ClassUnimplemented: false, ClassProtocol: false,
	}
	for _, c := range Classes() {
		want, ok := wantRetryable[c]
		require.True(t, ok, "class %s has no Retryable expectation", c)
		require.Equal(t, want, c.Retryable(), "class %s", c)
	}
}

func TestClassOfSurvivesFurtherWrapping(t *testing.T) {
	t.Parallel()

	srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusForbidden, "Forbidden", "gate refuses this version")
	})
	_, err := newHub(t, srv.URL, testToken).ListProfiles(t.Context())
	require.Error(t, err)

	wrapped := fmt.Errorf("syncing platform-baseline: %w", err)
	require.Equal(t, ClassForbidden, ClassOf(wrapped))
	require.ErrorIs(t, wrapped, ErrForbidden)
}

func TestGetRevisionChecksItsArgumentsBeforeDialling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		slug     string
		revision string
		wantCall bool
	}{
		{name: "head is accepted", slug: "platform-baseline", revision: "head", wantCall: true},
		{name: "a number is accepted", slug: "platform-baseline", revision: "7", wantCall: true},
		{name: "zero is accepted and left to the hub", slug: "platform-baseline", revision: "0", wantCall: true},
		{name: "an empty slug is refused", slug: "", revision: "head"},
		{name: "an empty revision is refused", slug: "platform-baseline", revision: ""},
		{name: "uppercase HEAD is refused", slug: "platform-baseline", revision: "HEAD"},
		{name: "trailing space is refused", slug: "platform-baseline", revision: "head "},
		{name: "a negative number is refused", slug: "platform-baseline", revision: "-1"},
		{name: "a decimal is refused", slug: "platform-baseline", revision: "1.0"},
		{
			// The CLI does not resolve. "latest" is not a revision the
			// contract knows, and silently mapping it to head would be this
			// package deciding something.
			name: "latest is refused rather than mapped to head",
			slug: "platform-baseline", revision: "latest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusOK, Lockfile{Revision: 7})
			})
			h := newHub(t, srv.URL, testToken)

			got, err := h.GetRevision(t.Context(), tc.slug, tc.revision)
			if tc.wantCall {
				require.NoError(t, err)
				require.Equal(t, int64(7), got.Revision)
				require.Len(t, spy.all(), 1)
				return
			}
			require.Error(t, err)
			require.Empty(t, spy.all(), "a local refusal must not reach the network")
			// Not a hub failure: nothing was asked of the hub.
			require.Equal(t, Class(0), ClassOf(err))
		})
	}
}

func TestGetRevisionReturnsTheLockfileVerbatim(t *testing.T) {
	t.Parallel()

	// An unrecognised skip reason must survive to the caller: it must be
	// reported verbatim, and this client ships separately from the hub.
	const body = `{
	  "schemaVersion": "1.0.0",
	  "profile": {"slug": "platform-baseline", "name": "Platform baseline"},
	  "revision": 7,
	  "resolvedAt": "2026-01-01T00:00:00Z",
	  "gate": "block",
	  "entries": [],
	  "skipped": [{"id": "acme/code-review", "reason": "a-reason-from-a-newer-hub"}],
	  "targets": ["claude-code"]
	}`
	srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
	h := newHub(t, srv.URL, testToken)

	lock, err := h.GetRevision(t.Context(), "platform-baseline", "head")
	require.NoError(t, err)
	require.Equal(t, int64(7), lock.Revision)
	require.Len(t, lock.Skipped, 1)
	require.Equal(t, LockfileSkipReason("a-reason-from-a-newer-hub"), lock.Skipped[0].Reason)
	require.False(t, lock.Skipped[0].Reason.Valid(),
		"an unknown reason is FR-011's report-verbatim case, not a parse failure")
}

func TestReportSyncExpectsNoContent(t *testing.T) {
	t.Parallel()

	report := SyncReport{Host: "dev-laptop-01", Profile: "platform-baseline", Revision: 7, Targets: []SyncReportTargets{SyncReportTargetsClaudeCode}}

	t.Run("204 is success and the body is the contract's", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		h := newHub(t, srv.URL, testToken)

		require.NoError(t, h.ReportSync(t.Context(), report))

		hits := spy.all()
		require.Len(t, hits, 1, "one call per sync, not per package")
		require.Equal(t, http.MethodPost, hits[0].Method)
		require.Contains(t, hits[0].ContentType, "application/json")
		require.Contains(t, hits[0].Body, `"revision":7`)
		require.Equal(t, "Bearer "+testToken, hits[0].Auth)
	})

	t.Run("200 is not success", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"ok": "sure"})
		})
		h := newHub(t, srv.URL, testToken)

		// The contract declares 204 and nothing else for success. Accepting any
		// 2xx would silently pass whatever a proxy substituted.
		requireClass(t, h.ReportSync(t.Context(), report), ClassProtocol)
	})

	t.Run("401 is unauthorised, and FR-033 leaves it to the caller to warn", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "token has expired")
		})
		h := newHub(t, srv.URL, testToken)
		requireClass(t, h.ReportSync(t.Context(), report), ClassUnauthorised)
	})
}

func TestDeviceFlow(t *testing.T) {
	t.Parallel()

	t.Run("authorize returns the pending request", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, DeviceAuthorization{
				DeviceCode: "device-code-value", UserCode: "HKQ2-9FTL", ExpiresIn: 900, Interval: 5,
				VerificationUri: "https://hub.example.com/device",
			})
		})
		h := newHub(t, srv.URL, "")

		got, err := h.DeviceAuthorize(t.Context(), DeviceAuthorizeRequest{ClientId: "amctl", Host: "dev-laptop-01"})
		require.NoError(t, err)
		require.Equal(t, "HKQ2-9FTL", got.UserCode)
		require.Equal(t, int64(5), got.Interval)
		require.Empty(t, spy.all()[0].Auth, "the device endpoints take no credential")
	})

	t.Run("the token poll is form encoded", func(t *testing.T) {
		t.Parallel()
		srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, DeviceToken{AccessToken: "issued-token", TokenType: Bearer, ExpiresIn: 3600})
		})
		h := newHub(t, srv.URL, "")

		got, err := h.DeviceToken(t.Context(), DeviceTokenRequest{
			ClientId: "amctl", DeviceCode: "device-code-value", GrantType: UrnIetfParamsOauthGrantTypeDeviceCode,
		})
		require.NoError(t, err)
		require.Equal(t, "issued-token", got.AccessToken)

		hits := spy.all()
		require.Contains(t, hits[0].ContentType, "application/x-www-form-urlencoded")
		require.Contains(t, hits[0].Body, "device_code=device-code-value")
		require.Contains(t, hits[0].Body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
	})

	// The polling codes are the protocol working, not failing. Classified as
	// ClassRequest they would abort a login on its first tick.
	t.Run("a 400 is the polling protocol and not an error class", func(t *testing.T) {
		t.Parallel()
		for _, code := range []DeviceTokenErrorError{AuthorizationPending, SlowDown, AccessDenied, ExpiredToken, InvalidGrant} {
			t.Run(string(code), func(t *testing.T) {
				t.Parallel()
				srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, http.StatusBadRequest, DeviceTokenError{Error: ptr(code)})
				})
				h := newHub(t, srv.URL, "")

				_, err := h.DeviceToken(t.Context(), DeviceTokenRequest{ClientId: "amctl", DeviceCode: "device-code-value"})
				require.Error(t, err)

				var flow *DeviceFlowError
				require.ErrorAs(t, err, &flow)
				require.Equal(t, code, flow.Code)
				require.Equal(t, Class(0), ClassOf(err), "a poll refusal is not one of FR-040's classes")
				require.NotErrorIs(t, err, ErrRequest)
			})
		}
	})

	t.Run("a 400 with no recognisable body still reports something", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})
		h := newHub(t, srv.URL, "")

		_, err := h.DeviceToken(t.Context(), DeviceTokenRequest{ClientId: "amctl"})
		var flow *DeviceFlowError
		require.ErrorAs(t, err, &flow)
		require.Empty(t, flow.Code)
		require.Contains(t, err.Error(), "without naming a reason")
	})

	t.Run("501 on the device endpoints is unimplemented", func(t *testing.T) {
		t.Parallel()
		srv, _ := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeProblem(w, http.StatusNotImplemented, "Not Implemented", "device flow is not enabled on this hub")
		})
		h := newHub(t, srv.URL, "")

		_, err := h.DeviceAuthorize(t.Context(), DeviceAuthorizeRequest{ClientId: "amctl", Host: "dev-laptop-01"})
		requireClass(t, err, ClassUnimplemented)
	})
}

func TestHubBasePathIsPreserved(t *testing.T) {
	t.Parallel()

	srv, spy := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, ProfileList{Profiles: []Profile{}})
	})
	h := newHub(t, srv.URL+"/hub", testToken)

	_, err := h.ListProfiles(t.Context())
	require.NoError(t, err)
	require.Equal(t, "/hub/v1/profiles", spy.all()[0].Path,
		"a hub behind a path prefix is a supported deployment; dropping the prefix would 404 mysteriously")

	// The same prefix must appear in a transport error's target, which has no
	// response to read a URL from.
	require.Contains(t, h.opURL("/v1/profiles"), "/hub/v1/profiles")
	require.Equal(t, srv.URL+"/hub", h.URL())
}
