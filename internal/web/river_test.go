package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/view"
)

// riverHandler is the web role with a dashboard configured at upstream, or
// with none when upstream is empty. viewer, when set, reshapes who is looking.
func riverHandler(t *testing.T, upstream string, viewer func(*fakeapi.Data)) http.Handler {
	t.Helper()

	opts := web.Options{}
	if upstream != "" {
		parsed, err := url.Parse(upstream)
		require.NoError(t, err)
		opts.RiverUI = &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	}
	api, h := newServerWith(t, opts)
	if viewer != nil {
		viewer(api.Data)
	}
	return h
}

func readOnly(d *fakeapi.Data) { d.As(apiclient.ViewerRoleReadOnly) }

// riverUpstream stands in for the dashboard, recording what reached it. Guarded
// because recording happens on the server goroutine.
type riverUpstream struct {
	*httptest.Server
	mu      sync.Mutex
	paths   []string
	cookies []string
}

func (u *riverUpstream) seenPaths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.paths)
}

func (u *riverUpstream) seenCookies() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.cookies)
}

func newRiverUpstream(t *testing.T) *riverUpstream {
	t.Helper()

	up := &riverUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.paths = append(up.paths, r.URL.Path)
		up.cookies = append(up.cookies, r.Header.Get("Cookie"))
		up.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "river_pref", Value: "table"})
		_, _ = w.Write([]byte(`{"available":0}`))
	}))
	t.Cleanup(up.Close)
	return up
}

func TestRiverScreenEmbedsTheDashboardOnThisHubsOwnOrigin(t *testing.T) {
	up := newRiverUpstream(t)
	body := get(t, riverHandler(t, up.URL, nil), "/river").Body.String()

	require.Contains(t, body, `id="river-frame"`)
	require.Contains(t, body, `src="`+view.RiverEmbedPrefix+`/"`)
	require.NotContains(t, body, up.URL,
		"the upstream address is this role's configuration, not something to publish to a browser")
}

// Both ways of being unavailable keep the entry, disabled, with their own reason:
// "no dashboard deployed" and "your role may not read it" are different facts.
func TestRiverNavEntryIsShownDisabledWithItsReasonRatherThanDropped(t *testing.T) {
	t.Run("no dashboard configured", func(t *testing.T) {
		body := get(t, riverHandler(t, "", nil), "/catalog").Body.String()

		require.Contains(t, body, "River Dashboard", "the entry stays in the sidebar")
		require.Contains(t, body, "am-nav-item-gated")
		// A fragment: templ escapes the apostrophe in "queue's".
		require.Contains(t, body, "This hub runs no River dashboard")
		require.NotContains(t, body, `href="/river"`, "a disabled entry is not a link")
	})

	t.Run("a role that may not read the queue", func(t *testing.T) {
		up := newRiverUpstream(t)
		body := get(t, riverHandler(t, up.URL, readOnly), "/catalog").Body.String()

		require.Contains(t, body, "River Dashboard")
		require.Contains(t, body, "am-nav-item-gated")
		require.Contains(t, body, "may not read the queue")
		require.NotContains(t, body, "This hub runs no River dashboard",
			"a role refusal is not a deployment fact and must not be reported as one")
	})

	t.Run("configured and permitted", func(t *testing.T) {
		up := newRiverUpstream(t)
		body := get(t, riverHandler(t, up.URL, nil), "/catalog").Body.String()

		require.Contains(t, body, `href="/river"`)
		require.NotContains(t, body, "am-nav-item-gated")
	})
}

// hubServer runs the web role on a real listener. Driven through
// httptest.NewRequest, httputil.ReverseProxy asks gin's writer for a
// CloseNotifier the recorder underneath does not implement, and panics.
func hubServer(t *testing.T, upstream string, viewer func(*fakeapi.Data)) string {
	t.Helper()

	srv := httptest.NewServer(riverHandler(t, upstream, viewer))
	t.Cleanup(srv.Close)
	return srv.URL
}

type hubResponse struct {
	Status int
	Header http.Header
	Body   string
}

// hubRequest sends one signed-in request without following redirects.
func hubRequest(t *testing.T, method, target string, body io.Reader) hubResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, target, body)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "am_session", Value: "screen-test-session"})

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, res.Body.Close()) }()

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return hubResponse{Status: res.StatusCode, Header: res.Header, Body: string(read)}
}

func TestRiverEmbedProxiesTheRequestThroughWithItsPathIntact(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, nil)

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusOK, res.Status)
	require.Equal(t, `{"available":0}`, res.Body)
	require.Equal(t, []string{view.RiverEmbedPrefix + "/api/states"}, up.seenPaths(),
		"the path goes upstream unchanged: the dashboard is started on this same prefix, "+
			"so nothing here rewrites it")
}

// The session cookie must never reach the third-party dashboard process.
func TestRiverEmbedForwardsNoSessionCookieUpstream(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, nil)

	hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, []string{""}, up.seenCookies(),
		"the request carried am_session and it must be stripped before it leaves")
}

// An upstream cookie would land on this origin, where the session cookie lives.
func TestRiverEmbedDropsUpstreamSetCookie(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, nil)

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Empty(t, res.Header.Values("Set-Cookie"),
		"the upstream set river_pref and it must not reach this origin")
}

// River's api can cancel, retry and delete jobs, none of which writes this hub's
// audit row, so the proxy is read-only and the refusal happens here.
func TestRiverEmbedRefusesEveryVerbThatCouldChangeTheQueue(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, nil)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			res := hubRequest(t, method, hub+view.RiverEmbedPrefix+"/api/jobs/cancel",
				strings.NewReader(`{"jobIDs":[1]}`))

			require.Equal(t, http.StatusMethodNotAllowed, res.Status)
			require.Empty(t, up.seenPaths(), "nothing reached the dashboard")
		})
	}
}

// The api is not in the proxy's path, so this is the only role check.
func TestRiverEmbedRefusesARoleThatMayNotReadTheQueue(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, readOnly)

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusForbidden, res.Status)
	require.Empty(t, up.seenPaths(), "a refused viewer's request never reaches the dashboard")
}

func TestRiverEmbedIsNotFoundWhenNoDashboardIsConfigured(t *testing.T) {
	hub := hubServer(t, "", nil)

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusNotFound, res.Status)
}

// An unreachable dashboard is a 502: a blank frame would read as an empty queue.
func TestRiverEmbedAnswersBadGatewayWhenTheDashboardIsUnreachable(t *testing.T) {
	up := newRiverUpstream(t)
	upstream := up.URL
	up.Close()
	hub := hubServer(t, upstream, nil)

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusBadGateway, res.Status)
}

// A refused viewer gets the screen with the reason, not a frame or a 403 page.
func TestRiverScreenExplainsItselfInsteadOfRenderingAnEmptyFrame(t *testing.T) {
	up := newRiverUpstream(t)

	t.Run("a role that may not read the queue", func(t *testing.T) {
		body := get(t, riverHandler(t, up.URL, readOnly), "/river").Body.String()

		require.Contains(t, body, `id="river-gate"`)
		require.Contains(t, body, "may not read the queue")
		require.NotContains(t, body, `id="river-frame"`)
	})

	t.Run("no dashboard configured", func(t *testing.T) {
		body := get(t, riverHandler(t, "", nil), "/river").Body.String()

		require.Contains(t, body, `id="river-gate"`)
		require.Contains(t, body, "AGENT_MANAGER_RIVER_UI_URL")
		require.NotContains(t, body, `id="river-frame"`)
	})
}

func TestRiverIsBehindTheSameGuardAsEveryOtherScreen(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, (*fakeapi.Data).SignedOut)

	for _, path := range []string{"/river", view.RiverEmbedPrefix + "/api/states"} {
		res := hubRequest(t, http.MethodGet, hub+path, http.NoBody)

		require.Equal(t, http.StatusFound, res.Status, path)
		require.True(t, strings.HasPrefix(res.Header.Get("Location"), "/auth/signin"),
			"%s redirected to %q", path, res.Header.Get("Location"))
		require.Empty(t, up.seenPaths())
	}
}
