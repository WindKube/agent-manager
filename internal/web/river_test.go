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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

// riverHandler is the web role with a dashboard configured at upstream, or
// with none when upstream is empty.
func riverHandler(t *testing.T, upstream string, viewers web.ViewerSource) http.Handler {
	t.Helper()

	opts := web.Options{}
	if upstream != "" {
		parsed, err := url.Parse(upstream)
		require.NoError(t, err)
		opts.RiverUI = &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	}
	return web.New(web.Deps{
		Catalog: fixture.New(), Viewers: viewers, Log: zerolog.Nop(),
	}, opts).Handler()
}

// riverUpstream stands in for the dashboard, recording what reached it.
//
// Guarded, because the recording happens on the server's goroutine and the
// assertions on the test's: -race calls that a data race whether or not the
// values happen to arrive.
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
		// A dashboard that sets a cookie, so the response side is exercised by
		// something rather than asserted against nothing.
		http.SetCookie(w, &http.Cookie{Name: "river_pref", Value: "table"})
		_, _ = w.Write([]byte(`{"available":0}`))
	}))
	t.Cleanup(up.Close)
	return up
}

// The frame's own src has to be the path this role proxies, or the screen
// renders a box that loads nothing.
func TestRiverScreenEmbedsTheDashboardOnThisHubsOwnOrigin(t *testing.T) {
	up := newRiverUpstream(t)
	body := get(t, riverHandler(t, up.URL, fixture.SignedInViewers()), "/river").Body.String()

	require.Contains(t, body, `id="river-frame"`)
	require.Contains(t, body, `src="`+view.RiverEmbedPrefix+`/"`)
	require.NotContains(t, body, up.URL,
		"the upstream address is this role's configuration, not something to publish to a browser")
}

// The owner's rule for anything a viewer cannot use: show it, disable it, say
// why on hover. Both ways of being unavailable are that, and each says its own
// thing — "no dashboard is deployed" and "your role may not read it" are
// different facts and a reader can act on only one of them.
func TestRiverNavEntryIsShownDisabledWithItsReasonRatherThanDropped(t *testing.T) {
	t.Run("no dashboard configured", func(t *testing.T) {
		body := get(t, riverHandler(t, "", fixture.SignedInViewers()), "/catalog").Body.String()

		require.Contains(t, body, "River Dashboard", "the entry stays in the sidebar")
		require.Contains(t, body, "am-nav-item-gated")
		// A fragment, not the whole sentence: templ escapes the apostrophe in
		// "queue's", so the constant does not appear in the markup verbatim.
		require.Contains(t, body, "This hub runs no River dashboard")
		require.NotContains(t, body, `href="/river"`, "a disabled entry is not a link")
	})

	t.Run("a role that may not read the queue", func(t *testing.T) {
		up := newRiverUpstream(t)
		body := get(t, riverHandler(t, up.URL, readOnlyViewers()), "/catalog").Body.String()

		require.Contains(t, body, "River Dashboard")
		require.Contains(t, body, "am-nav-item-gated")
		require.Contains(t, body, "may not read the queue")
		require.NotContains(t, body, "This hub runs no River dashboard",
			"a role refusal is not a deployment fact and must not be reported as one")
	})

	t.Run("configured and permitted", func(t *testing.T) {
		up := newRiverUpstream(t)
		body := get(t, riverHandler(t, up.URL, fixture.SignedInViewers()), "/catalog").Body.String()

		require.Contains(t, body, `href="/river"`)
		require.NotContains(t, body, "am-nav-item-gated")
	})
}

// hubServer runs the web role on a real listener.
//
// The proxy tests need one: httputil.ReverseProxy asks the ResponseWriter for
// a CloseNotifier when the request context has no Done channel, gin's writer
// says it is one, and the recorder underneath is not — so a proxy driven
// through httptest.NewRequest panics inside gin rather than proxying anything.
// A real server has a real context and a real writer, which is also the only
// arrangement that proves the bytes come back at all.
func hubServer(t *testing.T, upstream string, viewers web.ViewerSource) string {
	t.Helper()

	srv := httptest.NewServer(riverHandler(t, upstream, viewers))
	t.Cleanup(srv.Close)
	return srv.URL
}

// hubResponse is a finished answer: read and closed here, so no test has to
// remember to, and none of them holds an open body while asserting.
type hubResponse struct {
	Status int
	Header http.Header
	Body   string
}

// hubRequest is one signed-in request to the running web role, following no
// redirect: a redirect is an answer these tests want to see, not follow.
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

// The whole point of proxying rather than linking: the browser talks to this
// role, and the dashboard's own address never has to be reachable from it.
func TestRiverEmbedProxiesTheRequestThroughWithItsPathIntact(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, fixture.SignedInViewers())

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusOK, res.Status)
	require.Equal(t, `{"available":0}`, res.Body)
	require.Equal(t, []string{view.RiverEmbedPrefix + "/api/states"}, up.seenPaths(),
		"the path goes upstream unchanged: the dashboard is started on this same prefix, "+
			"so nothing here rewrites it")
}

// The session cookie is this role's own secret. The dashboard has no use for
// it and is a third-party process, so it must not see one.
func TestRiverEmbedForwardsNoSessionCookieUpstream(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, fixture.SignedInViewers())

	hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, []string{""}, up.seenCookies(),
		"the request carried am_session and it must be stripped before it leaves")
}

// A cookie from upstream would land on this origin, which is where the session
// cookie lives.
func TestRiverEmbedDropsUpstreamSetCookie(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, fixture.SignedInViewers())

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Empty(t, res.Header.Values("Set-Cookie"),
		"the upstream set river_pref and it must not reach this origin")
}

// River's own api can cancel, retry and delete jobs and pause queues. None of
// that writes this hub's audit row, and constitution principle IV calls a
// state change with no audit row incomplete — so the proxy reads and does not
// write, and the refusal happens here rather than upstream.
func TestRiverEmbedRefusesEveryVerbThatCouldChangeTheQueue(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, fixture.SignedInViewers())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			res := hubRequest(t, method, hub+view.RiverEmbedPrefix+"/api/jobs/cancel",
				strings.NewReader(`{"jobIDs":[1]}`))

			require.Equal(t, http.StatusMethodNotAllowed, res.Status)
			require.Empty(t, up.seenPaths(), "nothing reached the dashboard")
		})
	}
}

// The api is not in the proxy's path, so this check is the only one there is.
func TestRiverEmbedRefusesARoleThatMayNotReadTheQueue(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, readOnlyViewers())

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusForbidden, res.Status)
	require.Empty(t, up.seenPaths(), "a refused viewer's request never reaches the dashboard")
}

// A hub with no dashboard has no such path, rather than a path that answers
// with an error naming a service the operator never deployed.
func TestRiverEmbedIsNotFoundWhenNoDashboardIsConfigured(t *testing.T) {
	hub := hubServer(t, "", fixture.SignedInViewers())

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusNotFound, res.Status)
}

// An unreachable dashboard is a 502, not a blank frame: the screen around it
// rendered fine, so silence inside would read as an empty queue.
func TestRiverEmbedAnswersBadGatewayWhenTheDashboardIsUnreachable(t *testing.T) {
	up := newRiverUpstream(t)
	upstream := up.URL
	up.Close()
	hub := hubServer(t, upstream, fixture.SignedInViewers())

	res := hubRequest(t, http.MethodGet, hub+view.RiverEmbedPrefix+"/api/states", http.NoBody)

	require.Equal(t, http.StatusBadGateway, res.Status)
}

// The screen itself renders for a refused viewer — with the reason, not a
// frame and not a 403 page. The sidebar entry led here, and a dead end that
// explains itself is the point of showing the entry at all.
func TestRiverScreenExplainsItselfInsteadOfRenderingAnEmptyFrame(t *testing.T) {
	up := newRiverUpstream(t)

	t.Run("a role that may not read the queue", func(t *testing.T) {
		body := get(t, riverHandler(t, up.URL, readOnlyViewers()), "/river").Body.String()

		require.Contains(t, body, `id="river-gate"`)
		require.Contains(t, body, "may not read the queue")
		require.NotContains(t, body, `id="river-frame"`)
	})

	t.Run("no dashboard configured", func(t *testing.T) {
		body := get(t, riverHandler(t, "", fixture.SignedInViewers()), "/river").Body.String()

		require.Contains(t, body, `id="river-gate"`)
		require.Contains(t, body, "AGENT_MANAGER_RIVER_UI_URL")
		require.NotContains(t, body, `id="river-frame"`)
	})
}

// Signed out is the guard's business, not this screen's: no session means the
// sign-in screen, and the dashboard's bytes are never reached at all.
func TestRiverIsBehindTheSameGuardAsEveryOtherScreen(t *testing.T) {
	up := newRiverUpstream(t)
	hub := hubServer(t, up.URL, fixture.SignedOutViewers())

	for _, path := range []string{"/river", view.RiverEmbedPrefix + "/api/states"} {
		res := hubRequest(t, http.MethodGet, hub+path, http.NoBody)

		require.Equal(t, http.StatusFound, res.Status, path)
		require.True(t, strings.HasPrefix(res.Header.Get("Location"), "/auth/signin"),
			"%s redirected to %q", path, res.Header.Get("Location"))
		require.Empty(t, up.seenPaths())
	}
}
