package web

// An internal test so an expired round trip can be sealed with the product's own
// sealRound, rather than reimplementing (and pinning) the cookie format here.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/fakeapi"
	"agent-manager/internal/web/hub"
)

// recordingProvider is an AuthProvider that records calls, so "no code was
// exchanged" can be asserted.
type recordingProvider struct {
	idToken string

	states     []string
	challenges []string
	exchanges  []exchanged
	verified   []string
}

type exchanged struct {
	Code     string
	Verifier string
}

func (p *recordingProvider) Reachable(context.Context) error { return nil }

func (p *recordingProvider) AuthorizationURL(_ context.Context, state, challenge string) (string, error) {
	p.states = append(p.states, state)
	p.challenges = append(p.challenges, challenge)
	return "https://idp.invalid/authorize?state=" + state, nil
}

func (p *recordingProvider) Exchange(_ context.Context, code, verifier string) (string, error) {
	p.exchanges = append(p.exchanges, exchanged{Code: code, Verifier: verifier})
	return p.idToken, nil
}

func (p *recordingProvider) VerifyIDToken(_ context.Context, idToken string) error {
	p.verified = append(p.verified, idToken)
	return nil
}

type signInHarness struct {
	server   *Server
	handler  http.Handler
	provider *recordingProvider
	api      *fakeapi.API
}

func fakeHub(t *testing.T) (*fakeapi.API, *hub.Client) {
	t.Helper()
	api := fakeapi.New(t)
	client, err := hub.New(api.URL, hub.WithSessionMintSecret("a-mint-secret"))
	require.NoError(t, err)
	return api, client
}

func newSignInHarness(t *testing.T) signInHarness {
	t.Helper()

	provider := &recordingProvider{idToken: "an.id.token"}
	api, client := fakeHub(t)
	server := New(Deps{Hub: client, Auth: provider, Log: zerolog.Nop()}, Options{
		// Fixed, so a test can seal a cookie refused for its age alone.
		OIDCCookieKey: []byte("a-known-key-for-the-round-trip-cookie"),
	})

	return signInHarness{server: server, handler: server.Handler(), provider: provider, api: api}
}

// begin runs the outward leg and returns the sealed cookie and its opened round.
func (h signInHarness) begin(t *testing.T, rawReturn string) (string, oidcRound) {
	t.Helper()

	target := "/auth/login"
	if rawReturn != "" {
		target += "?return=" + rawReturn
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, http.NoBody))
	require.Equal(t, http.StatusFound, rec.Code, "the outward leg is a redirect to the provider")

	sealed := cookieNamed(t, rec, oidcCookie)
	require.NotEmpty(t, sealed, "no round-trip cookie was set, so nothing can come back")

	round, opened := h.server.openRound(sealed)
	require.True(t, opened, "the server would not open the cookie it just sealed")
	return sealed, round
}

func (h signInHarness) complete(t *testing.T, sealed string, query map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	target := "/auth/callback"
	if len(query) > 0 {
		parts := make([]string, 0, len(query))
		for key, value := range query {
			parts = append(parts, key+"="+value)
		}
		target += "?" + strings.Join(parts, "&")
	}

	req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	if sealed != "" {
		req.AddCookie(&http.Cookie{Name: oidcCookie, Value: sealed})
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie.Value
		}
	}
	return ""
}

// TestTheReturnTargetIsALocalPathOrNothing checks the Location of a completed
// sign-in, the hop a browser actually follows, and the sealed cookie, so an
// attacker's URL is refused on the way in too.
func TestTheReturnTargetIsALocalPathOrNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		// raw is written already-encoded, as it arrives in a query string.
		raw  string
		want string
	}{
		{name: "a bare path is kept", raw: "%2Fscanner", want: "/scanner"},
		{
			name: "a path keeps its query and its fragment",
			raw:  "%2Fprofiles%2Fplatform-engineer%3Ftab%3Dpackages%23top",
			want: "/profiles/platform-engineer?tab=packages#top",
		},
		{name: "nothing at all falls back", raw: "", want: "/"},
		{
			// The one every "starts with a slash" check lets through.
			name: "a scheme-relative url is refused",
			raw:  "%2F%2Fevil.example%2Fsignin",
			want: "/",
		},
		{
			// The same trick against a browser that normalises the backslash.
			name: "a backslash authority is refused",
			raw:  "%2F%5Cevil.example",
			want: "/",
		},
		{name: "three slashes are refused too", raw: "%2F%2F%2Fevil.example", want: "/"},
		{name: "an absolute url is refused", raw: "https%3A%2F%2Fevil.example%2Fx", want: "/"},
		{name: "an authority with credentials is refused", raw: "%2F%2Fuser%40evil.example", want: "/"},
		{name: "a bare host is refused", raw: "evil.example", want: "/"},
		{name: "a relative path with no leading slash is refused", raw: "catalog", want: "/"},
		{
			// Response splitting: this reaches a Location header.
			name: "a target carrying CRLF is refused",
			raw:  "%2Fscanner%0D%0ASet-Cookie%3A+am_session%3Dstolen",
			want: "/",
		},
		{name: "a target carrying a NUL is refused", raw: "%2Fscanner%00", want: "/"},
		{name: "a target longer than the bound is refused", raw: "%2F" + strings.Repeat("a", 2048), want: "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignInHarness(t)
			sealed, round := h.begin(t, tc.raw)

			require.Equal(t, tc.want, round.Return,
				"the target was sealed into the cookie unvalidated, so it is already off this origin")

			rec := h.complete(t, sealed, map[string]string{"state": round.State, "code": "the-code"})
			require.Equal(t, http.StatusFound, rec.Code)
			require.Equal(t, tc.want, rec.Header().Get("Location"))
			require.NotEmpty(t, cookieNamed(t, rec, sessionCookie), "the sign-in itself must still complete")
		})
	}
}

// TestNoBrokenRoundTripReachesTheExchangeOrIssuesASession: each callback must
// stop at the state check. The `error` parameter is read only after that check,
// or /auth/callback would publish arbitrary copy on this origin.
func TestNoBrokenRoundTripReachesTheExchangeOrIssuesASession(t *testing.T) {
	for _, tc := range []struct {
		name string
		// mutate returns the cookie to send and the query to send it with.
		mutate func(t *testing.T, h signInHarness, sealed string, round oidcRound) (string, map[string]string)
	}{
		{
			name: "no cookie at all",
			mutate: func(_ *testing.T, _ signInHarness, _ string, round oidcRound) (string, map[string]string) {
				return "", map[string]string{"state": round.State, "code": "the-code"}
			},
		},
		{
			name: "a cookie this role did not sign",
			mutate: func(_ *testing.T, _ signInHarness, sealed string, round oidcRound) (string, map[string]string) {
				body, _, _ := strings.Cut(sealed, ".")
				return body + ".YWJjZGVmZ2hpamtsbW5vcA", map[string]string{
					"state": round.State, "code": "the-code",
				}
			},
		},
		{
			name: "a state that is not the one in the cookie",
			mutate: func(_ *testing.T, _ signInHarness, sealed string, round oidcRound) (string, map[string]string) {
				return sealed, map[string]string{"state": round.State + "x", "code": "the-code"}
			},
		},
		{
			name: "no state at all, against a cookie that holds one",
			mutate: func(_ *testing.T, _ signInHarness, sealed string, _ oidcRound) (string, map[string]string) {
				return sealed, map[string]string{"code": "the-code"}
			},
		},
		{
			name: "a round trip left open too long",
			mutate: func(t *testing.T, h signInHarness, _ string, round oidcRound) (string, map[string]string) {
				t.Helper()
				// Validly signed but refused: the browser's Max-Age cannot be relied on.
				round.Issued = time.Now().Add(-2 * oidcCookieTTL).Unix()
				stale, err := h.server.sealRound(round)
				require.NoError(t, err)
				return stale, map[string]string{"state": round.State, "code": "the-code"}
			},
		},
		{
			name: "a provider refusal arriving with no usable round trip",
			mutate: func(_ *testing.T, _ signInHarness, _ string, _ oidcRound) (string, map[string]string) {
				return "", map[string]string{
					"error":             "access_denied",
					"error_description": "the+directory+said+no",
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignInHarness(t)
			sealed, round := h.begin(t, "%2Fscanner")

			cookie, query := tc.mutate(t, h, sealed, round)
			rec := h.complete(t, cookie, query)

			require.Equal(t, http.StatusOK, rec.Code, "a refusal renders the sign-in screen rather than redirecting")
			require.Contains(t, rec.Body.String(), noticeStaleRound,
				"every one of these is one outcome and one screen; "+
					"telling them apart would tell whoever caused it")

			require.Empty(t, h.provider.exchanges, "a code was exchanged for a round trip that did not verify")
			require.Empty(t, h.provider.verified)
			require.Empty(t, h.api.Calls("createSession"), "a session was minted for a round trip that did not verify")
			require.Empty(t, cookieNamed(t, rec, sessionCookie), "a session cookie was issued")
		})
	}
}

// Uses a round trip that verifies so the provider's detail actually reaches the page.
func TestProviderRefusalDetailIsEscapedOnTheSignInScreen(t *testing.T) {
	h := newSignInHarness(t)
	sealed, round := h.begin(t, "%2Fscanner")

	rec := h.complete(t, sealed, map[string]string{
		"state":             round.State,
		"error":             "access_denied",
		"error_description": url.QueryEscape(`<script>alert(1)</script>`),
	})

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, noticeProviderRefused)
	require.Contains(t, body, "signin-provider-detail")
	require.NotContains(t, body, "<script>alert(1)</script>",
		"the provider's own words must reach the page escaped, not raw")
	require.Contains(t, body, "&lt;script&gt;")
}

// Clearing the cookie without telling the api would leave the session live for
// anyone else holding the token.
func TestSignOutExpiresTheSessionServerSideAndClearsTheCookie(t *testing.T) {
	api, client := fakeHub(t)
	h := New(Deps{Hub: client, Log: zerolog.Nop()}, Options{}).Handler()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "the-browsers-own-session-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	signedOut := api.Calls("deleteSession")
	require.Len(t, signedOut, 1, "the api must be told to expire this browser's own session")
	require.Equal(t, "Bearer the-browsers-own-session-token", signedOut[0].Header.Get("Authorization"))
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/auth/signin", rec.Header().Get("Location"))

	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			found = true
			require.Negative(t, c.MaxAge, "the cookie must be told to expire, not merely emptied")
		}
	}
	require.True(t, found, "logout must set the cookie header at all, to overwrite the browser's copy")
}

// The callback deletes the round-trip cookie first, so a refresh or back button
// arrives without it; that is what makes the round trip single use.
func TestTheRoundTripIsSingleUseBecauseTheCookieIsGoneAfterIt(t *testing.T) {
	h := newSignInHarness(t)
	sealed, round := h.begin(t, "%2Fscanner")
	query := map[string]string{"state": round.State, "code": "the-code"}

	first := h.complete(t, sealed, query)
	require.Equal(t, http.StatusFound, first.Code)
	require.Equal(t, "/scanner", first.Header().Get("Location"))
	require.Len(t, h.provider.exchanges, 1)
	require.Equal(t, round.Verifier, h.provider.exchanges[0].Verifier,
		"the PKCE verifier came out of the cookie rather than off the wire")
	minted := h.api.Calls("createSession")
	require.Len(t, minted, 1)
	var body apiclient.CreateSessionJSONRequestBody
	minted[0].Decode(t, &body)
	require.Equal(t, "an.id.token", body.IdToken, "the raw ID token is what the api is asked to mint for")
	require.Equal(t, h.api.Data.Session.Token, cookieNamed(t, first, sessionCookie))

	deleted := false
	for _, cookie := range first.Result().Cookies() {
		if cookie.Name == oidcCookie && cookie.MaxAge < 0 {
			deleted = true
		}
	}
	require.True(t, deleted, "the round-trip cookie survived the callback, so a replay has one to send")

	second := h.complete(t, "", query)
	require.Equal(t, http.StatusOK, second.Code)
	require.Contains(t, second.Body.String(), noticeStaleRound)
	require.Len(t, h.provider.exchanges, 1, "the replayed callback reached the exchange")
	require.Len(t, h.api.Calls("createSession"), 1, "the replayed callback minted a second session")
}

// A reused state would make the state checks vacuous, and a challenge equal to
// the verifier would make PKCE decorative.
func TestTheOutwardLegSendsAFreshStateAndAChallengeItKeepsNoSecretFor(t *testing.T) {
	h := newSignInHarness(t)

	_, first := h.begin(t, "%2Fscanner")
	_, second := h.begin(t, "%2Fscanner")

	require.NotEqual(t, first.State, second.State, "two sign-in attempts, two states")
	require.NotEqual(t, first.Verifier, second.Verifier)
	require.Len(t, h.provider.states, 2)
	require.Equal(t, []string{first.State, second.State}, h.provider.states,
		"the state sent to the provider is the one sealed in the cookie")

	for i, challenge := range h.provider.challenges {
		require.NotEmpty(t, challenge)
		require.NotContains(t, []string{first.Verifier, second.Verifier}, challenge,
			"attempt %d sent the verifier itself as the challenge, so the redirect URI carries the secret", i)
	}
}

func TestARefusedMintIssuesNoSession(t *testing.T) {
	h := newSignInHarness(t)
	h.api.Fail("createSession", http.StatusUnauthorized)
	sealed, round := h.begin(t, "%2Fscanner")

	rec := h.complete(t, sealed, map[string]string{"state": round.State, "code": "the-code"})

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "The hub could not complete sign-in.")
	require.Empty(t, cookieNamed(t, rec, sessionCookie))
	require.Len(t, h.api.Calls("createSession"), 1)
}

func TestASharedCookieKeyLetsAnotherReplicaFinishTheSignIn(t *testing.T) {
	first := newSignInHarness(t)
	sealed, _ := first.begin(t, "")

	_, client := fakeHub(t)
	replica := New(Deps{Hub: client, Auth: &recordingProvider{}, Log: zerolog.Nop()},
		Options{OIDCCookieKey: []byte("a-known-key-for-the-round-trip-cookie")})
	_, opened := replica.openRound(sealed)
	require.True(t, opened, "a replica holding the same key must accept the round trip")

	stranger := New(Deps{Hub: client, Auth: &recordingProvider{}, Log: zerolog.Nop()}, Options{})
	_, opened = stranger.openRound(sealed)
	require.False(t, opened, "a per-process key must refuse another process's round trip")
}
