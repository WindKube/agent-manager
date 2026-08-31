package web

// T030 and T031: the two ways the browser round trip is attacked, and the two
// tasks.md names as the reason /auth/login and /auth/callback cannot be trusted
// without them.
//
// An INTERNAL test, and the reason is T031's expired case. A stale round trip
// cannot be constructed from outside this package without reimplementing the
// cookie's format in the test — which would pin the format rather than the
// refusal, and would keep passing after a format change that broke every real
// browser. From in here the cookie is sealed by the product's own sealRound with
// an Issued in the past, so what is asserted is the server refusing its own
// signature over a value that is simply too old.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/hub"
)

// ---- the two stand-ins --------------------------------------------------------

// recordingProvider is an AuthProvider that remembers what was asked of it.
//
// The recording is the point rather than a convenience: "no code was exchanged"
// is the property T031 asks for, and it is only a test if something counted.
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

// recordingMinter is the api's session mint, counted. It hands back a token that
// is not a session token anywhere, because nothing in this file may care what one
// looks like — the api is what recognises them.
type recordingMinter struct {
	minted []string
}

func (m *recordingMinter) MintSession(_ context.Context, idToken string) (hub.Session, error) {
	m.minted = append(m.minted, idToken)
	return hub.Session{
		Token:     "minted-for-" + idToken,
		ExpiresAt: time.Now().Add(8 * time.Hour),
		ExpiresIn: 8 * time.Hour,
	}, nil
}

func (m *recordingMinter) SignOut(context.Context) error { return nil }

// ---- the harness --------------------------------------------------------------

type signInHarness struct {
	server   *Server
	handler  http.Handler
	provider *recordingProvider
	minter   *recordingMinter
}

func newSignInHarness(t *testing.T) signInHarness {
	t.Helper()

	provider := &recordingProvider{idToken: "an.id.token"}
	minter := &recordingMinter{}
	server := New(Deps{
		Catalog:  fixture.New(),
		Auth:     provider,
		Viewers:  fixture.SignedInViewers(),
		Sessions: minter,
		Log:      zerolog.Nop(),
	}, Options{
		// Fixed, so the test can seal a cookie this server will accept the
		// signature of and refuse for its age alone.
		OIDCCookieKey: []byte("a-known-key-for-the-round-trip-cookie"),
	})

	return signInHarness{server: server, handler: server.Handler(), provider: provider, minter: minter}
}

// begin runs the outward leg and returns the round trip the browser is now
// holding, opened, so a test can quote the state back the way a provider would.
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

// complete runs the return leg with whatever cookie and query a caller wants.
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

// ---- T030: the return-target validator ----------------------------------------

// TestTheReturnTargetIsALocalPathOrNothing is FR-113, asserted where it matters
// rather than on the validator alone.
//
// The observable is the Location header of a COMPLETED sign-in: that is the hop a
// browser actually follows, after a real sign-in, served by the real origin —
// which is what would make an open redirect here the most credible phishing
// surface this hub could have. The sealed cookie is checked too, because the
// validator runs on the way in as well and a refusal that happened only on the
// way out would leave an attacker's URL sitting in a cookie for 90 seconds.
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

// ---- T031: state handling -----------------------------------------------------

// TestNoBrokenRoundTripReachesTheExchangeOrIssuesASession is T031. Each case is a
// callback that must go no further than the state check, and "no further" is
// asserted three ways: no code exchanged, no session minted, no session cookie.
//
// The `error` parameter is checked as part of it. Its text is the only thing on
// this route that reaches the page, and it is read AFTER the state check on
// purpose — reflecting it before the round trip proved to be this hub's would make
// /auth/callback a way to publish copy on this origin under a sign-in heading.
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
				// The body kept, the signature broken: a forged round trip carrying a
				// state that would otherwise match.
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
				// This role's own signature over its own state, and refused anyway: the
				// browser enforces Max-Age and the browser is the one party in this flow
				// that cannot be relied on.
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
				"every one of these is one outcome and one screen: telling them apart on the "+
					"page would eventually mean telling them apart to whoever caused it")

			require.Empty(t, h.provider.exchanges, "a code was exchanged for a round trip that did not verify")
			require.Empty(t, h.provider.verified)
			require.Empty(t, h.minter.minted, "a session was minted for a round trip that did not verify")
			require.Empty(t, cookieNamed(t, rec, sessionCookie), "a session cookie was issued")
		})
	}
}

// TestTheRoundTripIsSingleUseBecauseTheCookieIsGoneAfterIt is the replay half of
// T031, tested with a browser's actual semantics rather than a resend of the same
// cookie.
//
// The callback deletes the round-trip cookie before it does anything else, so the
// second visit — a refresh of the callback URL, a back button, a bookmarked
// Location — arrives without it. That is what makes it single use, and it is why
// the deletion happens before the state check rather than after the mint.
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
	require.Len(t, h.minter.minted, 1)

	// What the browser holds now: the cookie was deleted by that response.
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
	require.Len(t, h.minter.minted, 1, "the replayed callback minted a second session")
}

// TestTheOutwardLegSendsAFreshStateAndAChallengeItKeepsNoSecretFor guards the
// pair the two tests above rest on: a state reused between attempts would make
// every state check above vacuous, and a challenge that was the verifier would
// make PKCE decorative.
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
