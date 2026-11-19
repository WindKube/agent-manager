package web_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTheThreeOutcomesOfACatalogReadRenderDifferently keeps three rowless pages
// distinguishable from each other.
//
// Signed out, api down and genuinely empty all produce a page with no rows, and
// any two of them collapsing into one is the bug: an outage that renders as an
// empty hub is never reported, and a login that renders as an empty hub is never
// performed. So each is pinned by BOTH its status and something only it says.
func TestTheThreeOutcomesOfACatalogReadRenderDifferently(t *testing.T) {
	const signInCopy = "Sign in to browse the catalog"
	const emptyCopy = "Nothing matches these filters"

	t.Run("signed out is a screen, at 200, that says so", func(t *testing.T) {
		api, h := newServer(t)
		api.Fail("listPackages", http.StatusUnauthorized)
		rec := get(t, h, "/catalog")

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.Contains(t, body, signInCopy)
		require.NotContains(t, body, emptyCopy,
			"a signed-out reader must not be told their filters matched nothing")
		require.Contains(t, body, "Signed out",
			"nor must the count line claim the catalog holds 0 results")
	})

	t.Run("an unreachable api is a 502 and renders no catalog at all", func(t *testing.T) {
		api, h := newServer(t)
		api.Fail("listPackages", http.StatusServiceUnavailable)
		rec := get(t, h, "/catalog")

		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.NotContains(t, rec.Body.String(), signInCopy,
			"an outage must not be dressed as a login")
	})

	t.Run("a genuinely empty catalog is a 200 with the empty state", func(t *testing.T) {
		api, h := newServer(t)
		api.Data.Packages = nil
		rec := get(t, h, "/catalog")

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.Contains(t, body, emptyCopy)
		require.NotContains(t, body, signInCopy)
		require.Contains(t, body, "0 results",
			"an empty catalog is an answer and says so, unlike the signed-out screen")
	})
}

// TestTheWebRoleSendsTheCallersOwnSessionAndNothingElse follows the credential
// from the browser cookie to the api and finds nothing else on the way.
//
// Constitution principle II. auth.Sessions.Resolve is a lookup in the session
// table by hashed token, so there is no token this role could mint at boot even
// if it wanted one — but "there is nothing to forward except the cookie" has to
// be asserted, not assumed, because the failure mode is silent: a role that
// found some credential to send would work perfectly and be wrong.
func TestTheWebRoleSendsTheCallersOwnSessionAndNothingElse(t *testing.T) {
	t.Run("the browser's session cookie reaches the api", func(t *testing.T) {
		api, h := newServer(t)
		req := httptest.NewRequest(http.MethodGet, "/catalog", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "am_session", Value: "the-callers-own-session-token"})
		h.ServeHTTP(httptest.NewRecorder(), req)

		calls := api.Calls("")
		require.NotEmpty(t, calls)
		for _, call := range calls {
			require.Equalf(t, "Bearer the-callers-own-session-token", call.Header.Get("Authorization"),
				"%s carried something other than exactly the caller's cookie", call.Operation)
		}
		require.Len(t, api.Calls("listPackages"), 1)
	})

	t.Run("a request with no cookie never reaches the api at all", func(t *testing.T) {
		// This assertion got STRONGER when the guard arrived, and the change is worth
		// stating. It used to assert the source was called with an empty token — that
		// the role forwarded nothing rather than substituting some credential of its
		// own. Now the guard refuses the request before any source is consulted, so
		// the property holds one layer earlier: there is no code path from an
		// unauthenticated request to the api at all, which is a stronger form of the
		// same principle-II claim than "it calls the api with an empty token".
		api, h := newServer(t)
		rec := getSignedOut(t, h, "/catalog")

		require.Empty(t, api.Calls(""), "an unauthenticated request must not reach the api")
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, "/auth/signin?return=%2Fcatalog", rec.Header().Get("Location"),
			"and it comes back to the route it asked for (FR-113, SC-105)")
	})
}

// The guard fails closed: no session and a session the api no longer knows
// both land on sign-in, and an api it cannot ask lets nobody through while
// still not claiming the person was signed out.
func TestTheGuardFailsClosed(t *testing.T) {
	t.Run("no session cookie is sent to sign in without asking the api", func(t *testing.T) {
		api, h := newServer(t)
		rec := getSignedOut(t, h, "/scanner")

		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, "/auth/signin?return=%2Fscanner", rec.Header().Get("Location"))
		require.Empty(t, api.Calls("getViewer"))
	})

	t.Run("a session the api does not recognise is sent to sign in", func(t *testing.T) {
		api, h := newServer(t)
		api.Data.SignedOut()
		rec := get(t, h, "/scanner")

		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, "/auth/signin?return=%2Fscanner", rec.Header().Get("Location"))
	})

	t.Run("an api that cannot resolve the viewer is a bad gateway, not a sign-out", func(t *testing.T) {
		api, h := newServer(t)
		api.Fail("getViewer", http.StatusServiceUnavailable)
		rec := get(t, h, "/scanner")

		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Empty(t, rec.Header().Get("Location"))
		body := rec.Body.String()
		require.Contains(t, body, "The hub&#39;s api is unavailable")
		require.NotContains(t, body, "am-viewer-name", "nobody was resolved, so no chip")
		require.Empty(t, api.Calls("scannerSummary"), "the screen behind the guard was never reached")
	})
}
