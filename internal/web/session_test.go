package web_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/web"
	"agent-manager/internal/web/fixture"
	"agent-manager/internal/web/view"
)

// sourceFunc is a CatalogSource that is whatever the test needs it to be.
type sourceFunc func(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error)

func (f sourceFunc) Catalog(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
	return f(ctx, q)
}

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
		rec := get(t, handler(t, sourceFunc(func(context.Context, view.CatalogQuery) (view.CatalogPage, error) {
			return view.CatalogPage{}, view.ErrSignedOut
		})), "/catalog")

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.Contains(t, body, signInCopy)
		require.NotContains(t, body, emptyCopy,
			"a signed-out reader must not be told their filters matched nothing")
		require.Contains(t, body, "Signed out",
			"nor must the count line claim the catalog holds 0 results")
	})

	t.Run("an unreachable api is a 502 and renders no catalog at all", func(t *testing.T) {
		rec := get(t, handler(t, sourceFunc(func(context.Context, view.CatalogQuery) (view.CatalogPage, error) {
			return view.CatalogPage{}, errors.New("dial tcp: connection refused")
		})), "/catalog")

		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.NotContains(t, rec.Body.String(), signInCopy,
			"an outage must not be dressed as a login")
	})

	t.Run("a genuinely empty catalog is a 200 with the empty state", func(t *testing.T) {
		rec := get(t, handler(t, sourceFunc(func(_ context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
			return view.CatalogPage{Query: q.Normalise(), PageSize: view.DefaultPageSize}, nil
		})), "/catalog")

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		require.Contains(t, body, emptyCopy)
		require.NotContains(t, body, signInCopy)
		require.Contains(t, body, "0 results",
			"an empty catalog is an answer and says so, unlike the signed-out screen")
	})
}

// TestTheWebRoleSendsTheCallersOwnSessionAndNothingElse follows the credential
// from the browser cookie to the source and finds nothing else on the way.
//
// Constitution principle II. auth.Sessions.Resolve is a lookup in the session
// table by hashed token, so there is no token this role could mint at boot even
// if it wanted one — but "there is nothing to forward except the cookie" has to
// be asserted, not assumed, because the failure mode is silent: a role that
// found some credential to send would work perfectly and be wrong.
func TestTheWebRoleSendsTheCallersOwnSessionAndNothingElse(t *testing.T) {
	var seen []string
	source := sourceFunc(func(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error) {
		seen = append(seen, view.TokenFrom(ctx))
		return view.CatalogPage{Query: q.Normalise(), PageSize: view.DefaultPageSize}, nil
	})
	h := web.New(web.Deps{
		Catalog: source,
		Viewers: fixture.SignedInViewers(),
		Log:     zerolog.Nop(),
	}, web.Options{}).Handler()

	t.Run("the browser's session cookie reaches the source", func(t *testing.T) {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, "/catalog", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "am_session", Value: "the-callers-own-session-token"})
		h.ServeHTTP(httptest.NewRecorder(), req)

		require.Equal(t, []string{"the-callers-own-session-token"}, seen,
			"exactly the caller's cookie, and nothing this role could have minted itself")
	})

	t.Run("a request with no cookie never reaches the source at all", func(t *testing.T) {
		// This assertion got STRONGER when the guard arrived, and the change is worth
		// stating. It used to assert the source was called with an empty token — that
		// the role forwarded nothing rather than substituting some credential of its
		// own. Now the guard refuses the request before any source is consulted, so
		// the property holds one layer earlier: there is no code path from an
		// unauthenticated request to the api at all, which is a stronger form of the
		// same principle-II claim than "it calls the api with an empty token".
		seen = nil
		rec := getSignedOut(t, h, "/catalog")

		require.Empty(t, seen, "an unauthenticated request must not reach the api")
		require.Equal(t, http.StatusFound, rec.Code)
		require.Equal(t, "/auth/signin?return=%2Fcatalog", rec.Header().Get("Location"),
			"and it comes back to the route it asked for (FR-113, SC-105)")
	})
}
