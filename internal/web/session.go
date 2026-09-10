package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// sessionCookie carries the browser's opaque session token. Only the callback
// in auth.go sets it: this role cannot reach the session table, so what is
// written here is a copy of an answer, never a credential of its own making.
const sessionCookie = "am_session"

// session returns the request's context carrying whatever session the browser
// sent. There is no fallback: a web role that could substitute a credential of
// its own would be a second door to the datastore with a different lock.
func session(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	token, err := c.Cookie(sessionCookie)
	if err != nil {
		return ctx
	}
	return view.WithToken(ctx, token)
}

// issueSession puts a freshly minted session in the browser. Max-Age comes
// from the api's own ExpiresIn, not ExpiresAt minus a local clock: across a
// skewed pair, a computed TTL could outlive the row or die early for no
// visible reason.
func (s *Server) issueSession(c *gin.Context, minted hub.Session) {
	// A non-positive TTL means the api and this role disagree about what a
	// session is. Falling back to a session cookie (no Max-Age) beats a
	// negative Max-Age, which would delete the cookie a moment after issuing it.
	maxAge := int(minted.ExpiresIn.Seconds())
	if maxAge < 1 {
		maxAge = 0
	}

	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     sessionCookie,
		Value:    minted.Token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true, // script must not read the plaintext token
		Secure:   s.secureCookie,
		// Lax, not Strict: the last hop of sign-in is a top-level GET navigation
		// the provider caused, which Strict would drop.
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSession removes this browser's copy of the token. It is a courtesy,
// not the mechanism: sign-out is server-side, the api expires the row, and a
// cookie cleared without that expiry would leave a token that still works.
func (s *Server) clearSession(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// secureCookie decides the Secure flag from the CONFIGURED public base URL,
// not the request: behind a TLS-terminating proxy, `c.Request.TLS != nil` is
// false even in production, which would lose Secure exactly where it matters.
// Unparseable or empty is false, since a Secure cookie never comes back over
// the quickstart's plain-http origin.
func secureCookie(publicBaseURL string) bool {
	parsed, err := url.Parse(publicBaseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}
