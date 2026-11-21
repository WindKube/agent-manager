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

// sessionCookie carries the opaque session token minted by the api; only the
// auth callback sets it.
const sessionCookie = "am_session"

// session has no fallback credential: one would be a second door to the datastore.
func session(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	token, err := c.Cookie(sessionCookie)
	if err != nil {
		return ctx
	}
	return view.WithToken(ctx, token)
}

// issueSession takes Max-Age from the api's ExpiresIn rather than ExpiresAt
// minus a local clock, which clock skew would distort.
func (s *Server) issueSession(c *gin.Context, minted hub.Session) {
	// A non-positive TTL falls back to a browser-session cookie; a negative
	// Max-Age would delete it immediately.
	maxAge := int(minted.ExpiresIn.Seconds())
	if maxAge < 1 {
		maxAge = 0
	}

	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:     sessionCookie,
		Value:    minted.Token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secureCookie,
		// Strict would drop the cookie on the provider's redirect back.
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSession is a courtesy: sign-out is the api expiring the row server-side.
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

// secureCookie uses the configured public base URL, not the request: behind a
// TLS-terminating proxy c.Request.TLS is nil even in production.
func secureCookie(publicBaseURL string) bool {
	parsed, err := url.Parse(publicBaseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}
