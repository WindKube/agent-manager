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

// sessionCookie carries the browser's opaque session token.
//
// The callback in auth.go is the ONLY thing that sets it, and that is not a
// convention: a session token exists because the api resolved a row someone
// created by signing in, and this role cannot reach that table (principle II).
// What is written here is a copy of an answer, never a credential of this role's
// own making.
const sessionCookie = "am_session"

// session returns the request's context carrying whatever session the browser
// sent. There is no fallback and there must not be one — a web role that could
// substitute a credential of its own would be a second door to the datastore
// with a different lock.
func session(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	token, err := c.Cookie(sessionCookie)
	if err != nil {
		return ctx
	}
	return view.WithToken(ctx, token)
}

// issueSession puts a freshly minted session in the browser, per
// contracts/auth.md's cookie table (FR-110).
//
// Max-Age comes from the api's own ExpiresIn and NOT from ExpiresAt minus a local
// clock. The two roles are two containers: across a skewed pair, a computed TTL
// gives a cookie that either outlives its row — which reads to a person as being
// signed out at random, on a page that was working a second ago — or dies early
// for no visible reason. ExpiresAt is for the log line and for matching the row.
func (s *Server) issueSession(c *gin.Context, minted hub.Session) {
	// A non-positive TTL means the api and this role disagree about what a session
	// is. A session cookie (no Max-Age) is the honest fallback: it lasts as long as
	// the window, and a negative Max-Age would delete the cookie a moment after
	// issuing it, which reads as a sign-in that did nothing.
	maxAge := int(minted.ExpiresIn.Seconds())
	if maxAge < 1 {
		maxAge = 0
	}

	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure comes from the configured public base URL.
		Name:  sessionCookie,
		Value: minted.Token,
		Path:  "/",
		// Every screen needs it, so the path is the whole origin.
		MaxAge: maxAge,
		// Script must not read it: the plaintext token exists here and nowhere else
		// in the world, since the api stores only its hash.
		HttpOnly: true,
		Secure:   s.secureCookie,
		// Lax, not Strict. The last hop of sign-in is a top-level GET navigation the
		// provider caused, which Lax permits and Strict would drop — and dropping it
		// there is a sign-in that appears to succeed and lands on a sign-in screen.
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSession removes this browser's copy of the token.
//
// It is a courtesy and not the mechanism: sign-out is server-side (FR-114), the
// api expires the row, and a cookie cleared without that expiry would leave a
// token that still works for anyone else holding it.
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

// secureCookie decides the Secure flag from the CONFIGURED public base URL
// rather than from the request (contracts/auth.md).
//
// The difference matters when something else terminates TLS: a proxy forwards
// plain http to this process, so `c.Request.TLS != nil` is false on every request
// of a deployment that is served over https, and the session cookie would lose
// Secure exactly where it is needed. Configuration is a value an operator states
// once; a request header is a value a client sends.
//
// Unparseable or empty is false, because the quickstart's origin is not https and
// a Secure cookie there simply never comes back — a sign-in that silently does
// not persist is worse than one that is honestly unencrypted on loopback.
func secureCookie(publicBaseURL string) bool {
	parsed, err := url.Parse(publicBaseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}
