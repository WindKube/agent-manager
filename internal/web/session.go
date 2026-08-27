package web

import (
	"context"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/view"
)

// sessionCookie carries the browser's opaque session token.
//
// Nothing sets it yet — browser login is T090 (US6), and it is the ONLY thing
// that may: a session token exists because auth.Sessions resolved a row someone
// created by signing in, and this role cannot reach that table (principle II).
// Reading the cookie here rather than waiting for T090 is what makes the api's
// bearer requirement survivable: the mechanism that carries a person's own
// credential to the api is in place, and login fills it.
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
