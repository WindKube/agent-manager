package web

import (
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
)

// FR-054: the theme is persisted per viewer and read server-side, so the first
// byte of HTML already carries data-sm-theme and there is no flash of the wrong
// theme. A cookie is the whole mechanism — no client storage, no second source
// of truth.
const themeCookie = "am_theme"

const (
	themeLight = "light"
	themeDark  = "dark"
)

// themeFor resolves the theme for one request: an explicit ?theme= wins but is
// NOT persisted (the screenshot harness needs to ask for one render in each
// theme without touching the viewer's choice), then the cookie, then light.
func themeFor(c *gin.Context) string {
	if t := normaliseTheme(c.Query("theme")); t != "" {
		return t
	}
	if cookie, err := c.Cookie(themeCookie); err == nil {
		if t := normaliseTheme(cookie); t != "" {
			return t
		}
	}
	return themeLight
}

func normaliseTheme(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case themeDark:
		return themeDark
	case themeLight:
		return themeLight
	default:
		return ""
	}
}

func otherTheme(theme string) string {
	if theme == themeDark {
		return themeLight
	}
	return themeDark
}

// setTheme persists the choice and returns the viewer to where they were.
func (s *Server) setTheme(c *gin.Context) {
	theme := normaliseTheme(c.PostForm("theme"))
	if theme == "" {
		theme = themeDark
	}

	// gosec G124 wants a literal `Secure: true` and cannot see the conditional
	// below it. Hardcoding it would be wrong here: see the field's comment.
	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure is set from c.Request.TLS.
		Name:  themeCookie,
		Value: theme,
		Path:  "/",
		// A year: a viewer's theme is not a session. HttpOnly because nothing
		// client-side reads it — the server renders the attribute — so there is no
		// reason to expose it to script.
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		// Secure follows the request rather than being hardcoded: the quickstart is
		// http://localhost, where a Secure cookie would simply never come back and
		// the theme would silently not persist.
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	c.Redirect(http.StatusSeeOther, localPath(c.PostForm("return")))
}

// localPath refuses anything that is not a path on this origin. A redirect target
// taken from a form field is an open-redirect vector, and "//evil.example" is a
// protocol-relative URL that a naive "starts with /" check lets through.
func localPath(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/catalog"
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "/catalog"
	}
	return raw
}

// shell assembles the layout props for one request.
func (s *Server) shell(c *gin.Context, title, active string) components.Shell {
	theme := themeFor(c)
	return components.Shell{
		Title: title,
		// The ONLY source of an identity on any screen (FR-116). The zero value is
		// the signed-out state and renders no chip at all; nothing else may supply
		// one, and there is no default.
		Viewer:   viewerFor(c),
		Theme:    theme,
		Next:     otherTheme(theme),
		Active:   active,
		Return:   localPath(c.Request.URL.RequestURI()),
		AppCSS:   assetURL("app.css"),
		AppJS:    assetURL("app.js"),
		VendorJS: assetURL("vendor/datastar.js"),
	}
}

// render writes one full page: the shell with a screen inside it.
func (s *Server) render(c *gin.Context, status int, title, active string, body templ.Component) {
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")

	ctx := templ.WithChildren(c.Request.Context(), body)
	if err := components.Layout(s.shell(c, title, active)).Render(ctx, c.Writer); err != nil {
		// The response is already partially written, so the only useful thing left
		// is a log line: the status cannot be changed now.
		logFrom(c).Error().Err(err).Str("screen", title).Msg("render page")
	}
}
