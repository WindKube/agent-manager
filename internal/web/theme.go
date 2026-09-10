package web

import (
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// The theme is persisted per viewer and read server-side, so the first byte
// of HTML already carries data-sm-theme and there is no flash of the wrong
// theme. A cookie is the whole mechanism.
const themeCookie = "am_theme"

const (
	themeLight = "light"
	themeDark  = "dark"
)

// themeFor resolves the theme for one request: an explicit ?theme= wins but
// is NOT persisted, then the cookie, then light.
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

	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure is set from c.Request.TLS.
		Name:     themeCookie,
		Value:    theme,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // a viewer's theme is not a session
		HttpOnly: true,
		// Follows the request rather than hardcoded true: over http://localhost
		// a Secure cookie would never come back and the theme would silently
		// not persist.
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	c.Redirect(http.StatusSeeOther, localPath(c.PostForm("return")))
}

// localPath refuses anything that is not a path on this origin: a redirect
// target from a form field is an open-redirect vector, and "//evil.example"
// is a protocol-relative URL a naive "starts with /" check lets through.
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
		// The ONLY source of an identity on any screen. The zero value is the
		// signed-out state and renders no chip; there is no default.
		Viewer:   viewerFor(c),
		Badges:   s.badges(c),
		Theme:    theme,
		Next:     otherTheme(theme),
		Active:   active,
		Return:   localPath(c.Request.URL.RequestURI()),
		AppCSS:   assetURL("app.css"),
		AppJS:    assetURL("app.js"),
		VendorJS: assetURL("vendor/datastar.js"),
	}
}

// badges reads the sidebar's three counts for one page render — once per
// FULL page, never on a datastar fragment update. A failure is not an error
// to render: it returns nil, the sidebar shows no counts, and the screen the
// reader asked for still arrives. Three zeroes would be the same class of lie
// as the compiled-in counts these replaced.
func (s *Server) badges(c *gin.Context) *view.Badges {
	viewer := viewerFor(c)
	if s.deps.Badges == nil || viewer == nil || !viewer.HasRole {
		// A viewer with no role may see nothing, so this is not a courtesy:
		// the counts are scoped to what the caller may see.
		return nil
	}

	counts, err := s.deps.Badges.Badges(session(c))
	if err != nil {
		logFrom(c).Debug().Err(err).Msg("read the sidebar counts")
		return nil
	}
	return &view.Badges{
		Packages:     counts.Packages,
		Profiles:     counts.Profiles,
		OpenFindings: counts.OpenFindings,
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
