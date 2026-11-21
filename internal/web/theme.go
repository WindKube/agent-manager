package web

import (
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

// themeCookie is read server-side so the first byte of HTML carries the theme, with no flash.
const themeCookie = "am_theme"

const (
	themeLight = "light"
	themeDark  = "dark"
)

// themeFor prefers ?theme= (not persisted), then the cookie, then light.
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

func (s *Server) setTheme(c *gin.Context) {
	theme := normaliseTheme(c.PostForm("theme"))
	if theme == "" {
		theme = themeDark
	}

	http.SetCookie(c.Writer, &http.Cookie{ //nolint:gosec // Secure is set from c.Request.TLS.
		Name:     themeCookie,
		Value:    theme,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		// Not hardcoded: over http://localhost a Secure cookie would never come back.
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	c.Redirect(http.StatusSeeOther, localPath(c.PostForm("return")))
}

// localPath refuses anything but a path on this origin; "//evil.example" is
// protocol-relative and slips past a naive prefix check.
func localPath(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/catalog"
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "/catalog"
	}
	return raw
}

func (s *Server) shell(c *gin.Context, title, active string) components.Shell {
	theme := themeFor(c)
	return components.Shell{
		Title: title,
		// The only source of identity on any screen; nil renders signed out.
		Viewer:   viewerFor(c),
		Badges:   s.badges(c),
		Theme:    theme,
		Next:     otherTheme(theme),
		Active:   active,
		Return:   localPath(c.Request.URL.RequestURI()),
		AppCSS:   assetURL("app.css"),
		AppJS:    assetURL("app.js"),
		VendorJS: assetURL("vendor/datastar.js"),
		NavGate:  s.navGate(c),
	}
}

// navGate gives the reason a sidebar entry is disabled; only the River Dashboard has one.
func (s *Server) navGate(c *gin.Context) map[string]string {
	river := view.RiverFor(viewerFor(c), s.riverUI != nil)
	if river.Gate == "" {
		return nil
	}
	return map[string]string{"river": river.Gate}
}

// badges is read once per full page render. A failure returns nil so the
// sidebar shows no counts rather than misleading zeroes.
func (s *Server) badges(c *gin.Context) *view.Badges {
	viewer := viewerFor(c)
	if viewer == nil || !viewer.HasRole {
		return nil
	}

	counts, err := s.deps.Hub.Badges(session(c))
	if err != nil {
		logFrom(c).Debug().Err(err).Msg("read the sidebar counts")
		return nil
	}
	return &counts
}

func (s *Server) render(c *gin.Context, status int, title, active string, body templ.Component) {
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")

	ctx := templ.WithChildren(c.Request.Context(), body)
	if err := components.Layout(s.shell(c, title, active)).Render(ctx, c.Writer); err != nil {
		// Already partially written, so the status cannot change.
		logFrom(c).Error().Err(err).Str("screen", title).Msg("render page")
	}
}
