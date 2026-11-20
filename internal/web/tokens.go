package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The Service tokens screen. Creating one answers the POST with the page
// itself rather than a redirect, because the secret must never travel in a
// URL; the page is no-store for the same reason.

func (s *Server) tokens(c *gin.Context) {
	screen := s.tokenScreen(c, view.ServiceTokenForm{
		Expires: time.Now().UTC().Add(view.ServiceTokenDefaultLifetime).Format(time.DateOnly),
	})
	screen.Notice = tokensNotice(c.Query("outcome"))
	s.renderTokens(c, screen)
}

func (s *Server) tokenScreen(c *gin.Context, form view.ServiceTokenForm) view.ServiceTokens {
	today := time.Now().UTC()
	screen := view.ServiceTokens{
		Form:       form,
		MinExpires: today.AddDate(0, 0, 1).Format(time.DateOnly),
		MaxExpires: today.Add(view.ServiceTokenMaxLifetime).Format(time.DateOnly),
	}

	tokens, err := s.deps.Hub.ServiceTokens(session(c))
	if err == nil {
		screen.Tokens = tokens
		screen.Profiles, err = s.deps.Hub.Profiles(session(c))
	}
	switch {
	case err == nil:
	case errors.Is(err, view.ErrSignedOut):
		screen.SignedOut = true
	default:
		logFrom(c).Error().Err(err).Msg("load service tokens")
		screen.Unavailable = true
	}
	return screen
}

func (s *Server) renderTokens(c *gin.Context, screen view.ServiceTokens) {
	status := http.StatusOK
	switch {
	case screen.SignedOut:
		s.toSignIn(c)
		return
	case screen.Unavailable:
		status = http.StatusBadGateway
	case screen.Notice != nil && screen.Notice.Tone == "dan" && screen.Created == nil:
		status = http.StatusUnprocessableEntity
	}
	c.Header("Cache-Control", "no-store")
	s.render(c, status, "Service tokens", "tokens", components.ServiceTokensScreen(screen))
}

func (s *Server) createToken(c *gin.Context) {
	form := view.ServiceTokenForm{
		Name:        strings.TrimSpace(c.PostForm("name")),
		Profiles:    c.PostFormArray("profile"),
		ReadCatalog: c.PostForm("readCatalog") != "",
		Expires:     strings.TrimSpace(c.PostForm("expires")),
	}

	scopes := make([]string, 0, len(form.Profiles)+1)
	for _, slug := range form.Profiles {
		scopes = append(scopes, view.SyncProfileScope(slug))
	}
	if form.ReadCatalog {
		scopes = append(scopes, view.ScopeReadCatalog)
	}

	refuse := func(text string) {
		screen := s.tokenScreen(c, form)
		screen.Notice = &view.Notice{Tone: "dan", Text: text}
		s.renderTokens(c, screen)
	}
	if len(scopes) == 0 {
		refuse("Choose at least one profile to sync or the read-only catalog scope.")
		return
	}
	expires, err := time.Parse(time.DateOnly, form.Expires)
	if err != nil {
		refuse("Choose an expiry date.")
		return
	}

	created, err := s.deps.Hub.CreateServiceToken(session(c), form.Name, scopes, expires)
	var refused *hub.ServiceTokenRefusedError
	switch {
	case err == nil:
		screen := s.tokenScreen(c, view.ServiceTokenForm{
			Expires: time.Now().UTC().Add(view.ServiceTokenDefaultLifetime).Format(time.DateOnly),
		})
		screen.Created = &created
		s.renderTokens(c, screen)
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.As(err, &refused):
		refuse(refused.Detail)
	default:
		logFrom(c).Error().Err(err).Msg("create service token")
		refuse("The hub's api could not be reached, so no token was created.")
	}
}

func (s *Server) revokeToken(c *gin.Context) {
	err := s.deps.Hub.RevokeServiceToken(session(c), c.Param("id"))
	outcome := "revoked"
	switch {
	case err == nil:
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
		return
	case errors.Is(err, hub.ErrServiceTokenNotFound):
		outcome = "missing"
	default:
		logFrom(c).Error().Err(err).Msg("revoke service token")
		outcome = "unavailable"
	}
	c.Redirect(http.StatusSeeOther, "/tokens?outcome="+outcome)
}

func tokensNotice(outcome string) *view.Notice {
	switch outcome {
	case "revoked":
		return &view.Notice{Tone: "ok", Text: "Revoked. The token is refused from its next request on."}
	case "missing":
		return &view.Notice{Tone: "dan", Text: "That token does not exist, or it is not one you may revoke."}
	case "unavailable":
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing was revoked."}
	default:
		return nil
	}
}
