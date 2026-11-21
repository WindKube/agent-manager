package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

func (s *Server) cli(c *gin.Context) {
	screen := view.CLI{
		Command: cliLoginCommand(s.opts.HubURL),
		HubURL:  s.opts.HubURL,
		Notice:  cliNotice(c.Query("outcome"), c.Query("host")),
	}

	code := strings.TrimSpace(c.Query("user_code"))
	screen.UserCode = code
	if code == "" {
		s.renderCLI(c, http.StatusOK, screen)
		return
	}

	pending, err := s.deps.Hub.LookupDeviceCode(session(c), code)
	switch {
	case err == nil:
		now := time.Now().UTC()
		screen.Pending = &view.PendingDeviceAuthorization{
			RequestingHost: pending.RequestingHost,
			ExpiresAt:      pending.ExpiresAt,
		}
		screen.Countdown = view.Until(pending.ExpiresAt, now)
		s.renderCLI(c, http.StatusOK, screen)
	case errors.Is(err, view.ErrSignedOut):
		logFrom(c).Debug().Msg("device code lookup without a session")
		s.toSignIn(c)
	case errors.Is(err, hub.ErrDeviceCodeUnknown):
		screen.Unknown = true
		s.renderCLI(c, http.StatusNotFound, screen)
	case errors.Is(err, hub.ErrDeviceCodeExpired):
		screen.Expired = true
		s.renderCLI(c, http.StatusGone, screen)
	case errors.Is(err, hub.ErrDeviceCodeDecided):
		screen.Decided = true
		s.renderCLI(c, http.StatusConflict, screen)
	default:
		logFrom(c).Error().Err(err).Msg("look up device code")
		screen.Unavailable = true
		s.renderCLI(c, http.StatusBadGateway, screen)
	}
}

func (s *Server) renderCLI(c *gin.Context, status int, screen view.CLI) {
	s.render(c, status, "Connect the CLI", "cli", components.CLIScreen(screen))
}

func (s *Server) confirmDeviceCode(c *gin.Context) {
	code := strings.TrimSpace(c.PostForm("user_code"))

	host, err := s.deps.Hub.ApproveDeviceCode(session(c), code)
	switch {
	case err == nil:
		s.backToCLI(c, "approved", host)
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrDeviceCodeUnknown):
		s.backToCLI(c, "unknown", "")
	case errors.Is(err, hub.ErrDeviceCodeExpired):
		s.backToCLI(c, "expired", "")
	case errors.Is(err, hub.ErrDeviceCodeDecided):
		s.backToCLI(c, "decided", "")
	default:
		logFrom(c).Error().Err(err).Msg("approve device code")
		s.backToCLI(c, "unavailable", "")
	}
}

// backToCLI never carries the user code: it is bearer-equivalent and a redirect
// URL leaks into history and referrers.
func (s *Server) backToCLI(c *gin.Context, outcome, host string) {
	values := url.Values{"outcome": {outcome}}
	if host != "" {
		values.Set("host", host)
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, "/cli?"+values.Encode())
}

func cliNotice(outcome, host string) *view.Notice {
	switch outcome {
	case "approved":
		text := "Approved."
		if host != "" {
			text += " " + host + " can finish signing in now — its next poll receives a token."
		}
		return &view.Notice{Tone: "ok", Text: text}
	case "unknown":
		return &view.Notice{Tone: "dan", Text: "That code is not one this hub has issued, or it " +
			"was mistyped. Check it against the terminal and try again."}
	case "expired":
		return &view.Notice{Tone: "warn", Text: "That code has expired. Run the login command " +
			"again to get a fresh one."}
	case "decided":
		return &view.Notice{Tone: "dan", Text: "That code has already been approved, denied or " +
			"used. If the CLI is still waiting, it needs a fresh code."}
	case "unavailable":
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing " +
			"was recorded."}
	default:
		return nil
	}
}

// cliLoginCommand is empty when this role was not told the api's address.
func cliLoginCommand(hubURL string) string {
	if hubURL == "" {
		return ""
	}
	return "amctl login --hub " + hubURL
}
