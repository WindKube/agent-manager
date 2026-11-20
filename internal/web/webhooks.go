package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The Webhooks screen. Creating one or rotating its secret answers the POST
// with the page itself, like Service tokens: the secret never goes in a URL.

func (s *Server) webhooks(c *gin.Context) {
	screen := s.webhookScreen(c, view.WebhookForm{})
	screen.Notice = webhooksNotice(c.Query("outcome"))
	if id := c.Query("webhook"); id != "" && screen.Readable() {
		s.openWebhook(c, &screen, id)
	}
	s.renderWebhooks(c, screen)
}

func (s *Server) webhookScreen(c *gin.Context, form view.WebhookForm) view.Webhooks {
	screen := view.Webhooks{Form: form}
	webhooks, eventTypes, err := s.deps.Hub.Webhooks(session(c))
	if _, ok := s.governanceFailure(c, err, &screen.GovernanceState, "webhooks"); ok {
		screen.Webhooks, screen.EventTypes = webhooks, eventTypes
	}
	return screen
}

func (s *Server) openWebhook(c *gin.Context, screen *view.Webhooks, id string) {
	for i := range screen.Webhooks {
		if screen.Webhooks[i].ID == id {
			screen.Open = &screen.Webhooks[i]
		}
	}
	if screen.Open == nil {
		return
	}
	deliveries, err := s.deps.Hub.WebhookDeliveries(session(c), id)
	if err != nil {
		logFrom(c).Error().Err(err).Msg("list webhook deliveries")
		screen.DeliveriesUnavailable = true
		return
	}
	screen.Deliveries = deliveries
}

func (s *Server) renderWebhooks(c *gin.Context, screen view.Webhooks) {
	status := http.StatusOK
	switch {
	case screen.SignedOut:
		s.toSignIn(c)
		return
	case screen.Refused:
		status = http.StatusForbidden
	case screen.Unavailable:
		status = http.StatusBadGateway
	case screen.Notice != nil && screen.Notice.Tone == "dan" && screen.Secret == nil:
		status = http.StatusUnprocessableEntity
	}
	c.Header("Cache-Control", "no-store")
	s.render(c, status, "Webhooks", "webhooks", components.WebhooksScreen(screen))
}

func (s *Server) createWebhook(c *gin.Context) {
	form := view.WebhookForm{
		Name:       strings.TrimSpace(c.PostForm("name")),
		URL:        strings.TrimSpace(c.PostForm("url")),
		EventTypes: c.PostFormArray("eventType"),
		Namespaces: strings.TrimSpace(c.PostForm("namespaces")),
	}
	refuse := func(text string) {
		screen := s.webhookScreen(c, form)
		screen.Notice = &view.Notice{Tone: "dan", Text: text}
		s.renderWebhooks(c, screen)
	}
	if len(form.EventTypes) == 0 {
		refuse("Choose at least one event type.")
		return
	}

	created, err := s.deps.Hub.CreateWebhook(session(c), form.Name, form.URL, form.EventTypes, form.NamespaceList())
	var refused *hub.WebhookRefusedError
	switch {
	case err == nil:
		screen := s.webhookScreen(c, view.WebhookForm{})
		screen.Secret = &created
		s.renderWebhooks(c, screen)
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		refuse("Your role may not manage webhooks. This needs the catalog admin role.")
	case errors.As(err, &refused):
		refuse(refused.Detail)
	default:
		logFrom(c).Error().Err(err).Msg("create webhook")
		refuse("The hub's api could not be reached, so no webhook was created.")
	}
}

func (s *Server) rotateWebhookSecret(c *gin.Context) {
	secret, err := s.deps.Hub.RotateWebhookSecret(session(c), c.Param("id"))
	if err != nil {
		s.webhookOutcome(c, err, "rotate webhook secret", "")
		return
	}
	screen := s.webhookScreen(c, view.WebhookForm{})
	name := "Webhook"
	for i := range screen.Webhooks {
		if screen.Webhooks[i].ID == c.Param("id") {
			name = screen.Webhooks[i].Name
		}
	}
	screen.Secret = &view.WebhookSecret{Name: name, Secret: secret}
	s.renderWebhooks(c, screen)
}

func (s *Server) setWebhookEnabled(c *gin.Context) {
	enabled := c.PostForm("enabled") == "1"
	outcome := "disabled"
	if enabled {
		outcome = "enabled"
	}
	s.webhookOutcome(c, s.deps.Hub.SetWebhookEnabled(session(c), c.Param("id"), enabled), "set webhook enabled", outcome)
}

func (s *Server) deleteWebhook(c *gin.Context) {
	s.webhookOutcome(c, s.deps.Hub.DeleteWebhook(session(c), c.Param("id")), "delete webhook", "deleted")
}

// webhookOutcome is post-redirect-get's redirect half; the copy is looked
// up from the token on the next request, never carried.
func (s *Server) webhookOutcome(c *gin.Context, err error, what, outcome string) {
	switch {
	case err == nil:
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
		return
	case errors.Is(err, hub.ErrForbidden):
		outcome = "refused"
	case errors.Is(err, hub.ErrWebhookNotFound):
		outcome = "missing"
	default:
		logFrom(c).Error().Err(err).Msg(what)
		outcome = "unavailable"
	}
	c.Redirect(http.StatusSeeOther, "/webhooks?outcome="+outcome)
}

func webhooksNotice(outcome string) *view.Notice {
	switch outcome {
	case "enabled":
		return &view.Notice{Tone: "ok", Text: "Enabled. Events from now on are delivered."}
	case "disabled":
		return &view.Notice{Tone: "ok", Text: "Disabled. Nothing is delivered until it is enabled again."}
	case "deleted":
		return &view.Notice{Tone: "ok", Text: "Deleted, with its delivery log."}
	case "missing":
		return &view.Notice{Tone: "dan", Text: "That webhook does not exist."}
	case "refused":
		return &view.Notice{Tone: "dan", Text: "Your role may not manage webhooks."}
	case "unavailable":
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing changed."}
	default:
		return nil
	}
}
