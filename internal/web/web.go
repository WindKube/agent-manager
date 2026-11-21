// Package web is the `serve web` role: a gin router rendering templ components,
// made interactive by datastar.
//
// This role holds no datastore credential; internal/archcheck fails the build if
// it imports a store, blob client or database driver. Data arrives through the hub client.
package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"agent-manager/internal/logging"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

func init() {
	// Set once here rather than from New: it is a package global.
	gin.SetMode(gin.ReleaseMode)
}

// CorrelationHeader ties a browser request to server log lines; the api echoes it.
const CorrelationHeader = "X-Correlation-ID"

// correlationIDPattern bounds inbound ids against log injection and header
// splitting; a non-match is replaced, not sanitised.
var correlationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Deps is what the role is handed. Hub is required; Auth is nil when the
// identity provider failed to configure at boot.
type Deps struct {
	Hub  *hub.Client
	Auth AuthProvider
	Log  zerolog.Logger
}

// Options is the run-time configuration of the surface itself.
type Options struct {
	Addr string
	// PublicBaseURL only decides secureCookie.
	PublicBaseURL string
	// ProviderName is the operator's name for the identity provider; never derived from the issuer URL.
	ProviderName string
	// DevCredentialHint puts the local stack's seeded logins on the sign-in screen.
	DevCredentialHint bool
	DevCredentials    []view.Credential
	// OIDCCookieKey signs the round-trip cookie. Empty draws one at boot, so
	// multiple web replicas must share the same value.
	OIDCCookieKey []byte
	// HubURL is the address `amctl login --hub` should name.
	HubURL string
	// RiverUI is the scheme and host of River's queue dashboard, or nil when none
	// runs. Nothing a request carries can steer where the proxy points.
	RiverUI *url.URL
	// Middleware runs ahead of everything else, instrumentation included.
	Middleware []gin.HandlerFunc
}

// Server is the assembled router. It owns no connections.
type Server struct {
	deps         Deps
	opts         Options
	engine       *gin.Engine
	secureCookie bool
	oidcKey      []byte
	// riverUI is nil when no dashboard is configured.
	riverUI *httputil.ReverseProxy
}

// New assembles the router. It performs no I/O.
func New(deps Deps, opts Options) *Server {
	if deps.Hub == nil {
		panic("web.New: Deps.Hub is required")
	}
	if opts.Addr == "" {
		opts.Addr = ":8080"
	}

	engine := gin.New()
	engine.HandleMethodNotAllowed = true

	srv := &Server{
		deps:         deps,
		opts:         opts,
		engine:       engine,
		secureCookie: secureCookie(opts.PublicBaseURL),
		oidcKey:      oidcSigningKey(opts.OIDCCookieKey),
		riverUI:      riverProxy(opts.RiverUI, deps.Log),
	}
	// The guard is global so a new route is protected by default, and runs after
	// correlation so its log lines and redirects carry the request id.
	engine.Use(opts.Middleware...)
	engine.Use(correlation(deps.Log), recovery(), srv.guard(), sameOrigin())
	srv.register()
	return srv
}

// Handler is the http.Handler the role serves.
func (s *Server) Handler() http.Handler { return s.engine }

func (s *Server) register() {
	s.engine.GET("/healthz", s.health)

	s.engine.GET("/", s.catalog)
	s.engine.GET("/catalog", s.catalog)
	s.engine.GET("/catalog/results", s.catalogResults)
	s.engine.GET("/catalog/facet/:name", s.catalogFacet)
	s.engine.POST("/catalog/import/preview", s.importPreview)
	s.engine.POST("/catalog/import", s.importRegister)

	// A package id is two segments; gin routes on the decoded path, so an encoded id still splits.
	s.engine.GET("/packages/:namespace/:name", s.packageDetail)
	// Writes are POST forms that redirect, so a reload cannot resubmit them.
	s.engine.POST("/packages/visibility", s.setPackageVisibility)
	s.engine.POST("/packages/tracking", s.setPackageTracking)
	s.engine.POST("/packages/signer", s.setPackageSigner)
	s.engine.POST("/packages/:namespace/:name/delete", s.deletePackage)
	s.engine.POST("/packages/:namespace/:name/versions/:version/delete", s.deleteVersion)

	s.engine.GET("/scanner", s.scanner)
	s.engine.POST("/scanner/findings/:id/accept", s.acceptFinding)
	s.engine.POST("/scanner/findings/:id/reject", s.rejectFinding)
	s.engine.GET("/audit", s.audit)
	s.engine.GET("/audit/export", s.auditExport)

	// A slug may span segments, so the read route is a catch-all. gin won't register
	// a catch-all beside a fixed-depth sibling, so writes carry the slug as a form field.
	s.engine.GET("/profiles", s.profiles)
	s.engine.POST("/profiles", s.createProfile)
	s.engine.GET("/profiles/*slug", s.profileDetail)
	s.engine.POST("/profiles/entries/pin", s.pinEntry)
	s.engine.POST("/profiles/entries/latest", s.floatEntry)
	s.engine.POST("/profiles/entries/add", s.addEntry)
	s.engine.POST("/profiles/entries/remove", s.removeEntry)
	s.engine.POST("/profiles/sharing", s.shareProfile)
	s.engine.POST("/profiles/targets", s.setTargets)
	s.engine.POST("/profiles/revisions", s.publishRevision)
	s.engine.POST("/profiles/delete", s.deleteProfile)
	// The user code never goes in the path: it is bearer-equivalent while valid.
	s.engine.GET("/cli", s.cli)
	s.engine.POST("/cli/confirm", s.confirmDeviceCode)
	s.engine.GET("/tokens", s.tokens)
	s.engine.POST("/tokens", s.createToken)
	s.engine.POST("/tokens/:id/revoke", s.revokeToken)
	s.engine.GET("/storage", s.storage)
	s.engine.GET("/machines", s.machines)
	s.engine.GET("/machines/:id", s.machineDetail)
	s.engine.POST("/machines/:id/forget", s.forgetMachine)

	s.engine.GET("/org", s.org)
	s.engine.POST("/org/identity/test", s.testConnection)
	s.engine.POST("/org/identity/secret", s.rotateSecret)
	s.engine.POST("/org/policy", s.savePolicy)
	s.engine.POST("/org/mappings", s.createMapping)
	s.engine.POST("/org/mappings/:id/delete", s.deleteMapping)
	s.engine.POST("/org/categories", s.createCategory)
	s.engine.POST("/org/categories/:id", s.renameCategory)
	s.engine.POST("/org/categories/:id/delete", s.deleteCategory)

	s.engine.GET("/webhooks", s.webhooks)
	s.engine.POST("/webhooks", s.createWebhook)
	s.engine.POST("/webhooks/:id/enabled", s.setWebhookEnabled)
	s.engine.POST("/webhooks/:id/secret", s.rotateWebhookSecret)
	s.engine.POST("/webhooks/:id/delete", s.deleteWebhook)

	s.engine.GET("/runtime", s.runtime)

	// The embed is a byte passthrough with no shell or session cookie, so it gets
	// its own prefix rather than a wildcard beside the rendered screen.
	s.engine.GET("/river", s.riverScreen)
	s.engine.Any(view.RiverEmbedPrefix+"/*path", s.riverEmbed)

	s.engine.POST("/theme", s.setTheme)

	// These, plus /healthz and /static, are exempt from the guard.
	s.engine.GET("/auth/signin", s.signin)
	s.engine.GET("/auth/login", s.login)
	s.engine.GET("/auth/callback", s.callback)
	s.engine.POST("/auth/logout", s.logout)

	s.engine.GET("/static/*path", serveStatic)

	s.engine.NoRoute(s.notFound)
}

func (s *Server) notFound(c *gin.Context) {
	s.render(c, http.StatusNotFound, "Not found", "",
		components.Placeholder("Not found", "There is no screen at this address."))
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "role": "web"})
}

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.opts.Addr,
		Handler:           s.engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.opts.Addr, err)
	}

	errs := make(chan error, 1)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errs <- serveErr
			return
		}
		errs <- nil
	}()

	s.deps.Log.Info().Str("addr", s.opts.Addr).Msg("web listening")

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down web: %w", err)
	}
	return <-errs
}

func logFrom(c *gin.Context) *zerolog.Logger {
	log := logging.From(c.Request.Context())
	return &log
}

func correlation(base zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(CorrelationHeader)
		if !correlationIDPattern.MatchString(id) {
			id = uuid.NewString()
		}

		ctx, log := logging.WithCorrelation(logging.Into(c.Request.Context(), base), id)
		c.Request = c.Request.WithContext(ctx)
		c.Header(CorrelationHeader, id)

		started := time.Now()
		c.Next()

		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("duration", time.Since(started)).
			Msg("request")
	}
}

func recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		logFrom(c).Error().
			Interface("panic", recovered).
			Str("path", c.Request.URL.Path).
			Msg("panic serving request")
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// sameOrigin backs up SameSite=Lax, which not every browser enforces. It checks
// Sec-Fetch-Site, falling back to Origin for browsers too old to send it.
func sameOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		if site := c.GetHeader("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" && site != "none" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		} else if origin := c.GetHeader("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != c.Request.Host {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}
