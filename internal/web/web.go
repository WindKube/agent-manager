// Package web is the `serve web` role: a gin router rendering templ components,
// made interactive by datastar.
//
// This role holds no datastore credential: config.Web has no DatabaseURL or
// BlobURL field, and internal/archcheck fails the build if internal/web imports
// a store, blob client or database driver. Data arrives through the hub client.
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
	// A package global, set once here rather than from New to avoid a race.
	gin.SetMode(gin.ReleaseMode)
}

// CorrelationHeader carries the id that ties a browser's request to the
// server's log lines. The api role echoes the same header.
const CorrelationHeader = "X-Correlation-ID"

// correlationIDPattern is what an inbound id may contain: unbounded, it is a
// log-injection and header-splitting vector, so a non-match is replaced
// rather than sanitised.
var correlationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Deps is what the role is handed. Hub is required. Auth is nil when the
// identity provider failed to configure at boot.
type Deps struct {
	Hub  *hub.Client
	Auth AuthProvider
	Log  zerolog.Logger
}

// Options is the run-time configuration of the surface itself.
type Options struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// PublicBaseURL is read for exactly one decision: see secureCookie.
	PublicBaseURL string
	// ProviderName is what the operator calls the identity provider. Empty
	// renders neutral wording; never derived from the issuer URL.
	ProviderName string
	// DevCredentialHint puts the local stack's seeded logins on the sign-in screen.
	DevCredentialHint bool
	// DevCredentials is what the hint above prints. Ignored unless the flag is set.
	DevCredentials []view.Credential
	// OIDCCookieKey signs the round-trip cookie. Empty draws one at boot — a
	// deployment with more than one web replica MUST set the same value on each.
	OIDCCookieKey []byte
	// HubURL is the address `amctl login --hub` should name.
	HubURL string
	// RiverUI is the base address of River's queue dashboard, or nil when this
	// deployment runs none — in which case the River Dashboard entry renders
	// disabled with the reason on it, rather than disappearing.
	//
	// Scheme and host only. It is not a credential: the dashboard holds the
	// queue's, this role holds none, and nothing a request carries can steer
	// where the proxy points.
	RiverUI *url.URL
}

// Server is the assembled router. It owns no connections.
type Server struct {
	deps   Deps
	opts   Options
	engine *gin.Engine
	// secureCookie and oidcKey are decided once, at construction, not per-request.
	secureCookie bool
	oidcKey      []byte
	// riverUI is the reverse proxy onto the queue dashboard, built once, and nil
	// when no dashboard is configured.
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
	// The guard is global, so a new route is protected by default. It runs
	// after correlation so its own log lines and redirect carry the request's id.
	engine.Use(correlation(deps.Log), recovery(), srv.guard(), sameOrigin())
	srv.register()
	return srv
}

// Handler is the http.Handler the role serves, and what tests drive.
func (s *Server) Handler() http.Handler { return s.engine }

func (s *Server) register() {
	s.engine.GET("/healthz", s.health)

	s.engine.GET("/", s.catalog)
	s.engine.GET("/catalog", s.catalog)
	s.engine.GET("/catalog/results", s.catalogResults)
	s.engine.GET("/catalog/facet/:name", s.catalogFacet)
	s.engine.POST("/catalog/import/preview", s.importPreview)
	s.engine.POST("/catalog/import", s.importRegister)

	// A package id IS two segments: `example/platform-toolkit`. gin routes on
	// the decoded path, so this splits correctly even if the id arrives encoded.
	s.engine.GET("/packages/:namespace/:name", s.packageDetail)
	// POST forms that redirect, like the profile screens' writes, so a reload
	// cannot resubmit any of them. The two deletes are additionally gated on
	// the role the api demands and sit behind a typed confirmation.
	s.engine.POST("/packages/visibility", s.setPackageVisibility)
	s.engine.POST("/packages/tracking", s.setPackageTracking)
	s.engine.POST("/packages/signer", s.setPackageSigner)
	s.engine.POST("/packages/:namespace/:name/delete", s.deletePackage)
	s.engine.POST("/packages/:namespace/:name/versions/:version/delete", s.deleteVersion)

	// Both governance decisions are POST forms that redirect, so a reload
	// cannot re-approve anything.
	s.engine.GET("/scanner", s.scanner)
	s.engine.POST("/scanner/findings/:id/accept", s.acceptFinding)
	s.engine.POST("/scanner/findings/:id/reject", s.rejectFinding)
	s.engine.GET("/audit", s.audit)
	s.engine.GET("/audit/export", s.auditExport)

	// A slug is one segment or several, so the read route is a catch-all. gin
	// won't register a catch-all beside a fixed-depth sibling, so every write
	// route below carries its slug as a form field instead of a path segment.
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
	// The confirm action never carries the user code in its own path: it is
	// bearer-equivalent for the length of its validity.
	s.engine.GET("/cli", s.cli)
	s.engine.POST("/cli/confirm", s.confirmDeviceCode)
	s.engine.GET("/tokens", s.tokens)
	s.engine.POST("/tokens", s.createToken)
	s.engine.POST("/tokens/:id/revoke", s.revokeToken)
	s.engine.GET("/storage", s.storage)

	// Every Organization write is a POST form that redirects, same as Scanner.
	s.engine.GET("/org", s.org)
	s.engine.POST("/org/identity/test", s.testConnection)
	s.engine.POST("/org/identity/secret", s.rotateSecret)
	s.engine.POST("/org/policy", s.savePolicy)
	s.engine.POST("/org/mappings", s.createMapping)
	s.engine.POST("/org/mappings/:id/delete", s.deleteMapping)
	s.engine.POST("/org/categories", s.createCategory)
	s.engine.POST("/org/categories/:id", s.renameCategory)
	s.engine.POST("/org/categories/:id/delete", s.deleteCategory)

	s.engine.GET("/runtime", s.runtime)

	// The screen and the dashboard it embeds are separate paths on purpose: the
	// embed is a byte passthrough with no layout, no shell and no session cookie
	// on the way out, and a wildcard sharing a segment with a rendered screen is
	// how one of them starts answering for the other.
	s.engine.GET("/river", s.riverScreen)
	s.engine.Any(view.RiverEmbedPrefix+"/*path", s.riverEmbed)

	s.engine.POST("/theme", s.setTheme)

	// These four routes, plus /healthz and /static, are exempt from the guard.
	// /auth/logout is a POST because a GET sign-out fires from any image tag on
	// any page, on any origin.
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

// health has no dependency to probe: if the process is up, it can serve.
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

// logFrom is the request's logger, already carrying the correlation id.
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

// sameOrigin is a second line of defence behind SameSite=Lax, which a browser
// with third-party cookies re-enabled (or a bug in one) does not enforce. A
// modern browser sends Sec-Fetch-Site on every request; where it is absent,
// Origin is the fallback every browser old enough to lack it still sends on a
// state-changing request.
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
