// Package web is the `serve web` role: a gin router rendering templ components,
// made interactive by datastar.
//
// Constitution principle II: this role holds no datastore credential. config.Web
// has no DatabaseURL and no BlobURL field, nothing here opens a connection, and
// internal/archcheck fails the build if any package under internal/web imports
// the store, the blob client, a database driver or anything else outside a named
// allowlist. Data arrives through a CatalogSource.
package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"agent-manager/internal/logging"
	"agent-manager/internal/web/components"
	"agent-manager/internal/web/view"
)

func init() {
	// gin's mode is a package global read on every engine construction, so it is
	// set once here rather than from New, where parallel callers would race.
	gin.SetMode(gin.ReleaseMode)
}

// CorrelationHeader carries the id that ties a browser's request to the server's
// log lines (FR-059). It is the same header the api role echoes.
const CorrelationHeader = "X-Correlation-ID"

// correlationIDPattern is what an inbound id may contain. An id supplied by a
// client reaches structured log lines and a response header, so an unbounded
// value is a log-injection and header-splitting vector; anything that does not
// match is replaced rather than sanitised.
var correlationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// CatalogSource is the web role's door to catalog data.
//
// internal/web/hub implements it over the generated client; internal/web/fixture
// still implements it for the screen tests, which need the design's ten rows
// without a hub behind them. A source reporting view.ErrSignedOut is stating a
// fact about the caller, not failing: see load.
type CatalogSource interface {
	Catalog(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error)
}

// PackageSource is the detail screen's door to one package (US3).
//
// It is a third interface rather than a second method on CatalogSource for the
// same reason Registrar is separate: internal/web/fixture implements both of
// these and internal/web/hub implements all three, and an interface a stand-in
// cannot honestly satisfy is one every screen test then exercises as a claim.
type PackageSource interface {
	Package(ctx context.Context, namespace, name string) (view.Package, error)
}

// Registrar is the modal's door to the two registration operations.
//
// It is a second interface rather than two more methods on CatalogSource because
// internal/web/fixture implements one and must not implement the other: a
// fixture that could accept a registration would be claiming something it cannot
// do, and every screen test would then be exercising the claim.
type Registrar interface {
	Preview(ctx context.Context, archive view.Archive) (view.ImportPreview, error)
	Register(ctx context.Context, registration view.Registration) (view.ImportResult, error)
}

// Deps is what the role is handed. Every field is narrow on purpose: there is no
// database handle and no bucket to reach for.
type Deps struct {
	Catalog CatalogSource
	// Packages backs the detail screen. Nil renders /packages/... as a 404 rather
	// than panicking, which is what a screen test that wired only the catalog gets.
	Packages PackageSource
	// Registrar is optional. Nil means the modal renders and refuses to submit,
	// which is what a screen test wants and is not a state a deployment is in.
	Registrar Registrar
	// Auth is the door to the identity provider. Nil is a role whose provider could
	// not be discovered at boot: /auth/signin then says the provider cannot be
	// reached and offers no action, rather than a button known to fail.
	Auth AuthProvider
	// Viewers resolves who each request is acting as, on EVERY request (FR-118).
	//
	// Nil fails closed: the guard sends every protected route to the sign-in screen.
	// A screen test that wants a signed-in shell has to supply one (SC-106) — there
	// is no default viewer and there must not be one.
	Viewers ViewerSource
	// Sessions is the api's session mint and its sign-out. Nil means sign-in cannot
	// complete, which the callback renders as the hub's own failure.
	Sessions SessionMinter
	Log      zerolog.Logger
}

// Options is the run-time configuration of the surface itself.
type Options struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// PublicBaseURL is the origin a browser reaches this role at. It is read for
	// exactly one decision — whether the two cookies are marked Secure — and it is
	// read instead of the request on purpose: see secureCookie.
	PublicBaseURL string
	// ProviderName is what the operator calls the identity provider, for the
	// sign-in screen's one action. Empty renders the neutral wording — naming it
	// tells a person which password-manager entry to reach for, and nothing else in
	// this role branches on it. It is a label an operator states or does without:
	// deriving one from the issuer URL would be the provider-specific quirk FR-105
	// forbids.
	ProviderName string
	// DevCredentialHint puts the local stack's seeded logins on the sign-in screen
	// (FR-119). It is an explicit flag and is never derived from the issuer, the
	// host name or the build type.
	DevCredentialHint bool
	// DevCredentials is what the hint above prints, handed in rather than spelled
	// anywhere under internal/web: a username or an address written into this role
	// would be the compiled-in identity FR-116 and SC-106 forbid, and it would
	// reach every visitor the moment that flag flipped. Ignored unless the flag is
	// set.
	DevCredentials []view.Credential
	// OIDCCookieKey signs the round-trip cookie. Empty means one is drawn at boot,
	// which is the right default for a single process: the cookie lives 90 seconds,
	// so a restart costs at most one person one retry, and there is no key material
	// in the environment to leak. A deployment running more than one web replica
	// behind a load balancer MUST set the same value on each, or a sign-in that
	// starts on one and returns to another finds no round trip in flight.
	OIDCCookieKey []byte
}

// Server is the assembled router. It owns no connections.
type Server struct {
	deps   Deps
	opts   Options
	engine *gin.Engine
	// secureCookie and oidcKey are decided once, at construction: a per-request
	// decision about either is a per-request opportunity to get one of them wrong.
	secureCookie bool
	oidcKey      []byte
}

// New assembles the router. It performs no I/O.
func New(deps Deps, opts Options) *Server {
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
	}
	// The guard is global, so a route added by a later layer is protected by
	// default and opting out means editing the one list that names the
	// unauthenticated set. It runs after correlation so its own log lines and its
	// redirect carry the request's id.
	engine.Use(correlation(deps.Log), recovery(), srv.guard())
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

	// Two segments, because a package id IS two segments: `example/platform-toolkit`.
	// A single :id would have to arrive percent-encoded and would not survive —
	// gin routes on the DECODED path, so `example%2Fplatform-toolkit` reaches the
	// router as two segments anyway.
	s.engine.GET("/packages/:namespace/:name", s.packageDetail)

	s.engine.POST("/theme", s.setTheme)

	// Sign-in (US2). These four and only these four are exempt from the guard,
	// together with /healthz and /static — contracts/auth.md fixes that set.
	// /auth/logout is a POST because a GET sign-out fires from any image tag on any
	// page, on any origin.
	s.engine.GET("/auth/signin", s.signin)
	s.engine.GET("/auth/login", s.login)
	s.engine.GET("/auth/callback", s.callback)
	s.engine.POST("/auth/logout", s.logout)

	s.engine.GET("/static/*path", serveStatic)

	// The screens later layers own. They render inside the real shell so the
	// sidebar is navigable, rather than dead-ending on a 404.
	for _, screen := range placeholders {
		s.engine.GET(screen.path, s.placeholder(screen))
	}

	s.engine.NoRoute(s.notFound)
}

type screen struct {
	path  string
	nav   string
	title string
	lede  string
}

var placeholders = []screen{
	{path: "/profiles", nav: "profiles", title: "Profiles", lede: "Named sets of packages a machine can sync."},
	{path: "/profiles/:slug", nav: "profiles", title: "Profile", lede: "The packages in one profile, their pins and their targets."},
	{path: "/scanner", nav: "scanner", title: "Scanner", lede: "Open findings, their evidence and the reviewer's decision."},
	{path: "/cli", nav: "cli", title: "Connect the CLI", lede: "Pair a machine with the hub through the device flow."},
	{path: "/org", nav: "org", title: "Organization", lede: "Identity provider, group-to-role mapping and policy."},
	{path: "/storage", nav: "storage", title: "Storage", lede: "Bucket layout, object counts and recent fetch outcomes."},
	{path: "/audit", nav: "audit", title: "Audit log", lede: "Every state-changing action, one row each."},
}

func (s *Server) placeholder(sc screen) gin.HandlerFunc {
	return func(c *gin.Context) {
		s.render(c, http.StatusOK, sc.title, sc.nav, components.Placeholder(sc.title, sc.lede))
	}
}

func (s *Server) notFound(c *gin.Context) {
	s.render(c, http.StatusNotFound, "Not found", "",
		components.Placeholder("Not found", "There is no screen at this address."))
}

// health is FR-058's endpoint. The web role has no dependency to probe, which is
// the whole point of the role: if the process is up, it can serve.
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
