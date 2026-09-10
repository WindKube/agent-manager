// Package web is the `serve web` role: a gin router rendering templ components,
// made interactive by datastar.
//
// This role holds no datastore credential: config.Web has no DatabaseURL or
// BlobURL field, and internal/archcheck fails the build if internal/web imports
// a store, blob client or database driver. Data arrives through a CatalogSource.
package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// CatalogSource is the web role's door to catalog data. A source reporting
// view.ErrSignedOut is stating a fact about the caller, not failing.
type CatalogSource interface {
	Catalog(ctx context.Context, q view.CatalogQuery) (view.CatalogPage, error)
}

// PackageSource is the detail screen's door to one package.
type PackageSource interface {
	Package(ctx context.Context, namespace, name string) (view.Package, error)
}

// Registrar is the import modal's door to the two registration operations,
// separate from CatalogSource so a fixture need not claim to accept one too.
type Registrar interface {
	Preview(ctx context.Context, archive view.Archive) (view.ImportPreview, error)
	Register(ctx context.Context, registration view.Registration) (view.ImportResult, error)
}

// ScannerSource is the Scanner screen's three reads. It excludes the accept
// and reject decision, which lives on Reviewer.
type ScannerSource interface {
	ScannerSummary(ctx context.Context, days int) (hub.ScannerSummary, error)
	Findings(ctx context.Context, q hub.FindingQuery) (hub.FindingsPage, error)
	Finding(ctx context.Context, id string) (hub.FindingDetail, error)
}

// Reviewer is the two decisions a scanner reviewer can take, separate from
// ScannerSource because it writes an audit row a fixture must not fake.
type Reviewer interface {
	AcceptFinding(ctx context.Context, id, note string, days int) (hub.Decision, error)
	RejectFinding(ctx context.Context, id, note string) (hub.Decision, error)
}

// AuditSource is the audit screen and its export. AuditExport hands back a
// LIVE body the caller owns the Close of, since the audit table grows without bound.
type AuditSource interface {
	Audit(ctx context.Context, page int) (hub.AuditPage, error)
	AuditExport(ctx context.Context) (io.ReadCloser, string, error)
}

// ProfileSource is the Profiles screens' two reads, kept separate from
// ProfileCurator's writes as ScannerSource is from Reviewer.
type ProfileSource interface {
	Profiles(ctx context.Context) ([]hub.ProfileSummary, error)
	Profile(ctx context.Context, slug string) (hub.ProfileDetail, error)
}

// ProfileCurator is every write the profile screens offer: create, curate,
// share, target and publish. One interface, not five, since each is gated by
// the same profile's ProfilePermissions.
type ProfileCurator interface {
	CreateProfile(ctx context.Context, creation hub.ProfileCreation) (hub.ProfileSummary, error)
	SetProfileEntries(ctx context.Context, slug string, entries []hub.EntrySetting) (hub.ProfileDetail, error)
	SetProfileSharing(ctx context.Context, slug string, members []hub.Share) (hub.ProfileDetail, error)
	SetProfileTargets(ctx context.Context, slug string, targets []string) (hub.ProfileDetail, error)
	PublishRevision(ctx context.Context, slug, note string) (hub.PublishedRevision, error)
}

// DeviceSource is the Connect-the-CLI screen's door to the api: looking a
// pending authorisation up and confirming it.
type DeviceSource interface {
	LookupDeviceCode(ctx context.Context, userCode string) (view.PendingDeviceAuthorization, error)
	ApproveDeviceCode(ctx context.Context, userCode string) (string, error)
}

// BadgeSource is the sidebar's three counts, read once per full page render.
// Nil means a shell with no badges, not three zeroes.
type BadgeSource interface {
	Badges(ctx context.Context) (hub.Badges, error)
}

// StorageSource is the Storage screen's one read.
type StorageSource interface {
	Storage(ctx context.Context) (view.Storage, error)
}

// OrganizationSource is the Organization screen's door to the api. Reads and
// writes share one interface since every mutation needs the same role.
type OrganizationSource interface {
	Organization(ctx context.Context) (view.Organization, error)
	TestIdentityConnection(ctx context.Context) (view.IdentityConnectionTest, error)
	UpdatePolicy(ctx context.Context, in view.OrganizationPolicy) (view.OrganizationPolicy, error)
	CreateMapping(ctx context.Context, groupName, role string) (view.GroupRoleMapping, error)
	DeleteMapping(ctx context.Context, groupName string) error
	CreateCategory(ctx context.Context, name string) (view.OrganizationCategory, error)
	UpdateCategory(ctx context.Context, id, name string) (view.OrganizationCategory, error)
	DeleteCategory(ctx context.Context, id string) error
}

// Deps is what the role is handed. Nil on any source renders that screen's
// unavailable state rather than an empty one or a panic.
type Deps struct {
	Catalog   CatalogSource
	Packages  PackageSource
	Registrar Registrar
	Auth      AuthProvider
	// Viewers resolves who each request is acting as. Nil fails closed.
	Viewers      ViewerSource
	Sessions     SessionMinter
	Scanner      ScannerSource
	Reviewer     Reviewer
	Audit        AuditSource
	Badges       BadgeSource
	Device       DeviceSource
	Profiles     ProfileSource
	Curator      ProfileCurator
	Storage      StorageSource
	Organization OrganizationSource
	Log          zerolog.Logger
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
}

// Server is the assembled router. It owns no connections.
type Server struct {
	deps   Deps
	opts   Options
	engine *gin.Engine
	// secureCookie and oidcKey are decided once, at construction, not per-request.
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
	s.engine.POST("/profiles/sharing", s.shareProfile)
	s.engine.POST("/profiles/targets", s.setTargets)
	s.engine.POST("/profiles/revisions", s.publishRevision)
	// The confirm action never carries the user code in its own path: it is
	// bearer-equivalent for the length of its validity.
	s.engine.GET("/cli", s.cli)
	s.engine.POST("/cli/confirm", s.confirmDeviceCode)
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
