// Package api is the HTTP surface of the `serve api` role: a gin router carrying
// huma operations, from which the OpenAPI document is generated (never hand-maintained).
// Reads live in queries/, writes in commands/.
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
)

func init() {
	// gin's mode is a package global read on every engine construction, so set it
	// once here rather than from New, where parallel callers would race.
	gin.SetMode(gin.ReleaseMode)

	huma.NewError = newHumaError

	// The contract types arrays as non-null `array`; handlers emit empty slices, never nil.
	huma.DefaultArrayNullable = false
}

// Probe is one dependency /v1/health reports on.
type Probe struct {
	Name  string
	Check func(context.Context) error
}

// Deps is what the api role is handed. Fields are deliberately narrow: the api gets
// a blob reader only, since only `worker fetcher` may write bundle bytes.
type Deps struct {
	DB       bun.IDB
	Bundles  blob.Reader
	Sessions auth.Resolver
	Probes   []Probe
	Log      zerolog.Logger

	// IDTokens verifies the ID token a session mint presents. It may be nil, in
	// which case the mint is refused rather than taking other operations down.
	IDTokens commands.IDTokenVerifier
	// SessionMintSecret authenticates the role-to-role session mint. Empty means the
	// mint is refused outright, with no development bypass; commands.SessionMint enforces it.
	SessionMintSecret string

	// Storage is read-and-describe only: this role holds no blob writer.
	Storage blob.Inspector

	// Identity is this role's OIDC configuration; it never carries the client secret.
	Identity commands.IdentityConfig

	// Queue is River's own database, never the application schema.
	Queue queries.RuntimeQueue
}

// Options is the run-time configuration of the surface itself.
type Options struct {
	Addr string
	// PublicBaseURL is emitted as the document's server entry and is the base of
	// the device flow's verification_uri.
	PublicBaseURL string
	// DeviceVerificationURL is the web role's /cli page where a human enters the device code.
	DeviceVerificationURL string
	DeviceCodeTTL         time.Duration
	DeviceTokenTTL        time.Duration
	// SessionTTL is decided by the api, not the web role: a caller that could choose
	// it could choose forever.
	SessionTTL    time.Duration
	HealthTimeout time.Duration
	// Middleware runs ahead of everything else, instrumentation included.
	Middleware []gin.HandlerFunc
}

func (o Options) withDefaults() Options {
	if o.Addr == "" {
		o.Addr = ":8081"
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 2 * time.Second
	}
	if o.DeviceCodeTTL <= 0 {
		o.DeviceCodeTTL = 10 * time.Minute
	}
	if o.DeviceTokenTTL <= 0 {
		o.DeviceTokenTTL = time.Hour
	}
	if o.SessionTTL <= 0 {
		// Duplicates config.API's default: New is reachable without config, and
		// commands.Login refuses a zero TTL.
		o.SessionTTL = 12 * time.Hour
	}
	return o
}

// Server is the assembled surface. It owns no connections, which lets Document
// build the same routes with no database.
type Server struct {
	deps   Deps
	opts   Options
	engine *gin.Engine
	api    huma.API
	// deviceLimiter is per process and therefore per replica; see device.go.
	deviceLimiter *rateLimiter
	// mintLimiter counts only refused session mints per caller address.
	mintLimiter *rateLimiter
}

// New assembles the router. It performs no I/O, so a zero Deps yields a server
// that emits the document and nothing else.
func New(deps Deps, opts Options) *Server {
	opts = opts.withDefaults()

	engine := gin.New()
	engine.HandleMethodNotAllowed = true
	// Route on the raw path and unescape captured values afterwards, so a path
	// parameter may carry an encoded slash. Profile slugs hold several segments
	// (e.g. `example/platform-engineer`) but the contract's revision path has one
	// {slug} parameter; without this, gin matches the decoded path and returns 404.
	engine.UseRawPath = true
	engine.UnescapePathValues = true
	engine.Use(opts.Middleware...)
	engine.Use(correlation(deps.Log), recovery())
	engine.NoRoute(notFound)
	engine.NoMethod(methodNotAllowed)

	srv := &Server{
		deps:          deps,
		opts:          opts,
		engine:        engine,
		deviceLimiter: newRateLimiter(deviceAuthorizeBurst, deviceAuthorizeWindow, deviceAuthorizeMaxKeys),
		mintLimiter: newRateLimiter(sessionMintFailureBurst, sessionMintFailureWindow,
			sessionMintFailureMaxKeys),
	}
	srv.api = humagin.New(engine, humaConfig(opts))
	srv.api.UseMiddleware(srv.authenticate)
	srv.register()
	return srv
}

// Handler is the http.Handler the role serves, and what tests drive.
func (s *Server) Handler() http.Handler { return s.engine }

// OpenAPI is the emitted document.
func (s *Server) OpenAPI() *huma.OpenAPI { return s.api.OpenAPI() }

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.opts.Addr,
		Handler:           s.engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", s.opts.Addr)
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

	s.deps.Log.Info().Str("addr", s.opts.Addr).Msg("api listening")

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down api: %w", err)
	}
	return <-errs
}
