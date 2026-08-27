// Package api is the HTTP surface of the `serve api` role: a gin router carrying
// huma operations, from which the OpenAPI 3.1 document is emitted.
//
// Constitution principle V: the document at /v1/openapi.json is generated from
// the operation definitions in operations.go and is never hand-maintained. The
// frozen machine-facing subset in specs/001-agent-manager-hub/contracts is a
// contract this document must remain a superset of, not a file to copy.
//
// Principle VIII: reads live in queries/, writes in commands/, split from the
// first handler. No command bus, no event sourcing, no read replica.
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

	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
)

func init() {
	// gin's mode is a package global read on every engine construction, so it is
	// set once here rather than from New, where parallel callers would race.
	gin.SetMode(gin.ReleaseMode)

	// One error shape across every operation, including the ones huma itself
	// produces for request validation (see errors.go).
	huma.NewError = newHumaError

	// huma types arrays as `["array","null"]` by default, on the reasoning that a
	// nil Go slice marshals to null. The frozen contract types them as `array` and
	// lists them as required, so the fix is at the source instead: handlers emit an
	// empty slice, never nil, and the document says what it means.
	huma.DefaultArrayNullable = false
}

// Probe is one dependency /v1/health reports on. The api role holds them rather
// than reaching for the store or the bucket itself, so a role that gains a
// dependency declares it here instead of the health handler growing a branch.
type Probe struct {
	Name  string
	Check func(context.Context) error
}

// Deps is what the api role is handed. Every field is narrow on purpose
// (principle VII): the api gets a blob *reader*, so there is no writer in scope
// to assert back to — only `worker fetcher` may write bundle bytes.
type Deps struct {
	DB       bun.IDB
	Bundles  blob.Reader
	Sessions auth.Resolver
	Probes   []Probe
	Log      zerolog.Logger
}

// Options is the run-time configuration of the surface itself.
type Options struct {
	// Addr is the listen address, e.g. ":8081".
	Addr string
	// PublicBaseURL is the externally reachable base URL. It is emitted as the
	// document's single server entry and is what the device flow's
	// verification_uri is built from.
	PublicBaseURL string
	// DeviceCodeTTL and DeviceTokenTTL are advertised by the device endpoints.
	DeviceCodeTTL  time.Duration
	DeviceTokenTTL time.Duration
	// HealthTimeout caps how long a dependency probe may take before the role
	// reports itself unready.
	HealthTimeout time.Duration
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
	return o
}

// Server is the assembled surface. It owns no connections: everything it touches
// arrives through Deps, which is what lets Document build the same routes with no
// database in sight.
type Server struct {
	deps   Deps
	opts   Options
	engine *gin.Engine
	api    huma.API
}

// New assembles the router. It performs no I/O, so a zero Deps is a valid
// argument and yields a server that emits the document and nothing else.
func New(deps Deps, opts Options) *Server {
	opts = opts.withDefaults()

	engine := gin.New()
	// Off by default in gin, which answers a wrong method with 404. A client that
	// used the wrong verb deserves to be told so.
	engine.HandleMethodNotAllowed = true
	engine.Use(correlation(deps.Log), recovery())
	engine.NoRoute(notFound)
	engine.NoMethod(methodNotAllowed)

	srv := &Server{deps: deps, opts: opts, engine: engine}
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
