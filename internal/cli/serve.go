package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/logging"
	"agent-manager/internal/metrics"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store"
	"agent-manager/internal/tracing"
)

func newServeCmd() *cobra.Command {
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run a serving role",
	}
	serve.AddCommand(newServeAPICmd(), newServeWebCmd())
	return serve
}

func newServeAPICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "REST API, OIDC, device flow and the outbox relay",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAPI(cmd.Context())
		},
	}
}

func newServeWebCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "Web UI (holds no datastore credential)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWeb(cmd.Context())
		},
	}
}

// healthProbeKey is never written: "no such key" already proves the bucket is
// reachable, authenticated and exists.
const healthProbeKey = "_health/probe"

// runAPI is the api role's bootstrap. It opens exactly what config.API names:
// the application database, the queue database and the bucket.
func runAPI(ctx context.Context) error {
	cfg, err := config.Load[config.API]()
	if err != nil {
		return err
	}
	log := logging.New("api", cfg.LogLevel, cfg.LogFormat)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stopTracing, err := startTracing(ctx, "api", log)
	if err != nil {
		return err
	}
	defer stopTracing()

	stopMetrics, err := metrics.Serve(ctx, cfg.MetricsBind, log)
	if err != nil {
		return err
	}
	defer stopMetrics()

	handle, err := store.Open(ctx, cfg.DatabaseURL, cfg.RiverDatabaseURL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close database handles")
		}
	}()

	// Fatal: otherwise the failure shows up later as a hub nobody can administer.
	if changed, ensureErr := commands.EnsureAdminGroup(ctx, handle.DB(), cfg.BootstrapAdminGroup); ensureErr != nil {
		return fmt.Errorf("reconcile the bootstrap admin group: %w", ensureErr)
	} else if changed {
		log.Info().Str("group", cfg.BootstrapAdminGroup).
			Msg("bootstrap admin group reconciled to catalog-admin")
	}

	bucket, err := blob.Open(ctx, cfg.BlobURL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := bucket.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close bucket")
		}
	}()

	// The relay lives beside the transactions that write the outbox rows it drains.
	relay, err := startRelay(ctx, handle, cfg, log)
	if err != nil {
		return err
	}
	defer relay()

	server := api.New(api.Deps{
		DB: handle.DB(),
		// A reader only: `worker fetcher` is the sole writer of bundle bytes.
		Bundles: bucket.Reader(),
		Sessions: auth.Chain{
			Sessions:      auth.NewSessions(handle.DB()),
			ServiceTokens: auth.NewServiceTokens(handle.DB()),
		},
		// ID tokens are verified here, in the role that owns identity, not in web.
		// Discovery is lazy so a slow provider cannot take this role down with it.
		IDTokens: api.NewLazyVerifier(auth.VerifierConfig{
			Issuer:       cfg.Issuer,
			DiscoveryURL: cfg.DiscoveryURL,
			ClientID:     cfg.ClientID,
		}),
		// Empty refuses every session mint; commands.SessionMint enforces it.
		SessionMintSecret: cfg.SessionMintSecret,
		// IdentityConfig has no ClientSecret field, so getOrganization cannot leak it.
		Identity: commands.IdentityConfig{
			Issuer:       cfg.Issuer,
			DiscoveryURL: cfg.DiscoveryURL,
			ClientID:     cfg.ClientID,
			Scopes:       cfg.Scopes,
		},
		Probes: []api.Probe{
			{Name: "database", Check: handle.Ping},
			{Name: "objectstore", Check: func(ctx context.Context) error {
				_, existsErr := bucket.Reader().Exists(ctx, healthProbeKey)
				return existsErr
			}},
		},
		Log:     log,
		Storage: bucket.Inspector(),
		// Same pool the outbox relay inserts through; read-only here since
		// queries.RuntimeQueue declares no write method.
		Queue: handle.Queue(),
	}, api.Options{
		Addr:                  cfg.Addr,
		PublicBaseURL:         cfg.PublicBaseURL,
		DeviceVerificationURL: cfg.DeviceVerificationURL,
		DeviceCodeTTL:         cfg.DeviceCodeTTL,
		DeviceTokenTTL:        cfg.DeviceTokenTTL,
		SessionTTL:            cfg.SessionTTL,
		Middleware:            []gin.HandlerFunc{metrics.HTTP(), tracing.Gin("api", "/v1/health")},
	})

	return server.Run(ctx)
}

// startRelay launches the outbox relay and returns its stopper. Failure is
// fatal, since without it published packages are silently never fetched.
func startRelay(ctx context.Context, handle *store.Handle, cfg config.API, log zerolog.Logger) (func(), error) {
	client, err := outbox.NewInsertClient(handle.Queue(), nil)
	if err != nil {
		return nil, err
	}

	relay, err := outbox.NewRelay(handle.DB(), outbox.RiverInserter(client), outbox.RelayConfig{
		AppDatabaseURL: cfg.DatabaseURL,
	}, log)
	if err != nil {
		return nil, err
	}

	relayCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if runErr := relay.Run(relayCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			log.Error().Err(runErr).Msg("outbox relay stopped")
		}
	}()

	return func() {
		cancel()
		<-done
	}, nil
}
