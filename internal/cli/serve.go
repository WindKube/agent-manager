package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/logging"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store"
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

// healthProbeKey is the object the blob probe looks for. It is never written: a
// bucket that answers "no such key" has proved everything the probe needs —
// reachable, authenticated, and the bucket exists.
const healthProbeKey = "_health/probe"

// runAPI is the api role's bootstrap. It opens exactly what config.API names —
// the application database, the queue database and the bucket — and nothing
// else. Which credentials this function can possibly use is the credential
// boundary made visible (constitution principle II, SC-006).
func runAPI(ctx context.Context) error {
	cfg, err := config.Load[config.API]()
	if err != nil {
		return err
	}
	log := logging.New("api", cfg.LogLevel, cfg.LogFormat)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	handle, err := store.Open(ctx, cfg.DatabaseURL, cfg.RiverDatabaseURL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := handle.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close database handles")
		}
	}()

	bucket, err := blob.Open(ctx, cfg.BlobURL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := bucket.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close bucket")
		}
	}()

	// The relay lives in the api role, beside the transactions that write the
	// outbox rows it drains (R5, constitution principle IX).
	relay, err := startRelay(ctx, handle, cfg, log)
	if err != nil {
		return err
	}
	defer relay()

	server := api.New(api.Deps{
		DB: handle.DB(),
		// A reader, not a bucket: only `worker fetcher` may write bundle bytes, and
		// the api holds no value that could.
		Bundles:  bucket.Reader(),
		Sessions: auth.NewSessions(handle.DB()),
		// Verification of a signed-in person's ID token happens HERE, in the role
		// that owns identity, rather than in the web role that received the callback
		// (contracts/auth.md's preferred refinement). The verifier discovers on first
		// use: discovery reaches the provider, and a provider that is slow to start
		// must not take this role's reads, health probe and device flow with it.
		IDTokens: api.NewLazyVerifier(auth.VerifierConfig{
			Issuer:       cfg.Issuer,
			DiscoveryURL: cfg.DiscoveryURL,
			ClientID:     cfg.ClientID,
		}),
		// Empty here means the session mint is refused outright — no default and no
		// development bypass. Nothing above this line enforces that, which is why
		// commands.SessionMint does.
		SessionMintSecret: cfg.SessionMintSecret,
		// The Organization screen's provider panel. ClientSecret is deliberately
		// absent from this value — commands.IdentityConfig has no field for it —
		// which is what makes "getOrganization never returns the secret" true by
		// construction rather than by care taken in a handler.
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
	}, api.Options{
		Addr:                  cfg.Addr,
		PublicBaseURL:         cfg.PublicBaseURL,
		DeviceVerificationURL: cfg.DeviceVerificationURL,
		DeviceCodeTTL:         cfg.DeviceCodeTTL,
		DeviceTokenTTL:        cfg.DeviceTokenTTL,
		SessionTTL:            cfg.SessionTTL,
	})

	return server.Run(ctx)
}

// startRelay launches the outbox relay and returns its stopper. A relay that
// cannot start is fatal: without it a published package never gets fetched or
// scanned, and the failure would otherwise show up as jobs that silently never
// run.
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
