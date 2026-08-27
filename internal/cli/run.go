package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agent-manager/internal/config"
	"agent-manager/internal/logging"
	"agent-manager/internal/outbox"
	"agent-manager/internal/web"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/roles"
)

// The remaining serving roles land in later layers of this stack. Each is
// replaced by a real bootstrap in the layer that owns it; until then a role
// starts, reports itself and exits 0 so the compose topology can be wired ahead
// of the code. `serve api` is real: see serve.go.

func runSeed(context.Context) error { return notYet("seed") }

// runWeb is the web role's bootstrap. Compare it with runAPI: there is no
// store.Open and no blob.Open here, and config.Web has no field that would let
// there be. That absence is the credential boundary (constitution principle II,
// SC-006), so the catalog arrives through a source the role is handed rather than
// through a connection it opens.
func runWeb(ctx context.Context) error {
	cfg, err := config.Load[config.Web]()
	if err != nil {
		return err
	}
	log := logging.New("web", cfg.LogLevel, cfg.LogFormat)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The role's whole door to data, and the reason it needs no credential: an
	// api base URL and the GENERATED client over it (principle V). The fixture it
	// replaced is still there, still driving internal/web's own screen tests,
	// because a test that needs a running api to render a page is not a screen
	// test.
	client, err := hub.New(cfg.APIBaseURL)
	if err != nil {
		return err
	}

	server := web.New(web.Deps{
		Catalog:   client,
		Registrar: client,
		Log:       log,
	}, web.Options{Addr: cfg.Addr})

	return server.Run(ctx)
}

// runWorker resolves the name against the registry and hands over. Nothing here
// names a role: adding one is a line in internal/worker/roles and nothing else
// (constitution principle VII).
func runWorker(ctx context.Context, name string) error {
	def, err := roles.Lookup(name)
	if err != nil {
		return err
	}

	cfg, err := config.Load[worker.Config]()
	if err != nil {
		return err
	}

	// A worker drains a queue, so it must shut down on the container's signal
	// rather than be killed mid-job; River's graceful stop is what finishes the
	// jobs already in flight.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return worker.Run(ctx, def, cfg)
}

func listWorkers(w io.Writer) error { return roles.List(w) }

// runMigrateQueue applies River's own migrations to the queue database. It reads
// only AGENT_MANAGER_RIVER_DATABASE_URL: the application database has its own
// tool (Atlas) and neither may see the other's tables (principle IX, R11).
func runMigrateQueue(ctx context.Context) error {
	cfg, err := config.Load[config.Migrate]()
	if err != nil {
		return err
	}

	log := logging.New("migrate-queue", cfg.LogLevel, cfg.LogFormat)

	applied, err := outbox.MigrateQueue(ctx, cfg.RiverDatabaseURL, nil)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		log.Info().Msg("queue database is already at the latest river migration")
		return nil
	}
	log.Info().Ints("versions", applied).Msg("applied river migrations")
	return nil
}

// runHealthcheck is real from the start: containers need it before any role is
// implemented, and it depends on nothing.
func runHealthcheck(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: status %d", url, resp.StatusCode)
	}
	return nil
}

func notYet(role string) error {
	fmt.Printf("agent-manager: %s is not implemented in this layer yet\n", role)
	return nil
}
