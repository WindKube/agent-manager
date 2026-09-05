package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"golang.org/x/oauth2"

	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/logging"
	"agent-manager/internal/outbox"
	"agent-manager/internal/seed"
	"agent-manager/internal/store/models"
	"agent-manager/internal/web"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/roles"
)

// runSeed is the one-shot that loads the design's dataset. It opens the
// pools itself instead of calling store.Open: config.Seed names only the
// application database and the bucket, since a role that enqueues
// nothing has no business holding a queue credential.
func runSeed(ctx context.Context) error {
	cfg, err := config.Load[config.Seed]()
	if err != nil {
		return err
	}
	log := logging.New("seed", cfg.LogLevel, cfg.LogFormat)

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open the application pool: %w", err)
	}
	defer pool.Close()

	sqldb := stdlib.OpenDBFromPool(pool)
	defer func() {
		if closeErr := sqldb.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close database handle")
		}
	}()

	db := bun.NewDB(sqldb, pgdialect.New())
	db.RegisterModel(models.All()...)

	bucket, err := blob.Open(ctx, cfg.BlobURL)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := bucket.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("close bucket")
		}
	}()

	// Both halves of the bucket: this is the only role besides the
	// fetcher that gets a writer, since the seed writes bundle bytes too.
	report, err := seed.Run(ctx, seed.Deps{
		DB:        db,
		BlobRead:  bucket.Reader(),
		BlobWrite: bucket.Writer(),
	})
	if err != nil {
		return err
	}

	log.Info().
		Int("packages", report.Packages).
		Int("versions", report.Versions).
		Int("profiles", report.Profiles).
		Int("findings", report.Findings).
		Int("revisions", report.Revisions).
		Int("bundles_written", report.Bundles).
		Int("lockfiles_written", report.Lockfiles).
		Msg("seeded the representative dataset")
	return nil
}

// runWeb is the web role's bootstrap. Unlike runAPI, there is no
// store.Open or blob.Open here, and config.Web has no field that would
// let there be — that absence is the credential boundary, so the catalog
// arrives through a source the role is handed rather than one it opens.
func runWeb(ctx context.Context) error {
	cfg, err := config.Load[config.Web]()
	if err != nil {
		return err
	}
	log := logging.New("web", cfg.LogLevel, cfg.LogFormat)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The mint secret is the one credential this role holds, buying
	// exactly one operation: asking the api to open a session for an
	// identity whose ID token verified. Empty is not a fallback — the api
	// refuses every mint when it holds no secret, and hub.MintSession
	// refuses before the call when this side holds none.
	client, err := hub.New(cfg.APIBaseURL, hub.WithSessionMintSecret(cfg.SessionMintSecret))
	if err != nil {
		return err
	}

	// Getting the provider's endpoints reaches the network on first use,
	// not here. A configure failure is not fatal: the role still answers
	// its health probe, and the sign-in screen offers no action rather
	// than a button known to fail.
	authProvider, err := webAuthProvider(cfg)
	if err != nil {
		log.Error().Err(err).Msg("configure the identity provider; sign-in is unavailable in this process")
	}

	server := web.New(web.Deps{
		Catalog:   client,
		Packages:  client,
		Registrar: client,
		Auth:      authProvider,
		// Same client, different fields: resolving the viewer and minting
		// a session are different claims.
		Viewers:  client,
		Sessions: client,
		// The two governance screens: four different claims over one client.
		Scanner:  client,
		Reviewer: client,
		Audit:    client,
		Badges:   client,
		// The profile screens: reading and curating are different claims.
		Profiles:     client,
		Curator:      client,
		Device:       client,
		Storage:      client,
		Organization: client,
		Log:          log,
	}, web.Options{
		Addr: cfg.Addr,
		// Read once for the Secure flag on both cookies, so a proxy that
		// terminates TLS cannot talk this role out of it per request.
		PublicBaseURL: cfg.PublicBaseURL,
		HubURL:        cfg.HubURL,
		// The hint is shown only because an operator set this variable —
		// nothing derives it from the issuer, host name or build type.
		ProviderName:      cfg.ProviderName,
		DevCredentialHint: cfg.DevCredentialHint,
		DevCredentials:    devCredentials(cfg.DevCredentialHint),
	})

	return server.Run(ctx)
}

// webAuthProvider discovers the provider and builds the browser flow over
// it. It returns the interface and a nil interface on failure, never a
// typed nil pointer — web.Deps.Auth is compared against nil to decide
// whether sign-in may offer an action, and a typed nil would panic on the
// first click. Discovery is lazy: a role started alongside its provider
// in the same compose up would otherwise race it, discover nothing, and
// serve the unreachable screen forever even after the provider came up.
func webAuthProvider(cfg config.Web) (web.AuthProvider, error) {
	return web.NewAuthProvider(web.AuthOptions{
		Discovery: &lazyDiscovery{cfg: auth.VerifierConfig{
			Issuer:       cfg.Issuer,
			DiscoveryURL: cfg.DiscoveryURL,
			ClientID:     cfg.ClientID,
		}},
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		// The authorization redirect's host: the only URL in the flow a
		// browser has to be able to resolve.
		BrowserBaseURL: cfg.BrowserBaseURL,
	})
}

// lazyDiscovery is web.Discovery over auth.Verifier, discovering on first
// use. It exists because auth.Verifier's Endpoint() cannot fail while
// web.Discovery's can; internal/web may not link auth directly, since
// that package reads the session table.
type lazyDiscovery struct {
	cfg auth.VerifierConfig

	mu       sync.Mutex
	verifier *auth.Verifier
}

func (l *lazyDiscovery) Endpoint(ctx context.Context) (oauth2.Endpoint, error) {
	verifier, err := l.resolve(ctx)
	if err != nil {
		return oauth2.Endpoint{}, err
	}
	return verifier.Endpoint(), nil
}

func (l *lazyDiscovery) VerifyIDToken(ctx context.Context, idToken string) error {
	verifier, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	return verifier.VerifyIDToken(ctx, idToken)
}

// resolve discovers once. A failure is not cached, so the next request
// tries again.
func (l *lazyDiscovery) resolve(ctx context.Context) (*auth.Verifier, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.verifier != nil {
		return l.verifier, nil
	}
	verifier, err := auth.NewVerifier(ctx, l.cfg)
	if err != nil {
		return nil, err
	}
	l.verifier = verifier
	return verifier, nil
}

// devCredentials is the dev-hint content, built here rather than in
// internal/web so a display name or address never appears in the role
// that renders screens. Values come from internal/seed's directory
// constants, so the hint can't drift from the accounts it names; the
// username is the mail, since that's what the provider searches on.
func devCredentials(enabled bool) []view.Credential {
	if !enabled {
		return nil
	}

	credentials := make([]view.Credential, 0, len(seed.DirectoryUsers))
	for _, user := range seed.DirectoryUsers {
		role := seed.RoleOf(user.Group)
		if role == "" {
			// Says so rather than leaving the column blank, which would
			// read as a rendering fault next to two filled ones.
			role = "no role (" + user.Group + ")"
		}
		credentials = append(credentials, view.Credential{
			Username: user.Email,
			Password: seed.DirectoryPassword,
			Role:     role,
		})
	}
	return credentials
}

// runWorker resolves the name against the registry and hands over.
// Adding a role is a line in internal/worker/roles and nothing else.
func runWorker(ctx context.Context, name string) error {
	def, err := roles.Lookup(name)
	if err != nil {
		return err
	}

	cfg, err := config.Load[worker.Config]()
	if err != nil {
		return err
	}

	// A worker drains a queue, so it shuts down on signal rather than
	// being killed mid-job; River's graceful stop finishes in-flight jobs.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return worker.Run(ctx, def, cfg)
}

func listWorkers(w io.Writer) error { return roles.List(w) }

// runMigrateQueue applies River's own migrations to the queue database. It
// reads only AGENT_MANAGER_RIVER_DATABASE_URL: the application database
// has its own tool (Atlas), and neither may see the other's tables.
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
