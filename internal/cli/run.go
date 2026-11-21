package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"golang.org/x/oauth2"

	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/logging"
	"agent-manager/internal/metrics"
	"agent-manager/internal/outbox"
	"agent-manager/internal/seed"
	"agent-manager/internal/store/models"
	"agent-manager/internal/tracing"
	"agent-manager/internal/web"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/roles"
)

// runSeed loads the design dataset. It skips store.Open because config.Seed
// deliberately holds no queue credential.
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

	// The only role besides the fetcher with a bucket writer: the seed writes bundle bytes too.
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

// runWeb is the web role's bootstrap. config.Web has no database or bucket
// credential, and that absence is the credential boundary.
func runWeb(ctx context.Context) error {
	cfg, err := config.Load[config.Web]()
	if err != nil {
		return err
	}
	log := logging.New("web", cfg.LogLevel, cfg.LogFormat)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stopTracing, err := startTracing(ctx, "web", log)
	if err != nil {
		return err
	}
	defer stopTracing()

	stopMetrics, err := metrics.Serve(ctx, cfg.MetricsBind, log)
	if err != nil {
		return err
	}
	defer stopMetrics()

	// The mint secret is this role's only credential. Empty is not a fallback:
	// both sides refuse every mint without it.
	client, err := hub.New(cfg.APIBaseURL,
		hub.WithSessionMintSecret(cfg.SessionMintSecret),
		hub.WithTransport(tracing.Transport(http.DefaultTransport)))
	if err != nil {
		return err
	}

	// Not fatal: the role still answers its health probe and sign-in offers no action.
	authProvider, err := webAuthProvider(cfg)
	if err != nil {
		log.Error().Err(err).Msg("configure the identity provider; sign-in is unavailable in this process")
	}

	// Parsed at boot so a typo fails loudly instead of looking like "no dashboard configured".
	riverUI, err := riverUIURL(cfg.RiverUIURL)
	if err != nil {
		return err
	}

	cookieKey, err := webCookieKey(cfg.CookieKey)
	if err != nil {
		return err
	}
	if cookieKey == nil {
		log.Warn().Msg("AGENT_MANAGER_WEB_COOKIE_KEY is unset; the sign-in cookie key is per process, " +
			"so a sign-in in flight across a restart or a second replica fails")
	}

	server := web.New(web.Deps{
		Hub:  client,
		Auth: authProvider,
		Log:  log,
	}, web.Options{
		Addr: cfg.Addr,
		// Fixes the cookies' Secure flag so a TLS-terminating proxy cannot drop it per request.
		PublicBaseURL:     cfg.PublicBaseURL,
		HubURL:            cfg.HubURL,
		ProviderName:      cfg.ProviderName,
		DevCredentialHint: cfg.DevCredentialHint,
		DevCredentials:    devCredentials(cfg.DevCredentialHint),
		RiverUI:           riverUI,
		OIDCCookieKey:     cookieKey,
		Middleware:        []gin.HandlerFunc{metrics.HTTP(), tracing.Gin("web", "/healthz")},
	})

	return server.Run(ctx)
}

// webCookieKey decodes the configured sign-in cookie key, nil when none is set.
func webCookieKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, errors.New("WEB_COOKIE_KEY: not base64")
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("WEB_COOKIE_KEY: decodes to %d bytes, needs at least 32", len(key))
	}
	return key, nil
}

// riverUIURL parses the dashboard base URL, nil when unset. A path is refused
// rather than joined, since the dashboard is mounted under this role's own prefix.
func riverUIURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("RIVER_UI_URL %q: %w", raw, err)
	}
	switch {
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return nil, fmt.Errorf("RIVER_UI_URL %q: scheme must be http or https", raw)
	case parsed.Host == "":
		return nil, fmt.Errorf("RIVER_UI_URL %q: needs a host", raw)
	case parsed.Path != "" && parsed.Path != "/":
		return nil, fmt.Errorf("RIVER_UI_URL %q: must carry no path", raw)
	}
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}, nil
}

// webAuthProvider builds the browser sign-in flow. It returns a nil interface on
// failure, never a typed nil, since web.Deps.Auth is nil-checked. Discovery is
// lazy so a role started alongside its provider does not lose the race forever.
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
		// The only URL in the flow a browser has to be able to resolve.
		BrowserBaseURL: cfg.BrowserBaseURL,
	})
}

// lazyDiscovery adapts auth.Verifier to web.Discovery, discovering on first use.
// internal/web may not import auth directly, since auth reads the session table.
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

// resolve discovers once; a failure is not cached.
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

// devCredentials builds the dev sign-in hint from internal/seed's constants, so
// it cannot drift from the seeded accounts. The username is the mail, since
// that is what the provider searches on.
func devCredentials(enabled bool) []view.Credential {
	if !enabled {
		return nil
	}

	credentials := make([]view.Credential, 0, len(seed.DirectoryUsers))
	for _, user := range seed.DirectoryUsers {
		role := seed.RoleOf(user.Group)
		if role == "" {
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

// runWorker resolves the name against the role registry and runs it.
func runWorker(ctx context.Context, name string) error {
	def, err := roles.Lookup(name)
	if err != nil {
		return err
	}

	cfg, err := config.Load[worker.Config]()
	if err != nil {
		return err
	}

	// Shut down on signal so River's graceful stop can finish in-flight jobs.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stopTracing, err := startTracing(ctx, name, logging.New("worker/"+name, cfg.LogLevel, cfg.LogFormat))
	if err != nil {
		return err
	}
	defer stopTracing()

	return worker.Run(ctx, def, cfg)
}

func listWorkers(w io.Writer) error { return roles.List(w) }

// runMigrateQueue applies River's migrations to the queue database only; the
// application database is migrated by Atlas, and neither sees the other's tables.
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
