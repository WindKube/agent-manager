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

// runSeed is the one-shot that loads the design's dataset (001 FR-057).
//
// It opens the pools itself instead of calling store.Open, and that is the
// config's doing rather than an omission: config.Seed names the application
// database and the bucket and NOTHING ELSE. store.Open requires the queue URL as
// well, because the pair of them is what lets it refuse the one misconfiguration
// that would put Atlas in front of River's tables — and a role that enqueues
// nothing has no business holding a queue credential (principle II).
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

	// Both halves of the bucket. This is the only role besides the fetcher that
	// gets a writer, and the reason is in the compose comment beside its service:
	// the seed writes bundle bytes as well as rows.
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
	// The mint secret is the ONE credential this role holds, and it buys exactly
	// one operation: asking the api to open a session for an identity whose ID
	// token verified. Empty is not a fallback — the api refuses every mint when it
	// holds no secret, and hub.MintSession refuses before the call when this side
	// holds none.
	client, err := hub.New(cfg.APIBaseURL, hub.WithSessionMintSecret(cfg.SessionMintSecret))
	if err != nil {
		return err
	}

	// The browser half of sign-in needs the provider's endpoints and its keys, and
	// getting them reaches the network — on first use, not here. A failure to
	// CONFIGURE is not fatal either: the role still answers its health probe, and
	// the sign-in screen states that the provider cannot be reached and offers no
	// action rather than a button known to fail (contracts/auth.md).
	authProvider, err := webAuthProvider(cfg)
	if err != nil {
		log.Error().Err(err).Msg("configure the identity provider; sign-in is unavailable in this process")
	}

	server := web.New(web.Deps{
		Catalog:   client,
		Packages:  client,
		Registrar: client,
		Auth:      authProvider,
		// Both are the same client, and they are two fields because they are two
		// claims: resolving the viewer is something a fixture can honestly do, and
		// minting a session is not.
		Viewers:  client,
		Sessions: client,
		// The two governance screens (US4). Four fields for the same client again,
		// and again because they are four different claims: reading findings, deciding
		// one, reading the audit log, and counting what this viewer may see.
		Scanner:  client,
		Reviewer: client,
		Audit:    client,
		Badges:   client,
		// The profile screens. Same client again: reading a profile and
		// curating one are different claims, and the fixture behind screen tests
		// answers only the first.
		Profiles: client,
		Curator:  client,
		Device:   client,
		Log:      log,
	}, web.Options{
		Addr: cfg.Addr,
		// Read for exactly one decision — the Secure flag on both cookies — and read
		// here rather than from each request, so a proxy that terminates TLS cannot
		// talk this role out of it.
		PublicBaseURL: cfg.PublicBaseURL,
		// The api's own address, for the command the Connect-the-CLI screen prints.
		HubURL: cfg.HubURL,
		// FR-119's ONE gate. The hint is shown because an operator asked for it in
		// this variable and for no other reason: nothing below derives it from the
		// issuer, the host name or the build type.
		ProviderName:      cfg.ProviderName,
		DevCredentialHint: cfg.DevCredentialHint,
		DevCredentials:    devCredentials(cfg.DevCredentialHint),
	})

	return server.Run(ctx)
}

// webAuthProvider discovers the provider and builds the browser flow over it.
//
// Two things about it are deliberate:
//
// It returns the INTERFACE and returns a nil interface on failure, never a typed
// nil pointer. web.Deps.Auth is compared against nil to decide whether the sign-in
// screen may offer an action at all, and a typed nil satisfies that comparison and
// then panics on the first click.
//
// Discovery is LAZY, as the api's is (api.NewLazyVerifier). Both methods of
// web.Discovery take a context and can fail, so a lazy implementation has
// somewhere to say "not yet" — and the alternative costs a restart: a web role
// started in the same `docker compose up` as its provider would race it, discover
// nothing, and then serve the provider-unreachable screen for ever even after the
// provider came up healthy. Failing per-request instead means the first sign-in
// after the provider answers succeeds, and until then the callback path renders
// contracts/auth.md's second failure, which is the honest screen either way.
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
		// The one value in this system that reaches exactly one function
		// (research R2): the authorization redirect, whose host is the only URL in
		// the flow a browser has to be able to resolve.
		BrowserBaseURL: cfg.BrowserBaseURL,
	})
}

// lazyDiscovery is web.Discovery over auth.Verifier, discovering on first use.
//
// It exists because auth.Verifier's own Endpoint() cannot fail — it is an
// accessor on a provider that has already been discovered — while web.Discovery's
// can, which is the whole point of the interface. This is the piece that turns one
// into the other, and it lives in internal/cli because that is where the roles are
// assembled; internal/web may not link auth (internal/archcheck refuses it, since
// that package reads the session table).
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

// resolve discovers once. A failure is NOT cached: the provider being down at the
// first attempt is the case this type exists for, so the next request tries again.
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

// devCredentials is FR-119's hint content, built here rather than in internal/web.
//
// The placement is the requirement, not a convenience: SC-106 makes a display name
// or an address in the role that renders screens a defect, and the sweep over
// internal/web's own source is what keeps one out. The values come from
// internal/seed's directory constants — the same ones the local directory fixture
// is checked against — so the hint cannot drift from the accounts it names.
//
// The username is the mail rather than the account name, because the mail is what
// the provider searches on: a hint naming the other one sends a person to a login
// form that refuses them.
func devCredentials(enabled bool) []view.Credential {
	if !enabled {
		return nil
	}

	credentials := make([]view.Credential, 0, len(seed.DirectoryUsers))
	for _, user := range seed.DirectoryUsers {
		role := seed.RoleOf(user.Group)
		if role == "" {
			// The directory's third person is in a group this hub maps to nothing, and
			// the hint says so rather than leaving the column blank. A blank there reads
			// as a rendering fault next to two filled ones, and this row is the only way
			// to reach FR-117's screen on the local stack — so it is worth finding.
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
