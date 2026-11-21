package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	tuffetcher "github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/fetch"
	"agent-manager/internal/signing"
	"agent-manager/internal/store"
)

// Config is the credential set the worker bootstrap may draw on. Nothing is
// `required` here: a role's Needs say which credentials it must have, and
// Build fails fast when one is missing.
type Config struct {
	config.Observability

	DatabaseURL       string        `env:"DATABASE_URL"`
	RiverDatabaseURL  string        `env:"RIVER_DATABASE_URL"`
	BlobURL           string        `env:"BLOB_URL"`
	FetchTimeout      time.Duration `env:"FETCH_TIMEOUT" envDefault:"60s"`
	OutboundAllowlist []string      `env:"OUTBOUND_ALLOWLIST" envSeparator:","`
	GitHubToken       string        `env:"GITHUB_TOKEN"`
	UpstreamInterval  time.Duration `env:"UPSTREAM_INTERVAL" envDefault:"1h"`
	// SigstoreTrustedRoot is a trusted_root.json; empty fetches the public-good
	// root over TUF through the outbound client.
	SigstoreTrustedRoot string `env:"SIGSTORE_TRUSTED_ROOT"`
}

// Built is a role's dependencies plus the handles that back them.
type Built struct {
	Deps Deps

	store  *store.Handle
	bucket *blob.Bucket
}

// Queue is the pool River works against; nil for a role with no database access.
func (b *Built) Queue() *pgxpool.Pool {
	if b.store == nil {
		return nil
	}
	return b.store.Queue()
}

func (b *Built) Close() error {
	var errs []error
	if b.bucket != nil {
		if err := b.bucket.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if b.store != nil {
		if err := b.store.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Build constructs exactly what def.Needs declares. An undeclared capability
// comes back nil rather than widening the role's reach; a declared one with no
// credential behind it is a startup error.
func Build(ctx context.Context, def Definition, cfg Config, log zerolog.Logger) (*Built, error) {
	if def.Name == "" {
		return nil, errors.New("worker definition has no name")
	}

	built := &Built{Deps: Deps{Log: log}}

	if def.Needs.DB != AccessNone {
		if cfg.DatabaseURL == "" {
			return nil, fmt.Errorf("worker %s declares DB: %s but AGENT_MANAGER_DATABASE_URL is empty", def.Name, def.Needs.DB)
		}
		// Required alongside it because store.Open opens both pools
		// together, and a worker with no queue is not a worker.
		if cfg.RiverDatabaseURL == "" {
			return nil, fmt.Errorf("worker %s declares DB: %s but AGENT_MANAGER_RIVER_DATABASE_URL is empty", def.Name, def.Needs.DB)
		}

		handle, err := store.Open(ctx, cfg.DatabaseURL, cfg.RiverDatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("worker %s: %w", def.Name, err)
		}
		built.store = handle
		built.Deps.DB = handle.DB()
	}

	if def.Needs.Blob != AccessNone {
		if cfg.BlobURL == "" {
			if err := built.Close(); err != nil {
				log.Error().Err(err).Msg("closing partially built dependencies")
			}
			return nil, fmt.Errorf("worker %s declares Blob: %s but AGENT_MANAGER_BLOB_URL is empty", def.Name, def.Needs.Blob)
		}

		bucket, err := blob.Open(ctx, cfg.BlobURL)
		if err != nil {
			if closeErr := built.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("closing partially built dependencies")
			}
			return nil, fmt.Errorf("worker %s: %w", def.Name, err)
		}
		built.bucket = bucket
		built.Deps.BlobRead = bucket.Reader()

		// This branch is what keeps the fetcher the only role with object-store write access.
		if def.Needs.Blob == AccessReadWrite {
			built.Deps.BlobWrite = bucket.Writer()
		}
	}

	if def.Needs.Outbound {
		client, err := fetch.New(fetch.Options{Timeout: cfg.FetchTimeout, Allowlist: cfg.OutboundAllowlist})
		if err != nil {
			if closeErr := built.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("closing partially built dependencies")
			}
			return nil, fmt.Errorf("worker %s: build the outbound client: %w", def.Name, err)
		}
		built.Deps.Fetch = client
		built.Deps.GitHubToken = cfg.GitHubToken

		verifier, err := signing.New(signing.Options{
			TrustedRootPath: cfg.SigstoreTrustedRoot,
			Fetcher:         tufFetcher(client),
		})
		if err != nil {
			if closeErr := built.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("closing partially built dependencies")
			}
			return nil, fmt.Errorf("worker %s: %w", def.Name, err)
		}
		built.Deps.Signatures = verifier
	}

	return built, nil
}

// tufFetcher sends the Sigstore TUF downloads through the SSRF-guarded client
// rather than go-tuf's own http.DefaultClient.
func tufFetcher(client fetch.Client) *tuffetcher.DefaultFetcher {
	f := tuffetcher.NewDefaultFetcher()
	f.SetHTTPClient(guardedDoer{client: client})
	return f
}

type guardedDoer struct{ client fetch.Client }

func (d guardedDoer) Do(req *http.Request) (*http.Response, error) {
	return d.client.Do(req.Context(), req)
}
