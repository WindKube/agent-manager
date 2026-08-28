package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"agent-manager/internal/blob"
	"agent-manager/internal/config"
	"agent-manager/internal/fetch"
	"agent-manager/internal/store"
)

// Config is the credential set the worker bootstrap may draw on.
//
// Nothing here is `required`: which credentials a role must have is stated by its
// Needs, and Build fails fast when a declared need has no credential behind it.
// Marking them required in the env struct instead would force every role to carry
// every credential, which is exactly the coupling principle II forbids. Per-role
// knobs (the rule-pack directory, the scan budget) stay in the role's own struct
// in internal/config and are read by its Definition, not here.
type Config struct {
	config.Observability

	DatabaseURL       string        `env:"DATABASE_URL"`
	RiverDatabaseURL  string        `env:"RIVER_DATABASE_URL"`
	BlobURL           string        `env:"BLOB_URL"`
	FetchTimeout      time.Duration `env:"FETCH_TIMEOUT" envDefault:"60s"`
	OutboundAllowlist []string      `env:"OUTBOUND_ALLOWLIST" envSeparator:","`
}

// Built is a role's dependencies plus the handles that back them.
type Built struct {
	Deps Deps

	store  *store.Handle
	bucket *blob.Bucket
}

// Queue is the pool River works against. It is opened alongside the application
// handle (two URLs, two pools — principle IX), so it is nil for a role that
// declares no database access.
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

// Build constructs exactly what def.Needs declares, and nothing else.
//
// The two rules that make this the enforcement point for principle II:
//
//   - An undeclared capability comes back nil. A role that did not declare
//     Blob: AccessReadWrite gets a nil BlobWrite, which panics on first use in a
//     test rather than quietly widening the role's reach in production.
//   - A declared capability with no credential behind it is a startup error, not a
//     nil. Failing fast here is the difference between a container that will not
//     start and a worker that silently does half its job.
func Build(ctx context.Context, def Definition, cfg Config, log zerolog.Logger) (*Built, error) {
	if def.Name == "" {
		return nil, errors.New("worker definition has no name")
	}

	built := &Built{Deps: Deps{Log: log}}

	if def.Needs.DB != AccessNone {
		if cfg.DatabaseURL == "" {
			return nil, fmt.Errorf("worker %s declares DB: %s but AGENT_MANAGER_DATABASE_URL is empty", def.Name, def.Needs.DB)
		}
		// The queue URL is required alongside it because store.Open opens both pools
		// together and a worker with no queue is not a worker. The two URLs stay two
		// parameters: one URL for both is the defect that signature exists to make
		// impossible to express.
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

		// The write half only for AccessReadWrite. This single branch is the whole
		// of "the fetcher is the only role with object-store write access".
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
	}

	return built, nil
}
