package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/rs/zerolog"

	"agent-manager/internal/logging"
)

// stopTimeout bounds the graceful shutdown: River stops fetching immediately and
// then waits for jobs in flight.
const stopTimeout = 30 * time.Second

// Run is the whole bootstrap for `agent-manager worker run <name>`.
//
// Nothing here knows which role it is running. That is the point of principle
// VII: this function is what a new Definition must not have to touch.
func Run(ctx context.Context, def Definition, cfg Config) error {
	log := logging.New("worker/"+def.Name, cfg.LogLevel, cfg.LogFormat)
	ctx = logging.Into(ctx, log)

	if len(def.Queues) == 0 {
		return fmt.Errorf("worker %s declares no queues, so it would never work a job", def.Name)
	}

	built, err := Build(ctx, def, cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := built.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("closing worker dependencies")
		}
	}()

	pool := built.Queue()
	if pool == nil {
		return fmt.Errorf("worker %s declares DB: %s, so it has no queue pool to work against", def.Name, def.Needs.DB)
	}

	workers := river.NewWorkers()
	if def.Register == nil {
		return fmt.Errorf("worker %s registers no handlers", def.Name)
	}
	if regErr := def.Register(built.Deps, workers); regErr != nil {
		return fmt.Errorf("worker %s: register handlers: %w", def.Name, regErr)
	}

	queues := make(map[string]river.QueueConfig, len(def.Queues))
	for name, concurrency := range def.Queues {
		queues[name] = river.QueueConfig{MaxWorkers: concurrency}
	}

	periodic := make([]*river.PeriodicJob, 0, len(def.Periodic))
	for i := range def.Periodic {
		periodic = append(periodic, &def.Periodic[i])
	}

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Logger:       slog.New(zerolog.NewSlogHandler(log)),
		PeriodicJobs: periodic,
		Queues:       queues,
		Workers:      workers,
	})
	if err != nil {
		return fmt.Errorf("worker %s: build the river client: %w", def.Name, err)
	}

	log.Info().
		Str("db", def.Needs.DB.String()).
		Str("blob", def.Needs.Blob.String()).
		Bool("outbound", def.Needs.Outbound).
		Int("queues", len(queues)).
		Msg("worker starting")

	if startErr := client.Start(ctx); startErr != nil {
		return fmt.Errorf("worker %s: start: %w", def.Name, startErr)
	}

	<-ctx.Done()

	// The parent context is already cancelled, so the stop needs a live one or
	// River would abandon the jobs it is trying to drain.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
	defer cancel()

	if stopErr := client.Stop(stopCtx); stopErr != nil && !errors.Is(stopErr, context.Canceled) {
		return fmt.Errorf("worker %s: stop: %w", def.Name, stopErr)
	}
	log.Info().Msg("worker stopped")
	return nil
}
