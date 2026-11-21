package cli

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"agent-manager/internal/tracing"
)

// startTracing installs the role's tracer provider and returns the flush to
// defer. A misconfigured exporter is a boot failure, not a silent no-op.
func startTracing(ctx context.Context, role string, log zerolog.Logger) (func(), error) {
	shutdown, err := tracing.Setup(ctx, role, Version)
	if err != nil {
		return nil, err
	}
	if tracing.Enabled() {
		log.Info().Msg("exporting traces over OTLP")
	}
	return func() {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := shutdown(flushCtx); err != nil {
			log.Warn().Err(err).Msg("flush traces")
		}
	}, nil
}
