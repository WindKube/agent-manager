// Package logging provides the project's zerolog setup and the correlation-id
// plumbing every role shares.
package logging

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type ctxKey struct{}

// CorrelationField is the log key carrying a request or job correlation id.
const CorrelationField = "correlation_id"

// New builds the root logger for a role.
func New(role, level, format string) zerolog.Logger {
	var w io.Writer = os.Stdout
	if strings.EqualFold(format, "console") {
		w = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	}

	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil || level == "" {
		lvl = zerolog.InfoLevel
	}

	return zerolog.New(w).Level(lvl).With().
		Timestamp().
		Str("role", role).
		Logger()
}

// Into stores a logger on the context.
func Into(ctx context.Context, l zerolog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// From returns the context's logger, or a disabled one when absent.
func From(ctx context.Context) zerolog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(zerolog.Logger); ok {
		return l
	}
	return zerolog.Nop()
}

// WithCorrelation derives a logger and context tagged with a correlation id.
func WithCorrelation(ctx context.Context, id string) (context.Context, zerolog.Logger) {
	l := From(ctx).With().Str(CorrelationField, id).Logger()
	return Into(ctx, l), l
}
