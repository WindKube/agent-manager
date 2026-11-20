//go:build integration

package outbox_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"agent-manager/internal/outbox"
)

// The relay inserts long after the request is gone, so the only way the job
// can point back at the request is the traceparent stored on the outbox row.
func TestTheEnqueuingTraceRidesTheOutboxRowIntoTheJobMetadata(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	provider := sdktrace.NewTracerProvider()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	reqCtx, span := provider.Tracer("test").Start(ctx, "POST /v1/packages")
	marker := uuid.NewString()
	require.NoError(t, handle.DB().RunInTx(reqCtx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := outbox.NewWriter().Enqueue(ctx, tx, job(outbox.KindFetch, marker))
		return err
	}))
	span.End()

	var stored string
	require.NoError(t, appPool.QueryRow(ctx,
		`select traceparent from outbox where payload->>'marker' = $1`, marker).Scan(&stored))
	require.Contains(t, stored, span.SpanContext().TraceID().String())

	require.NoError(t, newRelay(t, outbox.RelayConfig{}).Drain(ctx))

	var metadata string
	require.NoError(t, queuePool.QueryRow(ctx,
		`select coalesce(metadata->>'traceparent', '') from river_job where args->>'marker' = $1`, marker).Scan(&metadata))
	carried := propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": metadata})
	require.Equal(t, span.SpanContext().TraceID(), traceIDOf(carried),
		"the job must carry the enqueuing request's trace, not a fresh one")
}

func TestARowWrittenOutsideATraceStoresNoTraceparent(t *testing.T) {
	requireInfra(t)
	ctx := context.Background()

	marker := uuid.NewString()
	require.NoError(t, handle.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := outbox.NewWriter().Enqueue(ctx, tx, job(outbox.KindFetch, marker))
		return err
	}))

	var stored *string
	require.NoError(t, appPool.QueryRow(ctx,
		`select traceparent from outbox where payload->>'marker' = $1`, marker).Scan(&stored))
	require.Nil(t, stored)
}

func traceIDOf(ctx context.Context) trace.TraceID {
	return trace.SpanContextFromContext(ctx).TraceID()
}
