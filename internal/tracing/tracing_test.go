package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"OTEL_SDK_DISABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	} {
		t.Setenv(key, "")
	}
}

func TestTracingIsOffUntilAnEndpointIsSet(t *testing.T) {
	clearEnv(t)
	require.False(t, Enabled())

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	require.True(t, Enabled())

	t.Setenv("OTEL_SDK_DISABLED", "true")
	require.False(t, Enabled(), "OTEL_SDK_DISABLED wins over an endpoint")
}

func TestSetupWithoutAnEndpointLeavesTheNoopProvider(t *testing.T) {
	clearEnv(t)
	before := otel.GetTracerProvider()

	shutdown, err := Setup(context.Background(), "api", "dev")
	require.NoError(t, err)
	require.NoError(t, shutdown(context.Background()))
	require.Equal(t, before, otel.GetTracerProvider())
}

func TestSetupRefusesAProtocolItCannotSpeak(t *testing.T) {
	clearEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

	_, err := Setup(context.Background(), "api", "dev")
	require.ErrorContains(t, err, "only http/protobuf")
}

func TestOnlyTheInternalTransportSendsTraceHeaders(t *testing.T) {
	clearEnv(t)
	_, err := Setup(context.Background(), "test", "dev")
	require.NoError(t, err)

	headers := make(chan http.Header, 2)
	receiver := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
	}))
	t.Cleanup(receiver.Close)

	provider := sdktrace.NewTracerProvider()
	ctx, span := provider.Tracer("test").Start(context.Background(), "parent")
	defer span.End()

	for _, rt := range []http.RoundTripper{Transport(http.DefaultTransport), OpaqueTransport(http.DefaultTransport)} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, receiver.URL, http.NoBody)
		require.NoError(t, err)
		resp, err := (&http.Client{Transport: rt}).Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}

	require.Contains(t, (<-headers).Get("Traceparent"), span.SpanContext().TraceID().String())
	require.Empty(t, (<-headers).Get("Traceparent"), "an outside host must not learn internal trace ids")
}
