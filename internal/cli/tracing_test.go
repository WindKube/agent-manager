package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"agent-manager/internal/api"
	"agent-manager/internal/tracing"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The web role's hub client and the api role's router, wired exactly as the
// bootstraps wire them: a span open in web must be the parent of the api's
// server span, through real HTTP and the W3C headers.
func TestTheTraceContinuesFromTheWebClientIntoTheAPIHandler(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })

	_, err := tracing.Setup(context.Background(), "test", "dev")
	require.NoError(t, err)

	server := api.New(api.Deps{Log: zerolog.Nop()}, api.Options{
		Middleware: []gin.HandlerFunc{tracing.Gin("api", "/v1/health")},
	})
	upstream := httptest.NewServer(server.Handler())
	t.Cleanup(upstream.Close)

	client, err := hub.New(upstream.URL, hub.WithTransport(tracing.Transport(http.DefaultTransport)))
	require.NoError(t, err)

	ctx, root := provider.Tracer("web").Start(context.Background(), "GET /catalog")
	_, _ = client.Catalog(ctx, view.CatalogQuery{})
	root.End()

	var clientSpan, serverSpan sdktrace.ReadOnlySpan
	for _, span := range recorder.Ended() {
		switch span.SpanKind() {
		case trace.SpanKindClient:
			clientSpan = span
		case trace.SpanKindServer:
			serverSpan = span
		}
	}
	require.NotNil(t, clientSpan, "the hub client must open a client span")
	require.NotNil(t, serverSpan, "the api must open a server span")

	require.Equal(t, root.SpanContext().TraceID(), serverSpan.SpanContext().TraceID(), "one trace across both roles")
	require.Equal(t, root.SpanContext().SpanID(), clientSpan.Parent().SpanID())
	require.Equal(t, clientSpan.SpanContext().SpanID(), serverSpan.Parent().SpanID(),
		"the api's span must be the child of web's outbound call, not a new root")
	require.True(t, serverSpan.Parent().IsRemote())
	require.Equal(t, "GET /v1/packages", serverSpan.Name(), "server spans are named by route pattern")
}
