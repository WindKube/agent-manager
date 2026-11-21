// Package tracing installs OpenTelemetry tracing from the standard OTEL_*
// environment; with no OTLP endpoint it leaves the no-op provider in place.
package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Enabled reports whether the environment asks for traces to be exported.
func Enabled() bool {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return false
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// Setup installs the W3C propagator and, when Enabled, a batching OTLP/HTTP
// tracer provider whose service.name defaults to agent-manager-<role>. The
// returned shutdown flushes whatever is buffered.
func Setup(ctx context.Context, role, version string) (shutdown func(context.Context) error, err error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	noop := func(context.Context) error { return nil }
	if !Enabled() {
		return noop, nil
	}
	for _, key := range []string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL"} {
		if p := os.Getenv(key); p != "" && p != "http/protobuf" {
			return noop, fmt.Errorf("tracing: %s=%s: only http/protobuf is supported", key, p)
		}
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, fmt.Errorf("tracing: build the OTLP exporter: %w", err)
	}

	// Later options win, so OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES
	// override the defaults.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "agent-manager-"+role),
			attribute.String("service.version", version),
		),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	)
	if err != nil && !errors.Is(err, resource.ErrPartialResource) {
		return noop, fmt.Errorf("tracing: build the resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// Gin opens a server span per request, named by route pattern. Routes in quiet
// are not traced.
func Gin(service string, quiet ...string) gin.HandlerFunc {
	return otelgin.Middleware(service, otelgin.WithGinFilter(func(c *gin.Context) bool {
		return !slices.Contains(quiet, c.FullPath())
	}))
}

// Transport traces and propagates trace context, for calls between this system's roles.
func Transport(base http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(base)
}

// OpaqueTransport traces outbound requests but sends no trace headers, so
// external hosts never learn internal trace ids.
func OpaqueTransport(base http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(base, otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator()))
}
