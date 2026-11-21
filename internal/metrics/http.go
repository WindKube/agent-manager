package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "http_requests_total",
		Help:      "HTTP requests by route pattern, method and status class.",
	}, []string{"route", "method", "code"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request latency by route pattern and method.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"route", "method"})
)

// unmatched is the route label of every request no route matched, so a scan
// of random paths costs one series rather than one per path.
const unmatched = "unmatched"

// HTTP records request rate, errors and duration per route pattern. It belongs
// first in the chain, so a recovered panic is counted as the 500 it became.
func HTTP() gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = unmatched
		}
		method := c.Request.Method
		if !knownMethod(method) {
			method = "other"
		}
		httpRequests.WithLabelValues(route, method, StatusClass(c.Writer.Status())).Inc()
		httpDuration.WithLabelValues(route, method).Observe(time.Since(started).Seconds())
	}
}

func knownMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

// Handler serves /metrics and a /healthz that answers 200 while the process
// runs, which is the liveness probe for roles with no listener of their own.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// Serve binds addr before returning, so a port clash fails at start, then serves
// Handler until ctx ends. An empty addr returns a no-op stop.
func Serve(ctx context.Context, addr string, log zerolog.Logger) (stop func(), err error) {
	if addr == "" {
		return func() {}, nil
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics: listen on %s: %w", addr, err)
	}

	server := &http.Server{Handler: Handler(), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error().Err(serveErr).Msg("metrics listener stopped")
		}
	}()
	log.Info().Str("addr", addr).Msg("metrics listening")

	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		<-done
	}, nil
}
