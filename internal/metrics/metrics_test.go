package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRequestsAreCountedByRoutePatternNotRawPath(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(HTTP())
	engine.GET("/v1/packages/:namespace/:name", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/boom", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })

	route := "/v1/packages/:namespace/:name"
	before := testutil.ToFloat64(httpRequests.WithLabelValues(route, http.MethodGet, "2xx"))
	beforeUnmatched := testutil.ToFloat64(httpRequests.WithLabelValues(unmatched, http.MethodGet, "4xx"))
	before5xx := testutil.ToFloat64(httpRequests.WithLabelValues("/boom", http.MethodGet, "5xx"))

	for _, path := range []string{"/v1/packages/acme/one", "/v1/packages/acme/two", "/no/such/1", "/no/such/2", "/boom"} {
		engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, http.NoBody))
	}

	require.Equal(t, before+2, testutil.ToFloat64(httpRequests.WithLabelValues(route, http.MethodGet, "2xx")))
	require.Equal(t, beforeUnmatched+2, testutil.ToFloat64(httpRequests.WithLabelValues(unmatched, http.MethodGet, "4xx")),
		"paths no route matched must share one series")
	require.Equal(t, before5xx+1, testutil.ToFloat64(httpRequests.WithLabelValues("/boom", http.MethodGet, "5xx")))
}

func TestAnUnknownMethodDoesNotMintASeries(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(HTTP())

	before := testutil.ToFloat64(httpRequests.WithLabelValues(unmatched, "other", "4xx"))
	engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/pot", http.NoBody))
	require.Equal(t, before+1, testutil.ToFloat64(httpRequests.WithLabelValues(unmatched, "other", "4xx")))
}

func TestStatusClass(t *testing.T) {
	for status, want := range map[int]string{0: "error", 200: "2xx", 204: "2xx", 302: "3xx", 410: "4xx", 503: "5xx", 999: "error"} {
		require.Equal(t, want, StatusClass(status), "status %d", status)
	}
}

func TestTheHandlerServesMetricsAndLiveness(t *testing.T) {
	ScansTotal.WithLabelValues("clean").Add(0)

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "agent_manager_scans_total")
	require.Contains(t, body, "go_goroutines", "the Go runtime collector must be registered")
	require.Contains(t, body, "process_start_time_seconds", "the process collector must be registered")

	rec = httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAnEmptyAddressDisablesTheListener(t *testing.T) {
	stop, err := Serve(context.Background(), "", zerolog.Nop())
	require.NoError(t, err)
	stop()
}

func TestServeBindsBeforeReturningAndStops(t *testing.T) {
	stop, err := Serve(context.Background(), "127.0.0.1:0", zerolog.Nop())
	require.NoError(t, err)
	stop()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	_, err = Serve(context.Background(), taken.Addr().String(), zerolog.Nop())
	require.Error(t, err, "a port clash must fail the role at start, not in a goroutine")
}

func TestServeAnswersOverTheNetwork(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())

	stop, err := Serve(context.Background(), addr, zerolog.Nop())
	require.NoError(t, err)
	defer stop()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/healthz", http.NoBody)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "ok\n", string(body))
}
