package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// resolver is a stand-in for auth.Sessions. The container-free tests here are
// about the surface — status codes, the error shape, the correlation id, who may
// call what — none of which needs a database.
type resolver struct {
	principal auth.Principal
	err       error
}

func (r resolver) Resolve(context.Context, string) (auth.Principal, error) {
	return r.principal, r.err
}

func handler(t *testing.T, deps api.Deps) http.Handler {
	t.Helper()
	return api.New(deps, api.Options{}).Handler()
}

func request(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthReportsEveryDependencyAndFailsClosed(t *testing.T) {
	unreachable := errors.New("dial tcp 10.0.0.1:5432: connect: connection refused, user=am_api password=hunter2")

	for _, tc := range []struct {
		name       string
		probes     []api.Probe
		wantStatus int
		wantBody   string
	}{
		{
			name:       "all dependencies reachable is 200",
			probes:     []api.Probe{{Name: "database", Check: func(context.Context) error { return nil }}},
			wantStatus: http.StatusOK,
			wantBody:   "ok",
		},
		{
			name: "one unreachable dependency is 503",
			probes: []api.Probe{
				{Name: "database", Check: func(context.Context) error { return nil }},
				{Name: "objectstore", Check: func(context.Context) error { return unreachable }},
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
		{
			name:       "a probe with no check counts as unreachable",
			probes:     []api.Probe{{Name: "database"}},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler(t, api.Deps{Probes: tc.probes}), http.MethodGet, "/v1/health", "", "")
			require.Equal(t, tc.wantStatus, rec.Code)

			var body contract.Health
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tc.wantBody, body.Status)
			require.Len(t, body.Checks, len(tc.probes))

			// The probe endpoint is unauthenticated, so the driver's message must
			// not reach it: a connection error carries the host and sometimes the
			// whole DSN.
			require.NotContains(t, rec.Body.String(), "hunter2")
			require.NotContains(t, rec.Body.String(), "10.0.0.1")
		})
	}
}

func TestPublicOperationsNeedNoToken(t *testing.T) {
	h := handler(t, api.Deps{Probes: []api.Probe{{Name: "database", Check: func(context.Context) error { return nil }}}})

	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"health is a probe a supervisor calls", http.MethodGet, "/v1/health", "", http.StatusOK},
		{"the emitted document is public", http.MethodGet, "/v1/openapi.json", "", http.StatusOK},
		{
			"deviceAuthorize is unauthenticated by definition and not yet implemented",
			http.MethodPost, "/v1/device/authorize", `{"client_id":"agent-manager-cli","host":"dev-laptop-01"}`,
			http.StatusNotImplemented,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "", tc.body)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

func TestSecuredOperationsRefuseAnythingButAValidToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deps   api.Deps
		header string
	}{
		{"no authorization header", api.Deps{Sessions: resolver{}}, ""},
		{"an unknown token", api.Deps{Sessions: resolver{err: auth.ErrUnauthenticated}}, "not-a-real-session-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler(t, tc.deps), http.MethodGet, "/v1/profiles", tc.header, "")
			require.Equal(t, http.StatusUnauthorized, rec.Code)

			var body contract.Error
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, http.StatusUnauthorized, body.Status)
			// One message for missing, unknown and expired alike: telling them
			// apart tells an attacker whether a token ever existed.
			require.NotContains(t, strings.ToLower(body.Detail), "expired session")
		})
	}
}

func TestEveryFailureCarriesTheOneErrorShape(t *testing.T) {
	deps := api.Deps{Sessions: resolver{principal: auth.Principal{Subject: "user@example.com"}}}
	h := handler(t, deps)

	for _, tc := range []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"a path no operation serves", http.MethodGet, "/v1/nope", "", "", http.StatusNotFound},
		{"the wrong method on a real path", http.MethodDelete, "/v1/health", "", "", http.StatusMethodNotAllowed},
		{"a secured operation with no token", http.MethodGet, "/v1/profiles", "", "", http.StatusUnauthorized},
		{
			"a body that fails validation",
			http.MethodPost, "/v1/sync", "session-token", `{"revision":1}`, http.StatusUnprocessableEntity,
		},
		{
			"a path parameter that fails its pattern",
			http.MethodGet, "/v1/profiles/platform-baseline/revisions/head-ish", "session-token", "",
			http.StatusUnprocessableEntity,
		},
		{
			"an operation that is declared but not implemented",
			http.MethodPost, "/v1/device/token", "", "grant_type=x", http.StatusNotImplemented,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, tc.token, tc.body)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
			require.Equal(t, "application/problem+json", strings.Split(rec.Header().Get("Content-Type"), ";")[0])

			var body contract.Error
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tc.want, body.Status)
			require.NotEmpty(t, body.Title)
			require.Equal(t, rec.Header().Get(api.CorrelationHeader), body.CorrelationID,
				"the body's correlation id must be the one the client can read off the response")
			require.NotEmpty(t, body.CorrelationID)
		})
	}
}

func TestCorrelationIDIsEchoedOrReplaced(t *testing.T) {
	h := handler(t, api.Deps{})

	for _, tc := range []struct {
		name, supplied string
		wantEcho       bool
	}{
		{"absent means one is generated", "", false},
		{"a sane id is echoed", "01JC8Z5H8N-worker-3", true},
		{"a header-splitting id is replaced", "abc\r\nX-Injected: yes", false},
		{"an over-long id is replaced", strings.Repeat("a", 65), false},
		{"a log-injecting id is replaced", `" ,"level":"panic"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/health", http.NoBody)
			if tc.supplied != "" {
				// Set directly on the map: net/http refuses to write an invalid
				// header value, and the point is what the server does with one.
				req.Header[http.CanonicalHeaderKey(api.CorrelationHeader)] = []string{tc.supplied}
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			got := rec.Header().Get(api.CorrelationHeader)
			require.NotEmpty(t, got)
			if tc.wantEcho {
				require.Equal(t, tc.supplied, got)
				return
			}
			require.NotEqual(t, tc.supplied, got)
			_, err := uuid.Parse(got)
			require.NoError(t, err, "a replaced correlation id is a fresh uuid")
		})
	}
}
