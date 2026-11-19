// Package fakeapi is an in-process stand-in for the api role, for tests of the
// web role. It speaks the wire contract, so the web role is exercised through
// its real generated client rather than through a Go interface.
package fakeapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"agent-manager/internal/apiclient"
)

// routes maps each operationId the web role calls to its method and path.
// TestRoutesExistInTheContract holds this table to internal/apiclient/openapi.json.
var routes = map[string]string{
	"getViewer":     "GET /v1/viewer",
	"createSession": "POST /v1/sessions",
	"deleteSession": "DELETE /v1/sessions/current",

	"listPackages":         "GET /v1/packages",
	"registerPackage":      "POST /v1/packages",
	"previewPackage":       "POST /v1/packages/preview",
	"getPackage":           "GET /v1/packages/{namespace}/{name}",
	"deletePackage":        "DELETE /v1/packages/{namespace}/{name}",
	"listPackageFiles":     "GET /v1/packages/{namespace}/{name}/files",
	"getPackageFile":       "GET /v1/packages/{namespace}/{name}/files/content",
	"getPackageScan":       "GET /v1/packages/{namespace}/{name}/scan",
	"deleteVersion":        "DELETE /v1/packages/{namespace}/{name}/versions/{version}",
	"setPackageVisibility": "PUT /v1/packages/{namespace}/{name}/visibility",
	"setPackageTracking":   "PUT /v1/packages/{namespace}/{name}/tracking",

	"listProfiles":       "GET /v1/profiles",
	"createProfile":      "POST /v1/profiles",
	"getProfile":         "GET /v1/profiles/{slug}",
	"deleteProfile":      "DELETE /v1/profiles/{slug}",
	"setProfileEntries":  "PUT /v1/profiles/{slug}/entries",
	"removeProfileEntry": "POST /v1/profiles/{slug}/entries/remove",
	"publishRevision":    "POST /v1/profiles/{slug}/revisions",
	"getRevision":        "GET /v1/profiles/{slug}/revisions/{revision}",
	"setProfileSharing":  "PUT /v1/profiles/{slug}/sharing",
	"setProfileTargets":  "PUT /v1/profiles/{slug}/targets",

	"scannerSummary": "GET /v1/scanner/summary",
	"listFindings":   "GET /v1/findings",
	"getFinding":     "GET /v1/findings/{id}",
	"acceptFinding":  "POST /v1/findings/{id}/accept",
	"rejectFinding":  "POST /v1/findings/{id}/reject",
	"listAudit":      "GET /v1/audit",
	"exportAudit":    "GET /v1/audit/export",
	"getBadges":      "GET /v1/badges",
	"getStorage":     "GET /v1/storage",
	"getRuntime":     "GET /v1/runtime",

	"getOrganization":        "GET /v1/organization",
	"testIdentityConnection": "POST /v1/organization/identity/test",
	"updatePolicy":           "PUT /v1/organization/policy",
	"createGroupRoleMapping": "POST /v1/organization/mappings",
	"deleteGroupRoleMapping": "DELETE /v1/organization/mappings/{id}",
	"createCategory":         "POST /v1/organization/categories",
	"updateCategory":         "PATCH /v1/organization/categories/{id}",
	"deleteCategory":         "DELETE /v1/organization/categories/{id}",

	"lookupDeviceCode":  "GET /v1/device/authorizations/{user_code}",
	"approveDeviceCode": "POST /v1/device/authorizations/{user_code}/approve",
}

// Routes is the operation table, exported for the contract test.
func Routes() map[string]string {
	out := make(map[string]string, len(routes))
	for k, v := range routes {
		out[k] = v
	}
	return out
}

// Call is one request the fake received.
type Call struct {
	Operation string
	Method    string
	Path      string
	Query     string
	Header    http.Header
	Body      []byte
}

// Decode unmarshals the request body into v, failing the test on error.
func (c Call) Decode(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(c.Body, v); err != nil {
		t.Fatalf("decode %s body %q: %v", c.Operation, c.Body, err)
	}
}

// API is a running fake. Data is read on every request, so a test may change
// it between requests; Handle and Fail replace one operation's behaviour.
type API struct {
	URL  string
	Data *Data

	mu        sync.Mutex
	calls     []Call
	overrides map[string]http.HandlerFunc
}

// New starts a fake seeded with Seed() and stops it when the test ends.
func New(t testing.TB) *API {
	t.Helper()
	api := &API{Data: Seed(), overrides: map[string]http.HandlerFunc{}}

	mux := http.NewServeMux()
	for op, pattern := range routes {
		mux.HandleFunc(pattern, api.dispatch(op))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fakeapi: no route for %s %s", r.Method, r.URL.Path)
		Problem(w, http.StatusNotFound, "no such route")
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api.URL = server.URL
	return api
}

// Handle replaces one operation's behaviour for the rest of the test.
func (a *API) Handle(operation string, h http.HandlerFunc) {
	if _, ok := routes[operation]; !ok {
		panic("fakeapi: unknown operation " + operation)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.overrides[operation] = h
}

// Fail makes one operation answer status with a problem document.
func (a *API) Fail(operation string, status int, detail ...string) {
	msg := http.StatusText(status)
	if len(detail) > 0 {
		msg = detail[0]
	}
	a.Handle(operation, func(w http.ResponseWriter, _ *http.Request) { Problem(w, status, msg) })
}

// FailAll makes every operation answer status: the api is down.
func (a *API) FailAll(status int) {
	for op := range routes {
		a.Fail(op, status)
	}
}

// Calls returns the requests received for one operation, or every request
// when operation is empty.
func (a *API) Calls(operation string) []Call {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Call, 0, len(a.calls))
	for _, c := range a.calls {
		if operation == "" || c.Operation == operation {
			out = append(out, c)
		}
	}
	return out
}

func (a *API) dispatch(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))

		a.mu.Lock()
		a.calls = append(a.calls, Call{
			Operation: op, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Header: r.Header.Clone(), Body: body,
		})
		override := a.overrides[op]
		a.mu.Unlock()

		if override != nil {
			override(w, r)
			return
		}
		if op != "getViewer" && op != "createSession" && !a.authorised(r) {
			Problem(w, http.StatusUnauthorized, "no session")
			return
		}
		a.defaults(op)(w, r)
	}
}

func (a *API) authorised(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// JSON writes v with status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Problem writes an RFC 9457 problem document, as the api does.
func Problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiclient.Error{
		Status: int64(status),
		Title:  http.StatusText(status),
		Detail: &detail,
	})
}
