package api_test

import (
	"net/http"
	"regexp"
	"sort"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/auth"
)

// serviceTokenAllowlist is every operation a service token may call. Adding to
// it is a security decision.
var serviceTokenAllowlist = map[string][]string{
	"getRevision":      {"sync:profile"},
	"getBundle":        {"sync:profile", "read:catalog"},
	"reportSync":       {"sync:profile"},
	"listPackages":     {"read:catalog"},
	"getPackage":       {"read:catalog"},
	"listPackageFiles": {"read:catalog"},
	"getPackageFile":   {"read:catalog"},
	"getPackageScan":   {"read:catalog"},
}

type documentedOperation struct {
	method, path string
	op           *huma.Operation
}

func everyOperation(t *testing.T) []documentedOperation {
	t.Helper()

	var out []documentedOperation
	for path, item := range api.Document(api.Options{}).Paths {
		for method, op := range map[string]*huma.Operation{
			http.MethodGet: item.Get, http.MethodPost: item.Post, http.MethodPut: item.Put,
			http.MethodPatch: item.Patch, http.MethodDelete: item.Delete,
		} {
			if op != nil {
				out = append(out, documentedOperation{method: method, path: path, op: op})
			}
		}
	}
	require.Greater(t, len(out), 40, "the document must have been walked, not skipped")
	sort.Slice(out, func(i, j int) bool { return out[i].op.OperationID < out[j].op.OperationID })
	return out
}

func bearerAuthenticated(op *huma.Operation) bool {
	if op.Security == nil {
		return true
	}
	for _, requirement := range op.Security {
		if _, ok := requirement[api.BearerScheme]; ok {
			return true
		}
	}
	return false
}

func TestOnlyTheAllowlistAcceptsServiceTokens(t *testing.T) {
	got := map[string][]string{}
	for _, d := range everyOperation(t) {
		if scopes := api.ServiceTokenScopes(d.op); len(scopes) > 0 {
			got[d.op.OperationID] = scopes
		}
	}
	require.Equal(t, serviceTokenAllowlist, got)
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// The handlers here have no database, so a 403 proves the refusal came before the handler.
func TestEveryOperationOffTheAllowlistRefusesAServiceToken(t *testing.T) {
	everything := auth.Principal{Source: auth.SourceServiceToken, ServiceToken: &auth.ServiceTokenGrant{
		ID: uuid.New(), Name: "ci",
		Scopes: []auth.Scope{auth.ScopeReadCatalog, auth.SyncProfileScope("x")},
	}}
	h := handler(t, api.Deps{Sessions: resolver{principal: everything}})

	refused := 0
	for _, d := range everyOperation(t) {
		if !bearerAuthenticated(d.op) || len(api.ServiceTokenScopes(d.op)) > 0 {
			continue
		}
		t.Run(d.op.OperationID, func(t *testing.T) {
			rec := request(t, h, d.method, pathParam.ReplaceAllString(d.path, "x"), "amst_x", "{}")
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
		refused++
	}
	require.Greater(t, refused, 30)
}

func TestAnOperationOnTheAllowlistStillNeedsTheMatchingScope(t *testing.T) {
	syncOnly := auth.Principal{ServiceToken: &auth.ServiceTokenGrant{
		ID: uuid.New(), Scopes: []auth.Scope{auth.SyncProfileScope("a")},
	}}
	h := handler(t, api.Deps{Sessions: resolver{principal: syncOnly}})

	rec := request(t, h, http.MethodGet, "/v1/packages", "amst_x", "")
	require.Equal(t, http.StatusForbidden, rec.Code, "listing the catalog needs read:catalog")

	rec = request(t, h, http.MethodGet, "/v1/profiles/b/revisions/head", "amst_x", "")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "sync:profile/b")

	catalogOnly := auth.Principal{ServiceToken: &auth.ServiceTokenGrant{
		ID: uuid.New(), Scopes: []auth.Scope{auth.ScopeReadCatalog},
	}}
	h = handler(t, api.Deps{Sessions: resolver{principal: catalogOnly}})
	rec = request(t, h, http.MethodGet, "/v1/profiles/a/revisions/head", "amst_x", "")
	require.Equal(t, http.StatusForbidden, rec.Code, "resolving a lockfile needs a sync scope")
}
