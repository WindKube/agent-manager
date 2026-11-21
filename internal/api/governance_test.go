package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// Governance refusals, with no database: a hidden button can still send the
// request, so this layer must refuse it, and proving that must not need a container.

// governanceHandler has no database, so a 403 or 422 proves the refusal came before any query.
func governanceHandler(t *testing.T, principal auth.Principal) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: principal}})
}

func TestAdjudicatingAFindingIsRefusedToEveryRoleButTheReviewers(t *testing.T) {
	id := uuid.Must(uuid.NewV7()).String()

	for _, tc := range []struct {
		name string
		role models.OrgRole
		want int
	}{
		{
			name: "a scanner reviewer is who the operation is for",
			role: models.OrgRoleScannerReviewer,
			// Getting past 403 is the assertion; the status comes from the missing database.
			want: http.StatusInternalServerError,
		},
		{
			name: "a catalog admin holds it too, because the precedence order says the top role is not the weaker one",
			role: models.OrgRoleCatalogAdmin,
			want: http.StatusInternalServerError,
		},
		{
			name: "a profile consumer may read the screen and not decide on it",
			role: models.OrgRoleProfileConsumer,
			want: http.StatusForbidden,
		},
		{
			name: "a read-only identity is refused",
			role: models.OrgRoleReadOnly,
			want: http.StatusForbidden,
		},
		{
			name: "an identity whose groups map to no role at all is refused, and not defaulted into one",
			role: "",
			want: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := governanceHandler(t, auth.Principal{
				IdentityID: uuid.Must(uuid.NewV7()),
				Subject:    "sub-x",
				Email:      "x@example.dev",
				Role:       tc.role,
			})

			for _, path := range []string{"/v1/findings/" + id + "/accept", "/v1/findings/" + id + "/reject"} {
				rec := request(t, h, http.MethodPost, path, "token", `{"note":"considered"}`)
				require.Equal(t, tc.want, rec.Code, "%s answered %s", path, rec.Body.String())
			}
		})
	}
}

// The refusal names what the action needed, so holding no mapped group is
// distinguishable from holding the wrong one.
func TestTheRefusalNamesTheRoleTheActionNeeded(t *testing.T) {
	h := governanceHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})
	id := uuid.Must(uuid.NewV7()).String()

	rec := request(t, h, http.MethodPost, "/v1/findings/"+id+"/accept", "token", `{"note":"n"}`)
	require.Equal(t, http.StatusForbidden, rec.Code)

	var body contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body.Detail, "scanner-reviewer")
	require.Contains(t, body.Detail, "catalog-admin")
}

// A non-uuid path parameter is malformed, not a missing finding: a 404 would be a claim about the data.
func TestAMalformedFindingIDIsRefusedBeforeAnyStatement(t *testing.T) {
	h := governanceHandler(t, auth.Principal{
		IdentityID: uuid.Must(uuid.NewV7()),
		Subject:    "sub-x",
		Role:       models.OrgRoleScannerReviewer,
	})

	for _, tc := range []struct{ name, method, path, body string }{
		{"the detail pane", http.MethodGet, "/v1/findings/not-a-uuid", ""},
		{"accept", http.MethodPost, "/v1/findings/not-a-uuid/accept", `{"note":"n"}`},
		{"reject", http.MethodPost, "/v1/findings/not-a-uuid/reject", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "token", tc.body)
			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
		})
	}
}

func TestAcceptingWithoutANoteIsRefused(t *testing.T) {
	h := governanceHandler(t, auth.Principal{
		IdentityID: uuid.Must(uuid.NewV7()),
		Subject:    "sub-x",
		Role:       models.OrgRoleScannerReviewer,
	})
	id := uuid.Must(uuid.NewV7()).String()

	for _, body := range []string{`{"note":""}`, `{"note":"   "}`, `{}`} {
		rec := request(t, h, http.MethodPost, "/v1/findings/"+id+"/accept", "token", body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "body %s answered %s", body, rec.Body.String())
	}
}

// Catches a governance operation that opted out of the root bearer requirement.
func TestEveryGovernanceOperationNeedsASession(t *testing.T) {
	h := handler(t, api.Deps{Sessions: resolver{err: auth.ErrUnauthenticated}})
	id := uuid.Must(uuid.NewV7()).String()

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/scanner/summary", ""},
		{http.MethodGet, "/v1/findings", ""},
		{http.MethodGet, "/v1/findings/" + id, ""},
		{http.MethodPost, "/v1/findings/" + id + "/accept", `{"note":"n"}`},
		{http.MethodPost, "/v1/findings/" + id + "/reject", `{}`},
		{http.MethodGet, "/v1/audit", ""},
		{http.MethodGet, "/v1/audit/export", ""},
		{http.MethodGet, "/v1/badges", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "", tc.body)
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		})
	}
}

// huma cannot infer a body for a StreamResponse, so an undeclared 200 would
// silently leave generated clients with no field for it.
func TestTheAuditExportDeclaresItsStreamedResponse(t *testing.T) {
	document := api.Document(api.Options{})

	item := document.Paths["/v1/audit/export"]
	require.NotNil(t, item)
	require.NotNil(t, item.Get)

	response := item.Get.Responses["200"]
	require.NotNil(t, response, "the export's 200 is undeclared")
	require.Contains(t, response.Content, "application/x-ndjson")
	require.NotNil(t, response.Content["application/x-ndjson"].Schema)
	require.Contains(t, response.Headers, "Content-Disposition")
}
