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

// The governance surface's authorisation and its refusals, with no database.
//
// Every case here is decided before a statement is issued, which is exactly why
// it can be asserted without one — and why it must be: FR-126 is satisfied by a
// screen that hides a button, and this is the layer that has to refuse the request
// the hidden button could still have sent. A test that needed a container to prove
// a role check would be a test nobody runs on the change that breaks it.

// governanceHandler is a router whose Deps hold NO database. Any operation that
// reached a query would panic on the nil handle, so a 403 or a 422 from here is
// proof the refusal happened first.
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
			// Past the role check and into the command, which has no database. The
			// status is not the assertion here; getting past 403 is.
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

// The refusal has to name what the action needed, or a person holding no mapped
// group cannot tell that from holding the wrong one — which is the confusion
// FR-117 exists to remove and FR-126 asks the screen to state.
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

// A path parameter that is not a uuid is refused as a malformed request and not
// as a missing finding: a 404 is a claim about the data, and this request never
// named a finding at all.
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

// An accept with no note is refused. FR-028 asks for a RECORDED note, and an
// override whose reason is the empty string is an unexplained exception that
// nothing later can reconstruct.
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

// Every governance operation inherits the document's root bearer requirement.
// None of them is public, and the emitted document is what says so — an operation
// that forgot to declare security would be authenticated by default, and this is
// the test that would notice one that opted out.
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

// The export declares its own 200 with a media type and a schema. huma infers a
// response body from the handler's return type and a StreamResponse has none, so
// an undeclared 200 would leave a generated client with no field for it and no
// error either — the failure mode operations.go warns about in the device flow.
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
