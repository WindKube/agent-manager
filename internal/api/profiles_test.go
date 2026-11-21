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

// Profile refusals, with no database: a 403 or 422 here proves the refusal came
// before any query, since reaching one would panic on the nil handle.

func profileHandler(t *testing.T, principal auth.Principal) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: principal}})
}

// Creating a profile is authorised by the organisation role, since there is no
// membership to consult yet; read-only callers consume and do not create.
func TestCreatingAProfileIsRefusedToAnIdentityWithNoStandingToCreateOne(t *testing.T) {
	body := `{"slug":"example/new-profile","name":"New profile"}`

	for _, tc := range []struct {
		name string
		role models.OrgRole
		want int
	}{
		{
			name: "a catalog admin creates profiles",
			role: models.OrgRoleCatalogAdmin,
			// Getting past 403 is the assertion; the status comes from the missing database.
			want: http.StatusInternalServerError,
		},
		{
			name: "a scanner reviewer holds it too, because the precedence order says the top roles are not the weaker one",
			role: models.OrgRoleScannerReviewer,
			want: http.StatusInternalServerError,
		},
		{
			name: "a profile consumer is exactly who profiles are for",
			role: models.OrgRoleProfileConsumer,
			want: http.StatusInternalServerError,
		},
		{
			name: "a read-only identity may consume the organisation's profiles and not create one",
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
			h := profileHandler(t, auth.Principal{
				IdentityID: uuid.Must(uuid.NewV7()),
				Subject:    "sub-x",
				Email:      "x@example.dev",
				Role:       tc.role,
			})

			rec := request(t, h, http.MethodPost, "/v1/profiles", "token", body)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

func TestTheProfileCreationRefusalNamesTheRolesThatWouldHaveWorked(t *testing.T) {
	h := profileHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})

	rec := request(t, h, http.MethodPost, "/v1/profiles", "token",
		`{"slug":"example/p","name":"P"}`)
	require.Equal(t, http.StatusForbidden, rec.Code)

	var body contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body.Detail, "create a profile")
	// All three, so dropping one from the allowed set fails the test.
	require.Contains(t, body.Detail, "catalog-admin")
	require.Contains(t, body.Detail, "scanner-reviewer")
	require.Contains(t, body.Detail, "profile-consumer")
}

// An operation that opted out with `security: []` would be public.
func TestEveryProfileOperationNeedsASession(t *testing.T) {
	h := handler(t, api.Deps{Sessions: resolver{err: auth.ErrUnauthenticated}})

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/profiles", ""},
		{http.MethodGet, "/v1/profiles/example%2Fone", ""},
		{http.MethodPost, "/v1/profiles", `{"slug":"example/one","name":"One"}`},
		{http.MethodPut, "/v1/profiles/example%2Fone/entries", `{"entries":[]}`},
		{http.MethodPut, "/v1/profiles/example%2Fone/sharing",
			`{"members":[{"kind":"user","ref":"a@example.dev","role":"owner"}]}`},
		{http.MethodPut, "/v1/profiles/example%2Fone/targets", `{"targets":["codex"]}`},
		{http.MethodPost, "/v1/profiles/example%2Fone/revisions", `{}`},
		{http.MethodGet, "/v1/profiles/example%2Fone/revisions/head", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "", tc.body)
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		})
	}
}

// The enums live in struct tags; a dropped tag would turn this 422 into a 500 from a Postgres enum.
func TestAProfileBodyOutsideItsVocabularyIsRefusedBeforeAnyStatement(t *testing.T) {
	h := profileHandler(t, auth.Principal{
		IdentityID: uuid.Must(uuid.NewV7()),
		Subject:    "sub-x",
		Email:      "x@example.dev",
		Role:       models.OrgRoleCatalogAdmin,
	})

	for _, tc := range []struct{ name, method, path, body string }{
		{"a visibility the column has no value for", http.MethodPost, "/v1/profiles",
			`{"slug":"example/p","name":"P","visibility":"public"}`},
		{"a slug that is not URL-safe", http.MethodPost, "/v1/profiles",
			`{"slug":"Example Platform!","name":"P"}`},
		{"a tracking mode that is not one of the three", http.MethodPut, "/v1/profiles/example%2Fp/entries",
			`{"entries":[{"id":"example/x","mode":"newest"}]}`},
		{"a membership role the enum does not hold", http.MethodPut, "/v1/profiles/example%2Fp/sharing",
			`{"members":[{"kind":"user","ref":"a@example.dev","role":"admin"}]}`},
		{"a subject kind that is neither a person nor a group", http.MethodPut,
			"/v1/profiles/example%2Fp/sharing",
			`{"members":[{"kind":"team","ref":"platform","role":"owner"}]}`},
		{"a sync target this hub does not write", http.MethodPut, "/v1/profiles/example%2Fp/targets",
			`{"targets":["agents-md"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "token", tc.body)
			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
		})
	}
}

// A profile slug has several segments but the path template has one parameter,
// so an encoded slash must route; with gin's defaults every path here is a 404.
func TestAProfileSlugOfSeveralSegmentsReachesItsOperations(t *testing.T) {
	h := profileHandler(t, auth.Principal{
		IdentityID: uuid.Must(uuid.NewV7()),
		Subject:    "sub-x",
		Email:      "x@example.dev",
		Role:       models.OrgRoleCatalogAdmin,
	})

	// oapi-codegen's `simple` style escapes path parameters, so the slash arrives as %2F.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/profiles/example%2Fplatform-engineer", ""},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/entries", `{"entries":[]}`},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/sharing",
			`{"members":[{"kind":"user","ref":"a@example.dev","role":"owner"}]}`},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/targets", `{"targets":[]}`},
		{http.MethodPost, "/v1/profiles/example%2Fplatform-engineer/revisions", `{}`},
		{http.MethodGet, "/v1/profiles/example%2Fplatform-engineer/revisions/head", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "token", tc.body)
			// Anything but a 404 proves the router matched.
			require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		})
	}
}

// The revision number is allocated inside the transaction, so the caller learns
// it from Location rather than guessing head+1.
func TestPublishingIsDeclaredAsACreationThatNamesWhatItCreated(t *testing.T) {
	document := api.Document(api.Options{})

	item := document.Paths["/v1/profiles/{slug}/revisions"]
	require.NotNil(t, item, "the publish operation is not registered")
	require.NotNil(t, item.Post)
	require.Equal(t, "publishRevision", item.Post.OperationID)

	created := item.Post.Responses["201"]
	require.NotNil(t, created, "publishing declares no 201")
	require.NotNil(t, created.Content["application/json"])
	require.Contains(t, created.Headers, "Location")

	// The gate-mode test reads the detail operation, so it must not be renamed silently.
	detail := document.Paths["/v1/profiles/{slug}"]
	require.NotNil(t, detail, "the profile detail operation is not registered")
	require.NotNil(t, detail.Get)
	require.Equal(t, "getProfile", detail.Get.OperationID)
}
