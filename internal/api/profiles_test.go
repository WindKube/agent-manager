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

// The profile surface's refusals, with no database.
//
// Everything here is decided before a statement is issued, which is why it can be
// asserted without one — and why it must be. The handler is handed Deps with a
// nil database, so anything that reached a query would panic on the nil handle
// and answer 500; a 403 or a 422 from these cases is therefore proof the refusal
// came first. Same construction as governance_test.go, for the same reason: a
// test that needed a container to prove a role check is a test nobody runs on the
// change that breaks it.

func profileHandler(t *testing.T, principal auth.Principal) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: principal}})
}

// Creating a profile is the one profile operation authorised by the caller's
// ORGANISATION role rather than by a membership, because there is no membership
// to consult yet. It is refused to `read-only` for the reason registerPackage
// refuses one: a contractor consumes what the organisation publishes and does not
// create organisation state.
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
			// Past the role check and into the command, which has no database. The
			// status is not the assertion; getting past 403 is.
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

// FR-126 asks a screen to state why an action is unavailable, and FR-117 exists
// because a person holding no mapped group cannot otherwise tell that from
// holding the wrong one. The refusal has to name what would have worked.
func TestTheProfileCreationRefusalNamesTheRolesThatWouldHaveWorked(t *testing.T) {
	h := profileHandler(t, auth.Principal{Subject: "sub-x", Role: models.OrgRoleReadOnly})

	rec := request(t, h, http.MethodPost, "/v1/profiles", "token",
		`{"slug":"example/p","name":"P"}`)
	require.Equal(t, http.StatusForbidden, rec.Code)

	var body contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body.Detail, "create a profile")
	// All three, so dropping one from the allowed set is a red test rather than a
	// silently narrower product: FR-126 asks the screen to state what WOULD work,
	// and a list that quietly shed a role states it wrongly.
	require.Contains(t, body.Detail, "catalog-admin")
	require.Contains(t, body.Detail, "scanner-reviewer")
	require.Contains(t, body.Detail, "profile-consumer")
}

// Every profile operation inherits the document's root bearer requirement. An
// operation that opted out with `security: []` would be public, and this is the
// test that would notice one.
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

// A value outside its vocabulary is refused by the document's own schema, before
// a handler runs and therefore before any statement is issued.
//
// This is worth asserting rather than assuming: the enums live in struct tags,
// and a tag dropped in a refactor produces an operation that accepts anything and
// fails somewhere deeper — where the failure is a 500 rather than a 422 and the
// message names a Postgres enum.
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

// A profile slug carries several segments — the representative dataset's are
// `example/platform-engineer` — and the frozen contract gives the path template
// ONE parameter for it. The two are reconcilable only if an encoded slash routes,
// and this is the assertion that it does.
//
// It is worth its own test because the failure is total and silent: with gin's
// defaults every one of these paths answers 404 "no operation at ...", which
// reads as a missing route rather than as a slug that could not fit through one.
// api.go records the measurement; this is what would catch the flags being
// dropped.
func TestAProfileSlugOfSeveralSegmentsReachesItsOperations(t *testing.T) {
	h := profileHandler(t, auth.Principal{
		IdentityID: uuid.Must(uuid.NewV7()),
		Subject:    "sub-x",
		Email:      "x@example.dev",
		Role:       models.OrgRoleCatalogAdmin,
	})

	// The escaped form is what the generated clients send: oapi-codegen's `simple`
	// style escapes a path parameter, so the slash arrives as %2F on the wire.
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/profiles/example%2Fplatform-engineer", ""},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/entries", `{"entries":[]}`},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/sharing",
			`{"members":[{"kind":"user","ref":"a@example.dev","role":"owner"}]}`},
		{http.MethodPut, "/v1/profiles/example%2Fplatform-engineer/targets", `{"targets":[]}`},
		{http.MethodPost, "/v1/profiles/example%2Fplatform-engineer/revisions", `{}`},
		// The operation this configuration was actually broken for before now.
		{http.MethodGet, "/v1/profiles/example%2Fplatform-engineer/revisions/head", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := request(t, h, tc.method, tc.path, "token", tc.body)
			// Deps carry no database, so reaching the query is a 500. Anything but a
			// 404 proves the router matched; a 404 is the whole failure.
			require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		})
	}
}

// The publish operation answers 201 and names the revision it created in a
// Location header, because the caller could not choose the number: it is
// allocated inside the transaction and a concurrent publish may hold the one they
// expected. An operation that returned 200 and no location would leave a client
// guessing head+1.
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

	// And the detail operation is the one T089's gate-mode test reads. It is
	// asserted here so the surface it needs cannot be renamed without notice.
	detail := document.Paths["/v1/profiles/{slug}"]
	require.NotNil(t, detail, "the profile detail operation is not registered")
	require.NotNil(t, detail.Get)
	require.Equal(t, "getProfile", detail.Get.OperationID)
}
