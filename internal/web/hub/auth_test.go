package hub_test

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// Sign-in's half of this package (T038). As next door, the assertions are on the
// WIRE — the headers the stub api receives and the raw JSON it answers with —
// because the two roles only ever meet over HTTP.

// TestTheSecretTravelsOnTheHeaderTheEmittedDocumentDeclares closes the one seam
// this package cannot close with a compiler.
//
// internal/archcheck forbids internal/web from importing internal/api, which is
// the boundary that keeps this role free of a datastore credential — so the header
// name exists as a constant here AND as a constant there, and nothing makes them
// agree. The joint is the emitted document (constitution principle V): the api
// declares the header on its security scheme, `task gen:client` writes the
// document, and this reads it back. A rename on either side fails here.
func TestTheSecretTravelsOnTheHeaderTheEmittedDocumentDeclares(t *testing.T) {
	raw, err := os.ReadFile("../../apiclient/openapi.json")
	require.NoError(t, err, "the emitted document is missing — run `task gen:client`")

	var doc struct {
		Components struct {
			SecuritySchemes map[string]struct {
				Type string `json:"type"`
				In   string `json:"in"`
				Name string `json:"name"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	scheme, ok := doc.Components.SecuritySchemes["sessionMintSecret"]
	require.True(t, ok, "the emitted document declares no session-mint scheme, so the api is no "+
		"longer authenticating that operation the way this package sends it")
	require.Equal(t, "apiKey", scheme.Type)
	require.Equal(t, "header", scheme.In)
	require.Equal(t, hub.SessionMintHeader, scheme.Name)
}

func TestTheMintSecretIsSentOnTheMintAndOnNoOtherCall(t *testing.T) {
	const secret = "the-shared-secret"

	seen := map[string]string{}
	client := clientAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path] = r.Header.Get(hub.SessionMintHeader)
		switch r.URL.Path {
		case "/v1/sessions":
			writeJSON(w, http.StatusOK, `{"token":"t","expiresAt":"2026-08-31T12:00:00Z","expiresIn":43200}`)
		case "/v1/viewer":
			writeJSON(w, http.StatusOK, `{"subject":"s","displayName":"d","email":"e","hasRole":false,"groups":[]}`)
		default:
			writeJSON(w, http.StatusOK, `{"packages":[],"total":0,"page":1,"pageSize":10,"categories":[],"tags":[]}`)
		}
	}, hub.WithSessionMintSecret(secret))

	_, err := client.MintSession(t.Context(), "an.id.token")
	require.NoError(t, err)
	_, err = client.Viewer(t.Context())
	require.NoError(t, err)
	_, err = client.Catalog(t.Context(), view.CatalogQuery{})
	require.NoError(t, err)

	require.Equal(t, secret, seen["/v1/sessions"])
	// The credential this role holds buys exactly one operation, and it is sent as
	// a per-request editor rather than installed on the client so that this stays
	// true when a fourth call is added.
	require.Empty(t, seen["/v1/viewer"])
	require.Empty(t, seen["/v1/packages"])
}

func TestAMintWithNoSecretConfiguredIsRefusedBeforeItReachesTheApi(t *testing.T) {
	reached := false
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		writeJSON(w, http.StatusOK, `{"token":"t","expiresAt":"2026-08-31T12:00:00Z","expiresIn":1}`)
	})

	_, err := client.MintSession(t.Context(), "an.id.token")
	require.ErrorIs(t, err, hub.ErrMintRefused)
	require.False(t, reached, "a hub with no secret must not ask the api to mint, and must not "+
		"present an empty secret as if it were one")
}

func TestARefusedMintIsOneErrorWhateverTheApiSaidAndRepeatsNoSecret(t *testing.T) {
	const secret = "the-shared-secret"

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "the two secrets disagree", status: http.StatusUnauthorized,
			body: `{"title":"Unauthorized","status":401,"detail":"the session mint secret is not accepted"}`},
		{name: "the hub cannot mint at all", status: http.StatusServiceUnavailable,
			body: `{"title":"Service Unavailable","status":503,"detail":"this hub cannot mint sessions"}`},
		{name: "the id token did not verify", status: http.StatusUnprocessableEntity,
			body: `{"title":"Unprocessable Entity","status":422,"detail":"the id token did not verify"}`},
		{name: "too many refused mints", status: http.StatusTooManyRequests,
			body: `{"title":"Too Many Requests","status":429,"detail":"too many refused session mints"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, hub.WithSessionMintSecret(secret))

			session, err := client.MintSession(t.Context(), "an.id.token")
			// One sentinel for all four: contracts/auth.md gives every refused mint
			// the same rendering, and a caller that could tell them apart is a caller
			// that could tell a browser which one it was.
			require.ErrorIs(t, err, hub.ErrMintRefused)
			require.Empty(t, session.Token)
			require.Contains(t, err.Error(), "the api answered "+strconv.Itoa(tc.status),
				"the status is what an operator needs to tell a wrong secret from a missing one")
			require.NotContains(t, err.Error(), secret)
		})
	}
}

func TestAMintedSessionCarriesTheApisOwnExpiryRatherThanALocalSubtraction(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		// An expiresAt from a clock 40 minutes behind this process's, which is what a
		// skewed pair of containers looks like. The cookie's Max-Age must come from
		// expiresIn regardless, or it either outlives the row or dies early.
		writeJSON(w, http.StatusOK,
			`{"token":"a-session-token","expiresAt":"2026-08-31T11:20:00Z","expiresIn":43200}`)
	}, hub.WithSessionMintSecret("the-shared-secret"))

	session, err := client.MintSession(t.Context(), "an.id.token")
	require.NoError(t, err)
	require.Equal(t, "a-session-token", session.Token)
	require.Equal(t, 12*time.Hour, session.ExpiresIn)
	require.Equal(t, time.Date(2026, 8, 31, 11, 20, 0, 0, time.UTC), session.ExpiresAt.UTC())
}

func TestTheViewerIsMappedFromTheApisAnswerAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want hub.Viewer
	}{
		{
			name: "an identity with a mapped role",
			body: `{"subject":"sub-kw","displayName":"Krzysztof Wiatrzyk","email":"kwiatrzyk@example.dev",
			        "role":"catalog-admin","hasRole":true,"groups":["platform","security"]}`,
			want: hub.Viewer{
				Subject: "sub-kw", DisplayName: "Krzysztof Wiatrzyk", Email: "kwiatrzyk@example.dev",
				Role: "catalog-admin", HasRole: true, Groups: []string{"platform", "security"},
			},
		},
		{
			// FR-117: the role is absent from the body, not empty in it, and HasRole
			// is what a screen branches on.
			name: "an identity whose groups map to nothing",
			body: `{"subject":"sub-new","displayName":"A Newcomer","email":"newcomer@example.dev",
			        "hasRole":false,"groups":["contractors"]}`,
			want: hub.Viewer{
				Subject: "sub-new", DisplayName: "A Newcomer", Email: "newcomer@example.dev",
				HasRole: false, Groups: []string{"contractors"},
			},
		},
		{
			// A null groups array becomes an empty slice here rather than reaching a
			// template as nil, for the same reason the api never emits one.
			name: "a body whose groups are null",
			body: `{"subject":"sub-bare","displayName":"sub-bare","email":"","hasRole":false,"groups":null}`,
			want: hub.Viewer{Subject: "sub-bare", DisplayName: "sub-bare", Groups: []string{}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, tc.body)
			})

			viewer, err := client.Viewer(t.Context())
			require.NoError(t, err)
			require.Equal(t, tc.want, viewer)
		})
	}
}

func TestA401IsTheSignedOutStateOnBothTheViewerAndSignOut(t *testing.T) {
	client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401,"detail":"missing, expired or invalid token"}`))
	})

	_, err := client.Viewer(t.Context())
	require.ErrorIs(t, err, view.ErrSignedOut)

	// On sign-out this is the state the person asked for: the session was already
	// gone. It is the one error a sign-out handler may swallow.
	require.ErrorIs(t, client.SignOut(t.Context()), view.ErrSignedOut)
}

func TestOnly204MeansTheSessionWasActuallyExpired(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{status: http.StatusNoContent, wantErr: false},
		// Anything else and the row may still be live. Clearing the cookie without
		// reporting that is a credential still valid to whoever else holds it.
		{status: http.StatusInternalServerError, wantErr: true},
		{status: http.StatusBadGateway, wantErr: true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			client := clientAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})

			err := client.SignOut(t.Context())
			if tc.wantErr {
				require.Error(t, err)
				require.NotErrorIs(t, err, view.ErrSignedOut)
				return
			}
			require.NoError(t, err)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var out any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		panic(err)
	}
	_ = json.NewEncoder(w).Encode(out)
}
