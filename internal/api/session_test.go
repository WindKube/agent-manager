package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The identity operations' container-free half; the database half is in session_integration_test.go.

type idTokens struct {
	claims auth.Claims
	err    error
}

func (v idTokens) Verify(context.Context, string) (auth.Claims, error) { return v.claims, v.err }

const mintSecret = "a-configured-session-mint-secret"

// mintRequest takes an address because the refusal cap is keyed on it; reusing
// one would get later table cases a 429.
func mintRequest(t *testing.T, h http.Handler, secret, from string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions",
		strings.NewReader(`{"idToken":"an.id.token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = from + ":54321"
	if secret != "" {
		req.Header.Set(api.SessionMintHeader, secret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTheDocumentSaysTheSessionMintIsAuthenticatedByItsOwnSchemeAndNotThatItIsPublic(t *testing.T) {
	doc := api.Document(api.Options{})

	scheme := doc.Components.SecuritySchemes[api.SessionMintScheme]
	require.NotNil(t, scheme, "the session mint's secret is undeclared, so the document does not say "+
		"what guards the one operation that can mint a session for any subject")
	require.Equal(t, "apiKey", scheme.Type)
	require.Equal(t, "header", scheme.In)
	require.Equal(t, api.SessionMintHeader, scheme.Name,
		"the scheme and the constant the handler reads must name one header, or the generated "+
			"client sends the secret where nothing looks for it")

	op := doc.Paths["/v1/sessions"].Post
	require.NotNil(t, op)
	require.Equal(t, []map[string][]string{{api.SessionMintScheme: {}}}, op.Security,
		"an empty security array would publish this operation as unauthenticated, which it is not")
}

func TestTheOnlyOperationThatDoesNotRequireASessionTokenIsTheMintAndThePublicThree(t *testing.T) {
	doc := api.Document(api.Options{})

	// Named rather than derived from the Security fields, which would assert nothing.
	unauthenticated := map[string]bool{
		"health": true, "deviceAuthorize": true, "deviceToken": true, "createSession": true,
	}

	seen := 0
	for path, item := range doc.Paths {
		for _, op := range []*huma.Operation{item.Get, item.Post, item.Put, item.Delete, item.Patch} {
			if op == nil {
				continue
			}
			seen++
			requiresBearer := op.Security == nil
			for _, requirement := range op.Security {
				if _, ok := requirement[api.BearerScheme]; ok {
					requiresBearer = true
				}
			}
			require.Equalf(t, !unauthenticated[op.OperationID], requiresBearer,
				"%s %s (%s) disagrees with the list above about whether it needs a session",
				op.Method, path, op.OperationID)
		}
	}
	require.GreaterOrEqual(t, seen, 14, "walked %d operations, which is fewer than exist", seen)
}

func TestTheSessionMintIsRefusedWithoutTheSecretAndNeedsNoBearerToken(t *testing.T) {
	h := handler(t, api.Deps{
		SessionMintSecret: mintSecret,
		// Refusing, so passing the secret check is recognisable by the verifier's status.
		IDTokens: idTokens{err: errors.New("the signature did not verify")},
	})

	// No Authorization header below: the caller holds a secret, not a session.
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "", "198.51.100.1").Code)
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "not-the-secret", "198.51.100.2").Code)

	require.Equal(t, http.StatusUnprocessableEntity, mintRequest(t, h, mintSecret, "198.51.100.3").Code)
}

func TestAHubWithNoSharedSecretRefusesEveryMintAsUnavailable(t *testing.T) {
	h := handler(t, api.Deps{IDTokens: idTokens{claims: auth.Claims{Subject: "sub-1"}}})

	rec := mintRequest(t, h, "", "198.51.100.10")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var body contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.CorrelationID, "an operator's only route back to the log line")
}

func TestRefusedMintsAreCappedPerAddressAndSucceedingOnesAreNotCounted(t *testing.T) {
	h := handler(t, api.Deps{
		SessionMintSecret: mintSecret,
		// Always refuses, with a status the cap must not count.
		IDTokens: idTokens{err: errors.New("the signature did not verify")},
	})

	const attacker = "203.0.113.7"
	for i := range 5 {
		require.Equalf(t, http.StatusUnauthorized, mintRequest(t, h, "guess", attacker).Code,
			"guess %d should still be answered", i+1)
	}

	blocked := mintRequest(t, h, "guess", attacker)
	require.Equal(t, http.StatusTooManyRequests, blocked.Code)
	retryAfter, err := strconv.Atoi(blocked.Header().Get("Retry-After"))
	require.NoError(t, err, "a 429 with no Retry-After tells a caller to retry immediately")
	require.Positive(t, retryAfter)

	// The cap is per address, so one attacker does not lock out other callers.
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "guess", "203.0.113.8").Code)

	// An accepted secret is never counted; behind one proxy every sign-in shares this key.
	const web = "203.0.113.20"
	for i := range 20 {
		require.Equalf(t, http.StatusUnprocessableEntity, mintRequest(t, h, mintSecret, web).Code,
			"request %d from the web role was refused by the cap rather than by the token", i+1)
	}
}

func TestTheViewerIsWhatThisRequestResolvedToAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal auth.Principal
		want      contract.Viewer
	}{
		{
			name: "an identity with a mapped role",
			principal: auth.Principal{
				Subject: "sub-kw", Email: "kwiatrzyk@example.dev", DisplayName: "Krzysztof Wiatrzyk",
				Groups: []string{"platform", "security"}, Role: models.OrgRoleCatalogAdmin,
			},
			want: contract.Viewer{
				Subject: "sub-kw", Email: "kwiatrzyk@example.dev", DisplayName: "Krzysztof Wiatrzyk",
				Role: "catalog-admin", HasRole: true, Groups: []string{"platform", "security"},
			},
		},
		{
			// hasRole is separate from role so a screen cannot fall through into an empty catalog.
			name: "an identity whose groups map to nothing",
			principal: auth.Principal{
				Subject: "sub-new", Email: "newcomer@example.dev", DisplayName: "A Newcomer",
				Groups: []string{"contractors"},
			},
			want: contract.Viewer{
				Subject: "sub-new", Email: "newcomer@example.dev", DisplayName: "A Newcomer",
				HasRole: false, Groups: []string{"contractors"},
			},
		},
		{
			// No groups must serialise as [] rather than null.
			name:      "an identity with no email and no groups",
			principal: auth.Principal{Subject: "sub-bare", DisplayName: "sub-bare"},
			want:      contract.Viewer{Subject: "sub-bare", DisplayName: "sub-bare", Groups: []string{}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := handler(t, api.Deps{Sessions: resolver{principal: tc.principal}})

			rec := request(t, h, http.MethodGet, "/v1/viewer", "a-session-token", "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			var got contract.Viewer
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			require.Equal(t, tc.want, got)
			require.Contains(t, rec.Body.String(), `"groups":[`,
				"groups must be an array on the wire even when it is empty")
		})
	}
}

func TestNeitherTheViewerNorSignOutHasAnAnonymousForm(t *testing.T) {
	h := handler(t, api.Deps{Sessions: resolver{err: auth.ErrUnauthenticated}})

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/viewer"},
		{http.MethodDelete, "/v1/sessions/current"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			require.Equal(t, http.StatusUnauthorized, request(t, h, tc.method, tc.path, "", "").Code,
				"with no token at all")
			require.Equal(t, http.StatusUnauthorized,
				request(t, h, tc.method, tc.path, "a-token-that-resolves-to-nothing", "").Code,
				"with a token that resolves to nothing")
		})
	}
}
