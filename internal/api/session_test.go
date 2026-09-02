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

// The three identity operations' container-free half (T033, T035, T036, T037).
// What needs a database — the row a mint writes, the audit rows, and a role that
// changes under a live session — is in session_integration_test.go.

// idTokens stands in for the api's ID-token verifier.
type idTokens struct {
	claims auth.Claims
	err    error
}

func (v idTokens) Verify(context.Context, string) (auth.Claims, error) { return v.claims, v.err }

const mintSecret = "a-configured-session-mint-secret"

// mintRequest posts a session mint from a named address. The address matters:
// the refusal cap is keyed on it, so a table test that reused one would have its
// later cases answered 429 by its earlier ones.
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

	// Named rather than derived: the point is that the set is short and that
	// growing it is a deliberate act. Deriving the expectation from the same
	// Security fields the middleware reads would assert nothing.
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
		// Refusing, so the request that gets past the secret can be recognised by
		// the status only the verifier produces — no database needed to tell the two
		// halves of this test apart.
		IDTokens: idTokens{err: errors.New("the signature did not verify")},
	})

	// No Authorization header anywhere below. This operation's caller is a role
	// holding a secret, not a person holding a session, so a missing bearer token
	// must not be what refuses it — if it were, the web role could never call it.
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "", "198.51.100.1").Code)
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "not-the-secret", "198.51.100.2").Code)

	// The right secret reaches the verifier, which is the proof that the secret —
	// and not a session — is what admits this call.
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
		// A verifier that always refuses, so a request that passed the secret check
		// still fails — with a status the cap must NOT count.
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

	// The cap is on this address and not on the operation: another caller's
	// sign-ins must not be collateral damage from one attacker.
	require.Equal(t, http.StatusUnauthorized, mintRequest(t, h, "guess", "203.0.113.8").Code)

	// And the property that makes the cap safe to set this low: an ACCEPTED
	// secret is never counted, however many times the mint then fails for another
	// reason. A cap on attempts would be a cap on how many people may sign in per
	// minute, because behind one proxy every sign-in shares this key.
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
			// FR-117. The role is empty and hasRole is false, and the two are
			// separate fields so a screen cannot fall through this state into an
			// empty catalog.
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
			// A provider is not obliged to release an email, and a viewer with no
			// groups at all must serialise as an empty array rather than as null:
			// a screen that iterates null is a screen that renders nothing where it
			// meant to render "you hold no groups".
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
