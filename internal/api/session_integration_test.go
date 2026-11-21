//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The session mint, sign-out and the viewer against a real Postgres.

// theMintSecret is distinctive so finding it in a statement or row is unambiguous.
const theMintSecret = "integration-session-mint-secret-8f3a"

// mintingHandler is liveHandler plus the shared secret and a verifier that
// returns the claims it is given instead of reaching a provider.
func mintingHandler(t *testing.T, claims auth.Claims) http.Handler {
	t.Helper()

	return api.New(api.Deps{
		DB:                db,
		Sessions:          auth.NewSessions(db),
		SessionMintSecret: theMintSecret,
		IDTokens:          fixedClaims{claims: claims},
	}, api.Options{}).Handler()
}

type fixedClaims struct {
	claims auth.Claims
}

func (f fixedClaims) Verify(context.Context, string) (auth.Claims, error) { return f.claims, nil }

func mint(t *testing.T, h http.Handler, secret string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions",
		strings.NewReader(`{"idToken":"a.raw.id.token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.SessionMintHeader, secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAMintedSessionIsUsableAndWritesExactlyOneLoginAuditRow(t *testing.T) {
	claims := auth.Claims{
		Subject: "sub-mint-1", Email: "mint-one@example.com", Name: "Mint One",
		Groups: []string{"eng-platform"},
	}
	h := mintingHandler(t, claims)

	before := countRows(t, "select count(*) from audit_event where actor = 'mint-one@example.com'")

	rec := mint(t, h, theMintSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var session contract.Session
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &session))
	require.NotEmpty(t, session.Token)
	require.Positive(t, session.ExpiresIn)
	require.True(t, session.ExpiresAt.After(time.Now().UTC()),
		"a session that is already expired is not a session")

	viewer := request(t, h, http.MethodGet, "/v1/viewer", session.Token, "")
	require.Equal(t, http.StatusOK, viewer.Code, viewer.Body.String())

	var body contract.Viewer
	require.NoError(t, json.Unmarshal(viewer.Body.Bytes(), &body))
	require.Equal(t, "Mint One", body.DisplayName)
	require.Equal(t, "mint-one@example.com", body.Email)
	// The role comes from this suite's group_role_map, not from the mint request.
	require.Equal(t, "catalog-admin", body.Role)
	require.True(t, body.HasRole)

	// Exactly one, inside the mint's own transaction.
	require.Equal(t, before+1,
		countRows(t, "select count(*) from audit_event where actor = 'mint-one@example.com'"))

	var text, source, kind string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select text, source, kind::text from audit_event
		 where actor = 'mint-one@example.com' order by occurred_at desc limit 1`).
		Scan(&text, &source, &kind))
	require.Contains(t, text, "signed in")
	require.Equal(t, auth.SourceWeb, source)
	require.Equal(t, "login", kind)
}

// Asserting on every statement rather than per column also catches a future column carrying the secret.
func TestTheSharedSecretReachesNoStatementAndSoNoRow(t *testing.T) {
	h := mintingHandler(t, auth.Claims{
		Subject: "sub-mint-2", Email: "mint-two@example.com", Name: "Mint Two",
		Groups: []string{"eng-platform"},
	})

	recorder.record()
	rec := mint(t, h, theMintSecret)
	seen := recorder.stop()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NotEmpty(t, seen, "no statement was recorded, so this asserts nothing")
	for _, statement := range seen {
		require.NotContains(t, statement, theMintSecret)
	}

	// The sweep above depends on the recorder being wired; this check does not.
	var rendered string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select to_jsonb(audit_event)::text from audit_event
		 where actor = 'mint-two@example.com' order by occurred_at desc limit 1`).Scan(&rendered))
	require.NotContains(t, rendered, theMintSecret)
}

func TestSigningOutExpiresTheRowAndWritesItsOwnAuditRow(t *testing.T) {
	h := mintingHandler(t, auth.Claims{
		Subject: "sub-mint-3", Email: "mint-three@example.com", Name: "Mint Three",
		Groups: []string{"eng-platform"},
	})

	rec := mint(t, h, theMintSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var session contract.Session
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &session))

	before := countRows(t,
		"select count(*) from audit_event where actor = 'mint-three@example.com'")

	out := request(t, h, http.MethodDelete, "/v1/sessions/current", session.Token, "")
	require.Equal(t, http.StatusNoContent, out.Code, out.Body.String())

	// Server-side: the row's expiry moved, so the cookie the browser holds is worthless.
	require.Equal(t, 1, countRows(t,
		`select count(*) from session s join identity i on i.id = s.identity_id
		 where i.subject = 'sub-mint-3' and s.expires_at <= now()`))

	// A replay is indistinguishable from a token that never existed.
	replay := request(t, h, http.MethodGet, "/v1/viewer", session.Token, "")
	require.Equal(t, http.StatusUnauthorized, replay.Code)
	again := request(t, h, http.MethodDelete, "/v1/sessions/current", session.Token, "")
	require.Equal(t, http.StatusUnauthorized, again.Code)

	// One row for the sign-out, none for the refusals.
	require.Equal(t, before+1, countRows(t,
		"select count(*) from audit_event where actor = 'mint-three@example.com'"))

	var text, source string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select text, source from audit_event
		 where actor = 'mint-three@example.com' order by occurred_at desc limit 1`).
		Scan(&text, &source))
	require.Contains(t, text, "signed out")
	require.Equal(t, auth.SourceWeb, source)
}

// There is no role cache: the session is never reissued while its mapping changes three times.
func TestTheViewersRoleFollowsTheGroupMapWithNothingToInvalidate(t *testing.T) {
	const group = "eng-fr118"

	h := mintingHandler(t, auth.Claims{
		Subject: "sub-mint-4", Email: "mint-four@example.com", Name: "Mint Four",
		Groups: []string{group},
	})

	rec := mint(t, h, theMintSecret)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var session contract.Session
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &session))

	viewerNow := func() contract.Viewer {
		t.Helper()
		out := request(t, h, http.MethodGet, "/v1/viewer", session.Token, "")
		require.Equal(t, http.StatusOK, out.Code, out.Body.String())
		var body contract.Viewer
		require.NoError(t, json.Unmarshal(out.Body.Bytes(), &body))
		return body
	}

	// An unmapped group grants nothing rather than defaulting to the least-privileged role.
	unmapped := viewerNow()
	require.False(t, unmapped.HasRole)
	require.Empty(t, unmapped.Role)
	require.Equal(t, []string{group}, unmapped.Groups)

	mapping := &models.GroupRoleMap{GroupName: group, Role: models.OrgRoleScannerReviewer}
	_, err := db.NewInsert().Model(mapping).Exec(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := db.NewDelete().Model((*models.GroupRoleMap)(nil)).
			Where("group_name = ?", group).Exec(context.Background())
		require.NoError(t, cleanupErr)
	})

	mapped := viewerNow()
	require.True(t, mapped.HasRole)
	require.Equal(t, "scanner-reviewer", mapped.Role)

	_, err = db.NewDelete().Model((*models.GroupRoleMap)(nil)).
		Where("group_name = ?", group).Exec(context.Background())
	require.NoError(t, err)

	// A revocation must take effect as immediately as a grant.
	revoked := viewerNow()
	require.False(t, revoked.HasRole)
	require.Empty(t, revoked.Role)
}
