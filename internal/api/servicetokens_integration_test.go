//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

func createServiceToken(t *testing.T, who actor, name string, scopes ...string) commands.CreatedServiceToken {
	t.Helper()

	created, err := commands.CreateServiceToken(context.Background(), db, principalFor(t, who),
		commands.CreateServiceTokenInput{Name: name, Scopes: scopes, ExpiresAt: time.Now().Add(24 * time.Hour)})
	require.NoError(t, err)
	return created
}

func tokenAuditRows(t *testing.T, id uuid.UUID, action string) int {
	t.Helper()

	n, err := db.NewSelect().Model((*models.AuditEvent)(nil)).
		Where("subject_kind = 'service-token' and subject_id = ? and data ->> 'action' = ?", id.String(), action).
		Count(context.Background())
	require.NoError(t, err)
	return n
}

func TestAServiceTokenIsStoredHashedAndResolvesToANonHumanPrincipal(t *testing.T) {
	ctx := context.Background()
	created := createServiceToken(t, kw, "ci-kw-private", "sync:profile/kw-private", "read:catalog")

	require.True(t, auth.IsServiceTokenSecret(created.Secret))
	var stored models.ServiceToken
	require.NoError(t, db.NewSelect().Model(&stored).Where("id = ?", created.Token.ID).Scan(ctx))
	require.Equal(t, auth.HashToken(created.Secret), stored.TokenHash)
	require.NotContains(t, string(stored.TokenHash), created.Secret)
	require.Equal(t, 1, tokenAuditRows(t, created.Token.ID, "created"))

	p, err := auth.NewServiceTokens(db).Resolve(ctx, created.Secret)
	require.NoError(t, err)
	require.True(t, p.IsServiceToken())
	require.Equal(t, uuid.Nil, p.IdentityID)
	require.Empty(t, p.Groups)
	require.Empty(t, p.Role, "a token never holds its creator's catalog-admin role")
	require.Equal(t, []auth.Scope{"read:catalog", "sync:profile/kw-private"}, p.ServiceToken.Scopes)
	require.Equal(t, principalFor(t, kw).IdentityID, p.ServiceToken.Creator.IdentityID)
	require.Empty(t, p.ServiceToken.Creator.Role)

	_, err = auth.NewServiceTokens(db).Resolve(ctx, created.Secret+"x")
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

func TestUseIsTouchedAndAuditedAtMostOnceADay(t *testing.T) {
	ctx := context.Background()
	created := createServiceToken(t, kw, "ci-touch", "read:catalog")
	resolver := auth.NewServiceTokens(db)

	for range 5 {
		_, err := resolver.Resolve(ctx, created.Secret)
		require.NoError(t, err)
	}
	require.Equal(t, 1, tokenAuditRows(t, created.Token.ID, "first-used"))
	require.Equal(t, 0, tokenAuditRows(t, created.Token.ID, "used"))

	var lastUsed time.Time
	require.NoError(t, db.NewSelect().Model((*models.ServiceToken)(nil)).Column("last_used_at").
		Where("id = ?", created.Token.ID).Scan(ctx, &lastUsed))
	require.WithinDuration(t, time.Now(), lastUsed, time.Minute)

	// A day later the next use writes one more row, and only one.
	_, err := db.NewUpdate().Model((*models.ServiceToken)(nil)).
		Set("last_use_audited_at = now() - interval '25 hours'").
		Set("last_used_at = now() - interval '2 minutes'").
		Where("id = ?", created.Token.ID).Exec(ctx)
	require.NoError(t, err)
	for range 3 {
		_, err := resolver.Resolve(ctx, created.Secret)
		require.NoError(t, err)
	}
	require.Equal(t, 1, tokenAuditRows(t, created.Token.ID, "used"))
}

func TestARevokedOrExpiredTokenIsRefusedImmediately(t *testing.T) {
	ctx := context.Background()
	resolver := auth.NewServiceTokens(db)

	revoked := createServiceToken(t, kw, "ci-revoke", "read:catalog")
	_, err := resolver.Resolve(ctx, revoked.Secret)
	require.NoError(t, err)
	_, err = commands.RevokeServiceToken(ctx, db, principalFor(t, kw), revoked.Token.ID)
	require.NoError(t, err)
	_, err = resolver.Resolve(ctx, revoked.Secret)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Equal(t, 1, tokenAuditRows(t, revoked.Token.ID, "revoked"))

	_, err = commands.RevokeServiceToken(ctx, db, principalFor(t, kw), revoked.Token.ID)
	require.NoError(t, err, "revoking twice is a no-op")
	require.Equal(t, 1, tokenAuditRows(t, revoked.Token.ID, "revoked"))

	expired := createServiceToken(t, kw, "ci-expire", "read:catalog")
	_, err = db.NewUpdate().Model((*models.ServiceToken)(nil)).
		Set("created_at = now() - interval '2 days'").Set("expires_at = now() - interval '1 second'").
		Where("id = ?", expired.Token.ID).Exec(ctx)
	require.NoError(t, err)
	_, err = resolver.Resolve(ctx, expired.Secret)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
}

func TestOnlyTheCreatorOrACatalogAdminRevokes(t *testing.T) {
	ctx := context.Background()

	byAn := createServiceToken(t, an, "ci-an", "sync:profile/security-review")
	_, err := commands.RevokeServiceToken(ctx, db, principalFor(t, contractor), byAn.Token.ID)
	require.ErrorIs(t, err, commands.ErrServiceTokenNotFound)

	_, err = commands.RevokeServiceToken(ctx, db, principalFor(t, kw), byAn.Token.ID)
	require.NoError(t, err, "kw is a catalog-admin")

	_, err = commands.RevokeServiceToken(ctx, db, principalFor(t, kw), uuid.New())
	require.ErrorIs(t, err, commands.ErrServiceTokenNotFound)
}

func TestCreationIsRefusedOutsideTheCreatorsReachAndToAToken(t *testing.T) {
	ctx := context.Background()
	in := func(scopes ...string) commands.CreateServiceTokenInput {
		return commands.CreateServiceTokenInput{Name: "ci", Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour)}
	}

	for name, tc := range map[string]struct {
		who actor
		in  commands.CreateServiceTokenInput
	}{
		"a profile the creator cannot read": {an, in("sync:profile/kw-private")},
		"a profile that does not exist":     {kw, in("sync:profile/no-such-profile")},
		"no scope":                          {kw, in()},
		"a write scope":                     {kw, in("write:catalog")},
		"no expiry":                         {kw, commands.CreateServiceTokenInput{Name: "ci", Scopes: []string{"read:catalog"}}},
		"an expiry past a year": {kw, commands.CreateServiceTokenInput{Name: "ci", Scopes: []string{"read:catalog"},
			ExpiresAt: time.Now().Add(auth.MaxServiceTokenLifetime + time.Hour)}},
		"an expiry in the past": {kw, commands.CreateServiceTokenInput{Name: "ci", Scopes: []string{"read:catalog"},
			ExpiresAt: time.Now().Add(-time.Minute)}},
		"no name": {kw, commands.CreateServiceTokenInput{Name: "  ", Scopes: []string{"read:catalog"},
			ExpiresAt: time.Now().Add(time.Hour)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := commands.CreateServiceToken(ctx, db, principalFor(t, tc.who), tc.in)
			require.ErrorIs(t, err, commands.ErrValidation)
		})
	}

	t.Run("a service token cannot mint or revoke tokens", func(t *testing.T) {
		created := createServiceToken(t, kw, "ci-self", "read:catalog")
		p, err := auth.NewServiceTokens(db).Resolve(ctx, created.Secret)
		require.NoError(t, err)

		_, err = commands.CreateServiceToken(ctx, db, p, in("read:catalog"))
		require.ErrorIs(t, err, commands.ErrServiceTokenNeedsAPerson)
		_, err = commands.RevokeServiceToken(ctx, db, p, created.Token.ID)
		require.ErrorIs(t, err, commands.ErrServiceTokenNeedsAPerson)
	})
}

func TestServiceTokensAreCreatedListedAndRevokedOverHTTP(t *testing.T) {
	h := liveHandler(t)

	body := fmt.Sprintf(`{"name":"release","scopes":["sync:profile/kw-private"],"expiresAt":%q}`,
		time.Now().Add(90*24*time.Hour).Format(time.RFC3339))
	rec := request(t, h, http.MethodPost, "/v1/service-tokens", kw.token, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created contract.ServiceTokenCreated
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.True(t, auth.IsServiceTokenSecret(created.Secret))
	require.Equal(t, "active", created.Token.Status)
	require.Equal(t, "kwiatrzyk@example.com", created.Token.CreatedBy)

	list := func(who actor) []contract.ServiceToken {
		res := request(t, h, http.MethodGet, "/v1/service-tokens", who.token, "")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.NotContains(t, res.Body.String(), created.Secret)
		require.NotContains(t, res.Body.String(), "tokenHash")
		var out contract.ServiceTokenList
		require.NoError(t, json.Unmarshal(res.Body.Bytes(), &out))
		return out.Tokens
	}
	ids := func(tokens []contract.ServiceToken) []string {
		out := []string{}
		for _, tok := range tokens {
			out = append(out, tok.ID)
		}
		return out
	}
	require.Contains(t, ids(list(kw)), created.Token.ID)
	require.NotContains(t, ids(list(contractor)), created.Token.ID, "only the creator and a catalog-admin list it")
	require.Contains(t, ids(list(curator)), created.Token.ID, "curator is a catalog-admin")

	rec = request(t, h, http.MethodDelete, "/v1/service-tokens/"+created.Token.ID, contractor.token, "")
	require.Equal(t, http.StatusNotFound, rec.Code)
	rec = request(t, h, http.MethodDelete, "/v1/service-tokens/"+created.Token.ID, kw.token, "")
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	rec = request(t, h, http.MethodGet, "/v1/profiles/kw-private/revisions/head", created.Secret, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code, "revocation takes effect on the next request")

	rec = request(t, h, http.MethodPost, "/v1/service-tokens", kw.token,
		`{"name":"x","scopes":["sync:profile/nobody-home"],"expiresAt":"2030-01-01T00:00:00Z"}`)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
}

func TestASyncScopedTokenSyncsItsProfileAndNothingElse(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)
	tok := createServiceToken(t, kw, "ci-sync", "sync:profile/kw-private").Secret

	rec := request(t, h, http.MethodGet, "/v1/profiles/kw-private/revisions/head", tok, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = request(t, h, http.MethodGet, "/v1/bundles/acme/code-review/2.4.1", tok, "")
	require.Equal(t, http.StatusOK, rec.Code, "a bundle the scoped profile locks")
	rec = request(t, h, http.MethodGet, "/v1/bundles/acme/threat-model/1.0.0", tok, "")
	require.Equal(t, http.StatusNotFound, rec.Code, "a bundle no scoped profile locks")

	rec = request(t, h, http.MethodPost, "/v1/sync", tok, `{"profile":"kw-private","revision":1,"host":"ci-runner","targets":[]}`)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	var actor, actorKind string
	var tokenID *uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `select a.actor, a.actor_kind::text, s.service_token_id
		from audit_event a, sync_event s
		where a.kind = 'sync' and s.host = 'ci-runner' order by a.occurred_at desc limit 1`).
		Scan(&actor, &actorKind, &tokenID))
	require.Equal(t, "ci-sync", actor)
	require.Equal(t, "service-token", actorKind)
	require.NotNil(t, tokenID)

	// Profile A's scope used on profile B: refused from the token alone.
	for _, path := range []string{
		"/v1/profiles/platform-baseline/revisions/head",
		"/v1/profiles/nobody-home/revisions/head",
		"/v1/profiles/no-such-profile/revisions/head",
	} {
		rec = request(t, h, http.MethodGet, path, tok, "")
		require.Equal(t, http.StatusForbidden, rec.Code, path)
	}
	rec = request(t, h, http.MethodPost, "/v1/sync", tok, `{"profile":"platform-baseline","revision":1,"host":"ci","targets":[]}`)
	require.Equal(t, http.StatusForbidden, rec.Code)

	rec = request(t, h, http.MethodGet, "/v1/packages", tok, "")
	require.Equal(t, http.StatusForbidden, rec.Code, "the catalog needs read:catalog")
}

func TestAReadCatalogTokenReadsTheCatalogButResolvesNoProfile(t *testing.T) {
	h := liveHandler(t)
	tok := createServiceToken(t, contractor, "ci-catalog", "read:catalog").Secret

	for _, path := range []string{
		"/v1/packages", "/v1/bundles/acme/threat-model/1.0.0",
	} {
		rec := request(t, h, http.MethodGet, path, tok, "")
		require.Equal(t, http.StatusOK, rec.Code, path+": "+rec.Body.String())
	}
	rec := request(t, h, http.MethodGet, "/v1/profiles/platform-baseline/revisions/head", tok, "")
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestATokenOutlivingItsCreatorsAccessReadsNothing(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)

	login, err := commands.Login(ctx, db, commands.LoginInput{
		Claims:     auth.Claims{Subject: "sub-leaver", Email: "leaver@example.com", Groups: []string{"eng-security"}},
		SessionTTL: time.Hour, Source: auth.SourceWeb,
	})
	require.NoError(t, err)
	leaver := actor{token: login.Token}
	tok := createServiceToken(t, leaver, "ci-leaver", "sync:profile/security-review").Secret

	rec := request(t, h, http.MethodGet, "/v1/profiles/security-review/revisions/head", tok, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	_, err = db.NewUpdate().Model((*models.Identity)(nil)).Set("groups = '{}'").
		Where("subject = 'sub-leaver'").Exec(ctx)
	require.NoError(t, err)
	rec = request(t, h, http.MethodGet, "/v1/profiles/security-review/revisions/head", tok, "")
	require.Equal(t, http.StatusNotFound, rec.Code, "the same answer as any unreadable profile")
}

func TestAServiceTokenIsRefusedEveryWriteAndEveryUnscopedRead(t *testing.T) {
	h := liveHandler(t)
	tok := createServiceToken(t, kw, "ci-everything", "read:catalog", "sync:profile/kw-private").Secret

	param := regexp.MustCompile(`\{[^}]+\}`)
	tried := 0
	for path, item := range api.Document(api.Options{}).Paths {
		for method, op := range map[string]*huma.Operation{
			http.MethodGet: item.Get, http.MethodPost: item.Post, http.MethodPut: item.Put,
			http.MethodPatch: item.Patch, http.MethodDelete: item.Delete,
		} {
			if op == nil || len(api.ServiceTokenScopes(op)) > 0 || (op.Security != nil && !bearerAuthenticated(op)) {
				continue
			}
			rec := request(t, h, method, param.ReplaceAllString(path, "kw-private"), tok, "{}")
			require.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", method, path, rec.Body.String())
			tried++
		}
	}
	require.Greater(t, tried, 30)
}

func TestAnExpiredTokenIsUnauthorized(t *testing.T) {
	ctx := context.Background()
	h := liveHandler(t)
	created := createServiceToken(t, kw, "ci-expired", "sync:profile/kw-private")

	_, err := db.NewUpdate().Model((*models.ServiceToken)(nil)).
		Set("created_at = now() - interval '2 days'").Set("expires_at = now() - interval '1 second'").
		Where("id = ?", created.Token.ID).Exec(ctx)
	require.NoError(t, err)

	rec := request(t, h, http.MethodGet, "/v1/profiles/kw-private/revisions/head", created.Secret, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
