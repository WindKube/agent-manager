//go:build integration

package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/api/commands"
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
