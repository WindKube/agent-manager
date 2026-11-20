package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/auth"
)

func TestParseScopeAcceptsOnlyTheTwoShapes(t *testing.T) {
	for _, ok := range []string{"read:catalog", "sync:profile/platform", "sync:profile/example/platform-engineer"} {
		scope, err := auth.ParseScope(ok)
		require.NoError(t, err, ok)
		require.Equal(t, auth.Scope(ok), scope)
	}
	for _, bad := range []string{
		"", "read:catalog ", "write:catalog", "sync:profile/", "sync:profile/Upper",
		"sync:profile/a//b", "sync:profile/../x", "admin", "sync:profile/" + strings.Repeat("a", 121),
	} {
		_, err := auth.ParseScope(bad)
		require.ErrorIs(t, err, auth.ErrInvalidScope, bad)
	}
}

func TestParseScopesDeduplicatesSortsAndRefusesAnEmptyList(t *testing.T) {
	scopes, err := auth.ParseScopes([]string{"sync:profile/b", "read:catalog", "sync:profile/b"})
	require.NoError(t, err)
	require.Equal(t, []auth.Scope{"read:catalog", "sync:profile/b"}, scopes)

	_, err = auth.ParseScopes(nil)
	require.ErrorIs(t, err, auth.ErrInvalidScope)

	many := make([]string, auth.MaxServiceTokenScopes+1)
	for i := range many {
		many[i] = "sync:profile/p" + strings.Repeat("x", i)
	}
	_, err = auth.ParseScopes(many)
	require.ErrorIs(t, err, auth.ErrInvalidScope)
}

func TestAGrantAllowsOnlyItsScopes(t *testing.T) {
	g := &auth.ServiceTokenGrant{Scopes: []auth.Scope{auth.SyncProfileScope("a/b")}}
	require.True(t, g.Allows("sync:profile/a/b"))
	require.False(t, g.Allows(auth.ScopeReadCatalog))
	require.Equal(t, []string{"a/b"}, g.Profiles())

	var none *auth.ServiceTokenGrant
	require.False(t, none.Allows(auth.ScopeReadCatalog))
}

func TestAServiceTokenPrincipalHoldsNoIdentityAndNoRole(t *testing.T) {
	p := auth.Principal{ServiceToken: &auth.ServiceTokenGrant{ID: uuid.New()}}
	require.True(t, p.IsServiceToken())
	require.Empty(t, p.Role)
	require.Empty(t, p.Refs())
	require.False(t, auth.Principal{}.IsServiceToken())
}

func TestServiceTokenSecretsArePrefixedHighEntropyAndDistinct(t *testing.T) {
	a, err := auth.NewServiceTokenSecret()
	require.NoError(t, err)
	b, err := auth.NewServiceTokenSecret()
	require.NoError(t, err)

	require.True(t, auth.IsServiceTokenSecret(a))
	require.NotEqual(t, a, b)
	require.Len(t, strings.TrimPrefix(a, auth.ServiceTokenPrefix), 43, "32 bytes, unpadded base64url")
	require.Len(t, auth.HashToken(a), 32)
}

type stubResolver struct{ name string }

func (s stubResolver) Resolve(context.Context, string) (auth.Principal, error) {
	return auth.Principal{Subject: s.name}, nil
}

func TestChainRoutesByPrefix(t *testing.T) {
	ctx := context.Background()
	chain := auth.Chain{Sessions: stubResolver{"session"}, ServiceTokens: stubResolver{"token"}}

	p, err := chain.Resolve(ctx, "amst_abc")
	require.NoError(t, err)
	require.Equal(t, "token", p.Subject)

	p, err = chain.Resolve(ctx, "abc")
	require.NoError(t, err)
	require.Equal(t, "session", p.Subject)

	_, err = auth.Chain{Sessions: stubResolver{"session"}}.Resolve(ctx, "amst_abc")
	require.True(t, errors.Is(err, auth.ErrUnauthenticated), "no token resolver must not fall through to sessions")
}
