package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/auth"
)

// The identity provider here is minted in-process: a discovery document, a JWKS
// and an RSA key this test signs with. No container and no vendor.
//
// That is deliberate rather than convenient. The signature, the JWKS fetch and
// the expiry check are go-oidc's behaviour, and what this project owns is
// everything after them — which claims are read, and that a provider which omits
// `groups` is handled rather than crashed on. Pinning that to one vendor's
// container would test the vendor. The live-provider check belongs to the layer
// that writes compose.yaml, where the provider is a deployment choice.
type provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newProvider(t *testing.T) *provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &provider{key: key, kid: "test-signing-key"}
	mux := http.NewServeMux()
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.server.URL,
			"authorization_endpoint":                p.server.URL + "/auth",
			"token_endpoint":                        p.server.URL + "/token",
			"device_authorization_endpoint":         p.server.URL + "/device",
			"jwks_uri":                              p.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": p.kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})

	return p
}

func (p *provider) sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func (p *provider) claims(audience string, extra map[string]any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss": p.server.URL,
		"aud": audience,
		"sub": "CgVrd2lhdBIEbGRhcA",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

func TestVerifierAcceptsAnIDTokenAndReadsTheGroupsClaim(t *testing.T) {
	idp := newProvider(t)
	ctx := context.Background()

	verifier, err := auth.NewVerifier(ctx, idp.server.URL, "agent-manager", idp.server.Client())
	require.NoError(t, err)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		token      string
		wantErr    string
		wantGroups []string
		wantName   string
	}{
		{
			name: "a token carrying groups maps to those groups",
			token: idp.sign(t, idp.key, idp.claims("agent-manager", map[string]any{
				"email":  "kwiatrzyk@example.com",
				"name":   "Krzysztof Wiatrzyk",
				"groups": []string{"eng-platform"},
			})),
			wantGroups: []string{"eng-platform"},
			wantName:   "Krzysztof Wiatrzyk",
		},
		{
			// Measured behaviour of one real provider: a static-connector user's
			// ID token can arrive with no `groups` at all. That is a token with no
			// mapped role, not a malformed token, and it must not be an error here.
			name: "a provider that omits groups yields no groups and no error",
			token: idp.sign(t, idp.key, idp.claims("agent-manager", map[string]any{
				"email": "anowak@example.com",
			})),
			wantGroups: nil,
			wantName:   "anowak@example.com",
		},
		{
			name: "a token for another audience is refused",
			token: idp.sign(t, idp.key, idp.claims("some-other-client", map[string]any{
				"email": "kwiatrzyk@example.com",
			})),
			wantErr: "audience",
		},
		{
			name: "an expired token is refused",
			token: idp.sign(t, idp.key, idp.claims("agent-manager", map[string]any{
				"exp": time.Now().Add(-time.Hour).Unix(),
			})),
			wantErr: "expired",
		},
		{
			name: "a token signed by another key is refused",
			token: idp.sign(t, other, idp.claims("agent-manager", map[string]any{
				"email": "kwiatrzyk@example.com",
			})),
			wantErr: "verif",
		},
		{
			name:    "a token that is not a token at all is refused",
			token:   "not-a-json-web-token",
			wantErr: "malformed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := verifier.Verify(ctx, tc.token)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "CgVrd2lhdBIEbGRhcA", claims.Subject)
			require.Equal(t, tc.wantGroups, claims.Groups)
			require.Equal(t, tc.wantName, claims.DisplayName())
		})
	}
}

func TestVerifierRefusesAnUnreachableOrUnnamedIssuer(t *testing.T) {
	for _, tc := range []struct {
		name, issuer, clientID, wantErr string
	}{
		{"no issuer", "", "agent-manager", "issuer is empty"},
		{"no client id", "https://idp.example.dev", "", "client id is empty"},
		{"an issuer nothing answers on", "http://127.0.0.1:1/idp", "agent-manager", "discovery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := auth.NewVerifier(ctx, tc.issuer, tc.clientID, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestClaimsDisplayNameFallsBackInOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims auth.Claims
		want   string
	}{
		{"name wins", auth.Claims{Name: "Anna Nowak", PreferredUsername: "anowak", Email: "a@example.com"}, "Anna Nowak"},
		{"then preferred_username", auth.Claims{PreferredUsername: "anowak", Email: "a@example.com"}, "anowak"},
		{"then email", auth.Claims{Email: "a@example.com"}, "a@example.com"},
		{"and nothing is nothing", auth.Claims{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.claims.DisplayName())
		})
	}
}
