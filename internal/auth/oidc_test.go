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

// provider is an in-process IdP: signature, JWKS and expiry are go-oidc's job;
// this project owns which claims are read, which needs no vendor container.
type provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newProvider(t *testing.T) *provider { return newProviderWithIssuer(t, "") }

func newProviderWithIssuer(t *testing.T, issuer string) *provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &provider{key: key, kid: "test-signing-key"}
	mux := http.NewServeMux()
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		advertised := issuer
		if advertised == "" {
			advertised = p.server.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                advertised,
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

// The subject the local provider really mints (opaque base64url protobuf), so
// fixtures don't assume email- or UUID-shaped subjects.
const localDirectorySubject = "CgQ1MDAxEgRsZGFw"

func (p *provider) claims(audience string, extra map[string]any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss": p.server.URL,
		"aud": audience,
		"sub": localDirectorySubject,
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

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     idp.server.URL,
		ClientID:   "agent-manager",
		HTTPClient: idp.server.Client(),
	})
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
			// Real providers omit `groups` for static-password users; that is a token
			// with no role, not an error.
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
			require.Equal(t, localDirectorySubject, claims.Subject)
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
			_, err := auth.NewVerifier(ctx, auth.VerifierConfig{
				Issuer:   tc.issuer,
				ClientID: tc.clientID,
			})
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

// Metadata served from a host other than the issuer: only real providers do
// this, so nothing in the local stack would notice if it broke.
func TestDiscoveryMayBeFetchedFromAHostThatIsNotTheIssuer(t *testing.T) {
	ctx := context.Background()

	const configuredIssuer = "https://idp.example.dev"

	idp := newProviderWithIssuer(t, configuredIssuer)

	t.Run("without the split, discovery is refused", func(t *testing.T) {
		_, err := auth.NewVerifier(ctx, auth.VerifierConfig{
			Issuer:     idp.server.URL,
			ClientID:   "agent-manager",
			HTTPClient: idp.server.Client(),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did not match the issuer URL returned by provider")
	})

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:       configuredIssuer,
		DiscoveryURL: idp.server.URL,
		ClientID:     "agent-manager",
		HTTPClient:   idp.server.Client(),
	})
	require.NoError(t, err)

	t.Run("a token from the trusted issuer verifies", func(t *testing.T) {
		claims := idp.claims("agent-manager", map[string]any{"groups": []string{"eng-platform"}})
		claims["iss"] = configuredIssuer

		got, err := verifier.Verify(ctx, idp.sign(t, idp.key, claims))
		require.NoError(t, err)
		require.Equal(t, []string{"eng-platform"}, got.Groups)
	})

	t.Run("a token from the discovery host is still rejected", func(t *testing.T) {
		claims := idp.claims("agent-manager", nil)
		claims["iss"] = idp.server.URL

		_, err := verifier.Verify(ctx, idp.sign(t, idp.key, claims))
		require.Error(t, err)
		require.Contains(t, err.Error(), "id token issued by a different provider")
		require.Contains(t, err.Error(), configuredIssuer)
	})
}

// The discovery document must name the configured issuer; InsecureIssuerURLContext
// would have accepted a third issuer and adopted its keys.
func TestDiscoveryIsRefusedWhenTheMetadataNamesADifferentIssuer(t *testing.T) {
	idp := newProviderWithIssuer(t, "https://someone-elses-idp.example.dev")

	_, err := auth.NewVerifier(context.Background(), auth.VerifierConfig{
		Issuer:       "https://idp.example.dev",
		DiscoveryURL: idp.server.URL,
		ClientID:     "agent-manager",
		HTTPClient:   idp.server.Client(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "someone-elses-idp.example.dev")
	require.Contains(t, err.Error(), "not the configured")
}
