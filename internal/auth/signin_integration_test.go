//go:build integration

// The split-host sign-in round trip against the shipped Dex and glauth. The
// issuer `http://dex:5556/dex` is reachable only from containers, so only the
// browser's authorization endpoint authority is rewritten. Rewriting too much
// routes the backchannel through a browser address; too little sends the
// browser to an unresolvable host. Both are silent until someone signs in.

package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"agent-manager/internal/auth"
	"agent-manager/internal/seed"
	"agent-manager/internal/web"
)

// containerNetwork dials the mapped port for the issuer's authority, like the
// compose network, and records every address so a browser-facing URL leaking
// into the backchannel (which would work here) is caught.
type containerNet struct {
	client *http.Client

	mu     sync.Mutex
	dialed []string
}

func containerNetwork(t *testing.T) *containerNet {
	t.Helper()

	published, err := url.Parse(dexBase)
	require.NoError(t, err)
	container, err := url.Parse(issuer)
	require.NoError(t, err)
	require.NotEqual(t, published.Host, container.Host,
		"the mapped port and the published issuer are the same authority, so this suite is "+
			"asserting nothing about a split that is not there")

	network := &containerNet{}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	network.client = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, proto, address string) (net.Conn, error) {
				network.mu.Lock()
				network.dialed = append(network.dialed, address)
				network.mu.Unlock()

				if address == container.Host {
					address = published.Host
				}
				return dialer.DialContext(ctx, proto, address)
			},
		},
	}
	return network
}

func (n *containerNet) requireEveryDialWasContainerFacing(t *testing.T) {
	t.Helper()

	n.mu.Lock()
	dialed := append([]string(nil), n.dialed...)
	n.mu.Unlock()

	require.NotEmpty(t, dialed, "nothing reached the provider over the container network at all")
	for _, address := range dialed {
		require.Equalf(t, mustHost(t, issuer), address,
			"the backchannel dialled %q. Every address on this side of the flow is the "+
				"published one, so a mapped-port dial is the browser's override having reached "+
				"discovery, the token endpoint or the key set — where it would WORK here and "+
				"fail in a container", address)
	}
}

// internal/web may not import internal/auth (no datastore credential in that
// role), so endpoints cross as a value via this adapter.
type browserDiscovery struct{ verifier *auth.Verifier }

func (d browserDiscovery) Endpoint(context.Context) (oauth2.Endpoint, error) {
	return d.verifier.Endpoint(), nil
}

func (d browserDiscovery) VerifyIDToken(ctx context.Context, idToken string) error {
	return d.verifier.VerifyIDToken(ctx, idToken)
}

func signInThroughTheProduct(t *testing.T, email string) (string, *auth.Verifier) {
	t.Helper()

	network := containerNetwork(t)
	backchannel := network.client
	ctx := context.Background()

	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     issuer,
		ClientID:   oidcClientID,
		HTTPClient: backchannel,
	})
	require.NoError(t, err, "discovery over the container network")

	published := verifier.Endpoint()
	containerHost := mustHost(t, issuer)
	require.Equal(t, containerHost, mustHost(t, published.AuthURL),
		"the provider publishes its authorization endpoint at the issuer's authority. If it "+
			"published the browser's, there would be nothing for the override to do and the "+
			"override would be untested")
	require.Equal(t, containerHost, mustHost(t, published.TokenURL))

	provider, err := web.NewAuthProvider(web.AuthOptions{
		Discovery:      browserDiscovery{verifier: verifier},
		ClientID:       oidcClientID,
		ClientSecret:   oidcClientSecret,
		RedirectURL:    oidcRedirectURI,
		Scopes:         strings.Fields(composeOIDCScopes(t)),
		BrowserBaseURL: dexBase,
	})
	require.NoError(t, err)

	state := "signin-integration-" + email
	pkceVerifier := oauth2.GenerateVerifier()
	authorizationURL, err := provider.AuthorizationURL(ctx, state,
		oauth2.S256ChallengeFromVerifier(pkceVerifier))
	require.NoError(t, err)

	// A plain client: a redirect naming `dex:5556` fails to dial rather than working.
	require.Equal(t, mustHost(t, dexBase), mustHost(t, authorizationURL),
		"the redirect a browser follows still names the container-only authority")
	code := authorizationCode(t, authorizationURL, email, state)

	// oauth2 takes its client from the context; this is the container's network.
	idToken, err := provider.Exchange(context.WithValue(ctx, oauth2.HTTPClient, backchannel),
		code, pkceVerifier)
	require.NoError(t, err, "the code exchange over the container network")
	require.NotEmpty(t, idToken)

	require.NoError(t, provider.VerifyIDToken(ctx, idToken))

	network.requireEveryDialWasContainerFacing(t)

	return idToken, verifier
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Host, "%q names no host", raw)
	return parsed.Host
}

func rawIssuerClaim(t *testing.T, idToken string) string {
	t.Helper()

	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3, "an ID token is three segments")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Iss
}

func TestTheSplitHostRoundTripYieldsAVerifiedTokenWithTheClaimsTheProductNeeds(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			idToken, verifier := signInThroughTheProduct(t, user.Email)

			// Read off the raw bytes as well: the verifier enforcing an issuer is not the
			// same as the token naming the configured one.
			require.Equal(t, issuer, rawIssuerClaim(t, idToken),
				"the token names an issuer other than the one every container reaches. A "+
					"browser-facing issuer here is the rewrite having reached the backchannel")

			claims, err := verifier.Verify(context.Background(), idToken)
			require.NoError(t, err)

			require.NotEmpty(t, claims.Subject, "no sub, so there is no identity to key on")
			require.Equal(t, user.Email, claims.Email)
			require.Contains(t, claims.Groups, user.Group,
				"`groups` is the only claim with authorisation weight, and "+
					"the whole flow can succeed without it")
			require.NotEmpty(t, claims.DisplayName(), "nothing for the viewer chip to render")
		})
	}
}

// `iss` is enforced inside go-oidc, so this proves a verifier for another
// issuer refuses the same bytes; otherwise a disabled check upstream stays green.
func TestTheTokenFromTheSplitRoundTripIsRefusedByAVerifierConfiguredForAnotherIssuer(t *testing.T) {
	requireStack(t)

	idToken, _ := signInThroughTheProduct(t, seed.DirectoryEmailPlatform)

	ctx := context.Background()
	// Discovery must succeed so the refusal is about the issuer, not reachability.
	elsewhere, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:       "http://not-this-provider.invalid/dex",
		DiscoveryURL: issuer,
		ClientID:     oidcClientID,
		HTTPClient:   containerNetwork(t).client,
	})
	require.Error(t, err,
		"a metadata document naming one issuer was accepted for another. That is the check "+
			"internal/auth/oidc.go chose ProviderConfig over InsecureIssuerURLContext to keep")
	require.Nil(t, elsewhere)
	require.Contains(t, err.Error(), "document names issuer")

	wrongAnchor, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     issuer,
		ClientID:   "some-other-client",
		HTTPClient: containerNetwork(t).client,
	})
	require.NoError(t, err)
	_, err = wrongAnchor.Verify(ctx, idToken)
	require.Error(t, err, "a token minted for this hub's client id was accepted for another's")
}

// The round trip succeeds either way from the host, which reaches both
// addresses; a container can't, so the rewrite's shape is asserted directly.
func TestOnlyTheAuthorizationEndpointIsRewrittenForTheBrowser(t *testing.T) {
	requireStack(t)

	ctx := context.Background()
	verifier, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     issuer,
		ClientID:   oidcClientID,
		HTTPClient: containerNetwork(t).client,
	})
	require.NoError(t, err)

	provider, err := web.NewAuthProvider(web.AuthOptions{
		Discovery:      browserDiscovery{verifier: verifier},
		ClientID:       oidcClientID,
		ClientSecret:   oidcClientSecret,
		RedirectURL:    oidcRedirectURI,
		Scopes:         strings.Fields(composeOIDCScopes(t)),
		BrowserBaseURL: dexBase,
	})
	require.NoError(t, err)

	rewritten, err := provider.AuthorizationURL(ctx, "a-state", "a-challenge")
	require.NoError(t, err)
	got, err := url.Parse(rewritten)
	require.NoError(t, err)

	published, err := url.Parse(verifier.Endpoint().AuthURL)
	require.NoError(t, err)

	require.Equal(t, mustHost(t, dexBase), got.Host, "the authority is the browser's")
	require.Equal(t, published.Scheme, got.Scheme, "the scheme is the provider's decision, not ours")
	require.Equal(t, published.Path, got.Path, "the path is the provider's decision, not ours")

	// Rebuilding the URL instead of swapping its authority silently drops the PKCE
	// challenge: Dex then accepts an exchange with no verifier.
	query := got.Query()
	require.Equal(t, "a-state", query.Get("state"))
	require.Equal(t, "a-challenge", query.Get("code_challenge"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.Equal(t, oidcClientID, query.Get("client_id"))
	require.Equal(t, oidcRedirectURI, query.Get("redirect_uri"))
	require.Equal(t, composeOIDCScopes(t), query.Get("scope"))

	// Catches BrowserBaseURL applied to the token endpoint instead of the redirect.
	require.Equal(t, mustHost(t, issuer), mustHost(t, verifier.Endpoint().TokenURL))
}

// The unmapped directory user authenticates with a group mapped to nothing, so
// the no-role screen is reachable without breaking a fixture.
func TestTheUnmappedDirectoryUserSignsInAndCarriesAGroupNothingMapsTo(t *testing.T) {
	requireStack(t)

	idToken, verifier := signInThroughTheProduct(t, seed.DirectoryEmailUnmapped)

	claims, err := verifier.Verify(context.Background(), idToken)
	require.NoError(t, err, "the unmapped user must AUTHENTICATE. Holding no role is a state "+
		"after a successful sign-in, not a failed one")
	require.Equal(t, seed.DirectoryEmailUnmapped, claims.Email)
	require.Equal(t, []string{seed.GroupUnmapped}, claims.Groups)

	require.Empty(t, seed.RoleOf(seed.GroupUnmapped))
	for _, group := range claims.Groups {
		require.Emptyf(t, seed.RoleOf(group),
			"this identity resolves %q through %q, so it is not the no-role account any more "+
				"and the no-role screen has no route in a browser", seed.RoleOf(group), group)
	}

	for _, user := range seed.DirectoryUsers {
		if user.Group == seed.GroupUnmapped {
			continue
		}
		require.NotEqual(t, user.Email, claims.Email)
		require.NotEmpty(t, seed.RoleOf(user.Group))
	}
}
