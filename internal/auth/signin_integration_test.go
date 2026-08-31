//go:build integration

// T029 — the split-host round trip, end to end, against the Dex and glauth the
// stack actually ships.
//
// This is the gate tasks.md names: if it fails, nothing downstream in this feature
// is testable through the product, because every screen behind the guard needs a
// session and a session begins here.
//
// WHAT THE SPLIT IS. The provider has one issuer, `http://dex:5556/dex`, and every
// container on the compose network can reach it — so the api verifies tokens, and
// the web role discovers metadata and exchanges codes, at that address, exactly as
// published. A BROWSER cannot: `dex` is a compose service name and resolves
// nowhere on the operator's machine. So one component of one URL is rewritten for
// the browser's benefit, the authorization endpoint's authority, and nothing else
// is (research R2, FR-106).
//
// That arrangement has two failure modes, both silent until somebody signs in:
//
//  1. Rewrite too much and the backchannel goes through the browser's address,
//     which either fails from inside the container or — worse — succeeds and makes
//     the hub's trust in its tokens depend on a host the operator chose.
//  2. Rewrite too little and the redirect sends the browser to `dex:5556`, which
//     is a DNS error on the page a person meets first.
//
// Neither shows up in a unit test, because both are about two processes disagreeing
// about one name. So this file runs the real thing: the product's own verifier
// discovering over the container network, the product's own AuthorizationURL
// sending a real browser to the mapped port, Dex's own LDAP login form, and the
// product's own Exchange coming back over the container network. Then it reads
// `iss`, `sub`, `email` and `groups` off the token that comes out.
//
// The container network is modelled by a transport that dials the mapped port for
// requests addressed to the issuer's authority — which is what a compose network
// does, and the only honest way to be on one from a test process on the host. Every
// URL the product handles is the container-facing URL it would really see.

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

// ---- the two networks ---------------------------------------------------------

// containerNetwork is an HTTP client that resolves the issuer's authority the way
// a container on the compose network does, and RECORDS every address it was asked
// for.
//
// A DialContext override rather than a URL rewrite, and the recording rather than
// silent translation, are the same decision: the request the product builds keeps
// the container-facing host in its URL and in its Host header, so a browser-facing
// URL that leaked into the backchannel arrives here as a dial for the mapped port
// — which would work, and is exactly the failure this suite exists to catch. It is
// only catchable if something wrote the address down.
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

// requireEveryDialWasContainerFacing is the assertion the recording exists for.
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

// browserDiscovery adapts the verifier to what internal/web needs.
//
// internal/web cannot import internal/auth — internal/archcheck refuses it,
// because this package reads the session table and a role that must hold no
// datastore credential may not link one, not even for an accessor. So the
// endpoints cross that boundary as a value, and the adapter that carries them
// lives in the role's bootstrap. internal/cli's lazyDiscovery is the production
// one and resolves on first use rather than at construction; this one is handed an
// already-discovered verifier, because what is under test here is the URL the
// endpoints produce and not when they were fetched.
type browserDiscovery struct{ verifier *auth.Verifier }

func (d browserDiscovery) Endpoint(context.Context) (oauth2.Endpoint, error) {
	return d.verifier.Endpoint(), nil
}

func (d browserDiscovery) VerifyIDToken(ctx context.Context, idToken string) error {
	return d.verifier.VerifyIDToken(ctx, idToken)
}

// ---- the round trip -----------------------------------------------------------

// signInThroughTheProduct runs one whole sign-in the way the two roles do, and
// returns the raw ID token plus the verifier that accepted it.
func signInThroughTheProduct(t *testing.T, email string) (string, *auth.Verifier) {
	t.Helper()

	network := containerNetwork(t)
	backchannel := network.client
	ctx := context.Background()

	// The web role's bootstrap. The issuer is the trust anchor and DiscoveryURL is
	// left empty, which is the local stack's real shape: one address serves
	// discovery, tokens and keys, and the browser's override lands on the
	// authorization endpoint alone.
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
		Discovery:    browserDiscovery{verifier: verifier},
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		RedirectURL:  oidcRedirectURI,
		Scopes:       strings.Fields(composeOIDCScopes(t)),
		// The one place this value is read.
		BrowserBaseURL: dexBase,
	})
	require.NoError(t, err)

	state := "signin-integration-" + email
	pkceVerifier := oauth2.GenerateVerifier()
	authorizationURL, err := provider.AuthorizationURL(ctx, state,
		oauth2.S256ChallengeFromVerifier(pkceVerifier))
	require.NoError(t, err)

	// The browser leg. No rewriting client here and none possible: this is an
	// ordinary http.Client resolving whatever the product put in the URL, so a
	// redirect naming `dex:5556` fails to dial rather than quietly working.
	require.Equal(t, mustHost(t, dexBase), mustHost(t, authorizationURL),
		"the redirect a browser follows still names the container-only authority")
	code := authorizationCode(t, authorizationURL, email, state)

	// The backchannel leg, from the container network, at the published endpoints.
	// golang.org/x/oauth2 takes its client from the context, so this is how the web
	// container's own networking is expressed to it.
	idToken, err := provider.Exchange(context.WithValue(ctx, oauth2.HTTPClient, backchannel),
		code, pkceVerifier)
	require.NoError(t, err, "the code exchange over the container network")
	require.NotEmpty(t, idToken)

	// The web role verifies the token it just received before it asks the api to
	// open a session for it. Same keys, same network, same verifier.
	require.NoError(t, provider.VerifyIDToken(ctx, idToken))

	// Discovery, the exchange and the key set have all happened by now, so this is
	// the whole backchannel.
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

// rawIssuerClaim decodes the `iss` claim without verifying anything, for the one
// assertion that has to read the token as bytes rather than through a verifier
// that already enforced it.
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

// ---- the assertions -----------------------------------------------------------

// TestTheSplitHostRoundTripYieldsAVerifiedTokenWithTheClaimsTheProductNeeds is the
// gate. Everything else in this file exists to make its failure legible.
func TestTheSplitHostRoundTripYieldsAVerifiedTokenWithTheClaimsTheProductNeeds(t *testing.T) {
	requireStack(t)

	for _, user := range seed.DirectoryUsers {
		t.Run(user.Username, func(t *testing.T) {
			idToken, verifier := signInThroughTheProduct(t, user.Email)

			// iss, twice over. The verifier already enforced it — that is what makes
			// the NoError above an assertion about the issuer and not only about the
			// signature — and it is read off the bytes as well, because "the library
			// checked something" and "the token names the address the operator
			// configured" are only the same sentence while the configuration is right.
			require.Equal(t, issuer, rawIssuerClaim(t, idToken),
				"the token names an issuer other than the one every container reaches. A "+
					"browser-facing issuer here is the rewrite having reached the backchannel")

			claims, err := verifier.Verify(context.Background(), idToken)
			require.NoError(t, err)

			require.NotEmpty(t, claims.Subject, "no sub, so there is no identity to key on")
			require.Equal(t, user.Email, claims.Email)
			require.Contains(t, claims.Groups, user.Group,
				"FR-101 and FR-040: `groups` is the only claim with authorisation weight, and "+
					"the whole flow can succeed without it")
			require.NotEmpty(t, claims.DisplayName(), "nothing for the viewer chip to render")
		})
	}
}

// TestTheTokenFromTheSplitRoundTripIsRefusedByAVerifierConfiguredForAnotherIssuer
// keeps the assertion above from being about nothing.
//
// `iss` is enforced inside go-oidc, so "Verify returned no error" only says
// something about the issuer if a verifier holding a different one refuses the same
// bytes. Without this, an issuer check quietly turned off upstream would leave every
// assertion in this file green.
func TestTheTokenFromTheSplitRoundTripIsRefusedByAVerifierConfiguredForAnotherIssuer(t *testing.T) {
	requireStack(t)

	idToken, _ := signInThroughTheProduct(t, seed.DirectoryEmailPlatform)

	ctx := context.Background()
	// Discovery has to succeed for the refusal to be about the issuer rather than
	// about an unreachable provider, so the document is fetched from the real
	// address and its `issuer` is then held against a value it does not equal.
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

	// And the same again one layer down: a verifier built directly on the right
	// metadata but the wrong anchor must refuse the token itself.
	wrongAnchor, err := auth.NewVerifier(ctx, auth.VerifierConfig{
		Issuer:     issuer,
		ClientID:   "some-other-client",
		HTTPClient: containerNetwork(t).client,
	})
	require.NoError(t, err)
	_, err = wrongAnchor.Verify(ctx, idToken)
	require.Error(t, err, "a token minted for this hub's client id was accepted for another's")
}

// TestOnlyTheAuthorizationEndpointIsRewrittenForTheBrowser is the property the
// whole arrangement rests on, asserted on the URLs rather than on the outcome.
//
// The round trip above succeeds whether or not the token endpoint was rewritten,
// because this test process can reach both addresses. A container cannot, and
// neither can the hub in production — so the shape of the rewrite is asserted
// directly: one component, of one URL, and the published values everywhere else.
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

	// And the parameters the flow depends on survived the rewrite. A rewrite that
	// rebuilt the URL rather than replacing its authority is the version that drops
	// the challenge, and the drop is invisible: Dex accepts a code exchange with no
	// verifier when the authorization request carried no challenge.
	query := got.Query()
	require.Equal(t, "a-state", query.Get("state"))
	require.Equal(t, "a-challenge", query.Get("code_challenge"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.Equal(t, oidcClientID, query.Get("client_id"))
	require.Equal(t, oidcRedirectURI, query.Get("redirect_uri"))
	require.Equal(t, composeOIDCScopes(t), query.Get("scope"))

	// The backchannel is untouched. This is the assertion that would catch a
	// BrowserBaseURL applied to the endpoint pair instead of to the redirect.
	require.Equal(t, mustHost(t, issuer), mustHost(t, verifier.Endpoint().TokenURL))
}

// TestTheUnmappedDirectoryUserSignsInAndCarriesAGroupNothingMapsTo is FR-117's
// route, end to end.
//
// The no-role screen is asserted as a component next door in internal/web. What
// this adds is that it is REACHABLE: there is an account in the shipped directory
// that authenticates successfully and carries a group this hub maps to nothing, so
// an operator can see that screen without editing a fixture to break the coupling
// on purpose — which is the same edit as the bug the screen has to be
// distinguishable from.
func TestTheUnmappedDirectoryUserSignsInAndCarriesAGroupNothingMapsTo(t *testing.T) {
	requireStack(t)

	idToken, verifier := signInThroughTheProduct(t, seed.DirectoryEmailUnmapped)

	claims, err := verifier.Verify(context.Background(), idToken)
	require.NoError(t, err, "the unmapped user must AUTHENTICATE. Holding no role is a state "+
		"after a successful sign-in, not a failed one")
	require.Equal(t, seed.DirectoryEmailUnmapped, claims.Email)
	require.Equal(t, []string{seed.GroupUnmapped}, claims.Groups)

	// The whole point, stated against the mapping rather than against the screen.
	require.Empty(t, seed.RoleOf(seed.GroupUnmapped))
	for _, group := range claims.Groups {
		require.Emptyf(t, seed.RoleOf(group),
			"this identity resolves %q through %q, so it is not the no-role account any more "+
				"and FR-117's screen has no route in a browser", seed.RoleOf(group), group)
	}

	// And they are distinguishable from the two who do hold roles, which is what
	// makes the screen a boundary rather than an outage.
	for _, user := range seed.DirectoryUsers {
		if user.Group == seed.GroupUnmapped {
			continue
		}
		require.NotEqual(t, user.Email, claims.Email)
		require.NotEmpty(t, seed.RoleOf(user.Group))
	}
}
