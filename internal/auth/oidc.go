package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims is the subset of an ID token this project reads. `groups` is the input
// to group_role_map and therefore the only claim with authorisation weight
// (FR-040); everything else is display.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// DisplayName is what the UI shows. Providers differ on which of these they
// populate, so the fallback chain is deliberate rather than defensive.
func (c Claims) DisplayName() string {
	switch {
	case c.Name != "":
		return c.Name
	case c.PreferredUsername != "":
		return c.PreferredUsername
	default:
		return c.Email
	}
}

// Verifier verifies ID tokens against the organisation's provider.
//
// Discovery, key rotation and signature verification are go-oidc's job. Nothing
// provider-specific belongs here: which IdP the stack runs locally is a
// deployment choice, and a hard-coded quirk of one of them is how this stops
// working against the next.
type Verifier struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// VerifierConfig is what a role needs to verify an ID token.
//
// Issuer and DiscoveryURL are separate because in a container network they are
// not the same host. The `iss` claim and the authorisation endpoint have to be
// reachable from the operator's browser; the JWKS endpoint has to be reachable
// from this process. See the OIDC_DISCOVERY_URL note in quickstart.md.
type VerifierConfig struct {
	// Issuer is the value the `iss` claim must equal. It is the trust anchor and
	// is never derived from a document fetched over the network.
	Issuer string
	// DiscoveryURL is where the discovery document is fetched from. Empty, or
	// equal to Issuer, means the ordinary single-URL case.
	DiscoveryURL string
	ClientID     string
	HTTPClient   *http.Client
}

// NewVerifier performs OIDC discovery. It reaches the network, so it belongs in a
// role's bootstrap and not in a request path.
func NewVerifier(ctx context.Context, cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc issuer is empty")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc client id is empty")
	}
	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}

	discovery := cfg.DiscoveryURL
	if discovery == "" {
		discovery = cfg.Issuer
	}
	if discovery != cfg.Issuer {
		// go-oidc otherwise refuses a document whose `issuer` differs from the URL
		// it was fetched from, which is the whole point of the split. What this
		// disables is that one string comparison between two values the operator
		// supplied; signature, audience and expiry verification are untouched, and
		// the `iss` claim is still checked against cfg.Issuer below.
		ctx = oidc.InsecureIssuerURLContext(ctx, cfg.Issuer)
	}

	provider, err := oidc.NewProvider(ctx, discovery)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %s: %w", discovery, err)
	}
	return &Verifier{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// Verify checks the token's signature, issuer, audience and expiry, then returns
// its claims.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (Claims, error) {
	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("verify id token: %w", err)
	}
	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return Claims{}, fmt.Errorf("decode id token claims: %w", err)
	}
	if claims.Subject == "" {
		return Claims{}, fmt.Errorf("id token carries no subject")
	}
	return claims, nil
}
