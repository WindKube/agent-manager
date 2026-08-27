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

// NewVerifier performs OIDC discovery against issuer. It reaches the network, so
// it belongs in a role's bootstrap and not in a request path.
func NewVerifier(ctx context.Context, issuer, clientID string, client *http.Client) (*Verifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("oidc issuer is empty")
	}
	if clientID == "" {
		return nil, fmt.Errorf("oidc client id is empty")
	}
	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %s: %w", issuer, err)
	}
	return &Verifier{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
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
