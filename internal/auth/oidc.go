package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
// Issuer and DiscoveryURL are separate for the provider that serves its
// discovery document from a host other than the one its `issuer` names. That is
// a real production shape (FR-106) rather than a workaround: the local stack
// leaves DiscoveryURL empty, because the provider it runs publishes one issuer
// every container can reach and the browser's override lands on the
// authorisation endpoint alone.
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

	provider, err := discover(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Verifier{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// discover fetches the provider metadata and returns a provider built from it.
//
// The ordinary case is one URL, and it is the case the local stack now uses:
// discovery, token and JWKS all live under the issuer, so go-oidc's own check —
// that the document's `issuer` equals the URL it came from — simply passes.
//
// The split case exists for a provider whose metadata lives somewhere else.
// go-oidc offers two ways to reach one: InsecureIssuerURLContext, which turns
// that check OFF entirely, or ProviderConfig, which skips discovery and takes
// the endpoints directly. The second is used here because the check we actually
// want is neither of the library's: not "the document came from its own issuer",
// which is false by construction, and not "no check at all", but "the document
// names the issuer the operator configured". That is asserted below, so a
// metadata host that starts advertising a third issuer is refused rather than
// trusted — which the InsecureIssuerURLContext version accepted.
func discover(ctx context.Context, cfg VerifierConfig) (*oidc.Provider, error) {
	if cfg.DiscoveryURL == "" || cfg.DiscoveryURL == cfg.Issuer {
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery against %s: %w", cfg.Issuer, err)
		}
		return provider, nil
	}

	metadata, err := fetchMetadata(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery against %s: %w", cfg.DiscoveryURL, err)
	}
	if metadata.IssuerURL != cfg.Issuer {
		return nil, fmt.Errorf(
			"oidc discovery against %s: document names issuer %q, not the configured %q",
			cfg.DiscoveryURL, metadata.IssuerURL, cfg.Issuer)
	}
	return metadata.NewProvider(ctx), nil
}

func fetchMetadata(ctx context.Context, cfg VerifierConfig) (*oidc.ProviderConfig, error) {
	wellKnown := strings.TrimSuffix(cfg.DiscoveryURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, http.NoBody)
	if err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", wellKnown, resp.Status)
	}
	// Bounded, because this is an unauthenticated response that decides which keys
	// sign the tokens this process trusts. 1 MiB is orders of magnitude above any
	// real metadata document.
	metadata := &oidc.ProviderConfig{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(metadata); err != nil {
		return nil, fmt.Errorf("decode provider metadata: %w", err)
	}
	return metadata, nil
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
