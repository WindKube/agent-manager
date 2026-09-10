package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims: `groups` is the only claim with authorisation weight; everything
// else is display.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// DisplayName's fallback chain is deliberate: providers differ on which of
// these they populate.
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

// Verifier verifies ID tokens; nothing provider-specific belongs here.
type Verifier struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

type VerifierConfig struct {
	// Issuer is the trust anchor, never derived from a fetched document.
	Issuer       string
	DiscoveryURL string
	ClientID     string
	HTTPClient   *http.Client
}

// NewVerifier performs OIDC discovery, so it belongs in a role's bootstrap
// and not in a request path.
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

// discover uses ProviderConfig rather than go-oidc's
// InsecureIssuerURLContext (which disables issuer checking entirely): the
// fetched document's issuer is asserted below against the configured one,
// so a metadata host advertising a third issuer is refused.
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
	// Bounded: an unauthenticated response decides which keys we trust.
	metadata := &oidc.ProviderConfig{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(metadata); err != nil {
		return nil, fmt.Errorf("decode provider metadata: %w", err)
	}
	return metadata, nil
}

// Endpoint is exported because the role that owns the browser's origin
// cannot import this package (that role must hold no datastore credential),
// so the endpoints cross that boundary as a value.
func (v *Verifier) Endpoint() oauth2.Endpoint { return v.provider.Endpoint() }

// VerifyIDToken reads no claim on purpose: the api verifies the same bytes
// again and resolves the identity itself.
func (v *Verifier) VerifyIDToken(ctx context.Context, rawIDToken string) error {
	_, err := v.Verify(ctx, rawIDToken)
	return err
}

// Verify checks the token's signature, issuer, audience and expiry.
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
