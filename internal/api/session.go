package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/zerolog"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/logging"
)

// The identity operations: minting a browser session, ending one, and reporting
// who the request is acting as. The mint's caller is a role, not a person.
// SessionMintHeader carries the shared secret the web role presents to
// POST /v1/sessions. It is deliberately not Authorization, so the bearer path
// keeps a single meaning.
const SessionMintHeader = "X-Session-Mint-Secret"

const SessionMintScheme = "sessionMintSecret"

// sessionMintSecurity declares a real scheme rather than publicSecurity(), so the
// document does not call the most privileged operation public.
func sessionMintSecurity() []map[string][]string {
	return []map[string][]string{{SessionMintScheme: {}}}
}

type createSessionInput struct {
	// Hidden because the security scheme already documents it. The literal must match
	// SessionMintHeader; a test sends the header under the constant.
	Secret string `header:"X-Session-Mint-Secret" hidden:"true"`
	Body   contract.SessionMintRequest
}

type createSessionOutput struct {
	Body contract.Session
}

func (s *Server) createSession(ctx context.Context, in *createSessionInput) (*createSessionOutput, error) {
	log := logging.From(ctx)

	mint := commands.SessionMint{
		Secret:   s.deps.SessionMintSecret,
		Verifier: s.deps.IDTokens,
		TTL:      s.opts.SessionTTL,
	}
	result, err := mint.Mint(ctx, s.deps.DB, commands.MintInput{
		Secret:  in.Secret,
		IDToken: in.Body.IDToken,
		Source:  auth.SourceWeb,
	})
	if err != nil {
		return nil, mintFailure(log, err)
	}

	// Never log the token: the response body is its only copy on this side.
	log.Info().Str("identity_id", result.IdentityID.String()).Msg("session minted")

	return &createSessionOutput{Body: contract.Session{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
		ExpiresIn: int(time.Until(result.ExpiresAt).Round(time.Second).Seconds()),
	}}, nil
}

// mintFailure maps the mint's refusals onto the wire. Messages never carry the
// secret or the verifier's complaint; causes go to the log.
func mintFailure(log zerolog.Logger, err error) error {
	switch {
	case errors.Is(err, commands.ErrMintNotConfigured):
		// Error, not warn: sign-in is down hub-wide until an operator acts.
		log.Error().Err(err).Msg("a session mint was refused because this hub cannot mint sessions")
		return huma.Error503ServiceUnavailable("this hub cannot mint sessions")
	case errors.Is(err, commands.ErrMintUnauthorized):
		log.Warn().Msg("a session mint presented an unaccepted secret")
		return huma.Error401Unauthorized("the session mint secret is not accepted")
	case errors.Is(err, commands.ErrIDTokenRejected):
		log.Warn().Err(err).Msg("a session mint presented an id token that did not verify")
		return huma.Error422UnprocessableEntity("the id token did not verify")
	default:
		return fail(log, err)
	}
}

func (s *Server) deleteSession(ctx context.Context, _ *struct{}) (*struct{}, error) {
	log := logging.From(ctx)

	principal, ok := PrincipalFrom(ctx)
	token := sessionTokenFrom(ctx)
	if !ok || token == "" {
		// Unreachable through the router (bearer is required); kept so a lost declaration
		// is a 401 rather than a silent sign-out of nothing.
		return nil, huma.Error401Unauthorized("missing, expired or invalid token")
	}

	if err := commands.SignOut(ctx, s.deps.DB, principal, token); err != nil {
		return nil, fail(log, err)
	}
	return &struct{}{}, nil
}

type getViewerOutput struct {
	Body contract.Viewer
}

// getViewer reports what authenticate already resolved on this request. Resolve
// re-reads group mappings on every request, so a second query would only be a second answer.
func (s *Server) getViewer(ctx context.Context, _ *struct{}) (*getViewerOutput, error) {
	principal, ok := PrincipalFrom(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("missing, expired or invalid token")
	}

	groups := principal.Groups
	if groups == nil {
		groups = []string{}
	}
	return &getViewerOutput{Body: contract.Viewer{
		Subject:     principal.Subject,
		DisplayName: principal.DisplayName,
		Email:       principal.Email,
		Role:        string(principal.Role),
		// HasRole distinguishes "no mapped group" from a role for the screen.
		HasRole: principal.Role != "",
		Groups:  groups,
	}}, nil
}

// LazyVerifier defers OIDC discovery to the first session mint, so the identity
// provider is not a hard dependency of every operation. Success is memoised;
// failure is retried on the next mint.
type LazyVerifier struct {
	cfg auth.VerifierConfig

	mu sync.Mutex
	// Held across discovery on purpose, so concurrent first mints discover once.
	verifier *auth.Verifier
}

// NewLazyVerifier returns a verifier that discovers on first use; it performs no I/O.
func NewLazyVerifier(cfg auth.VerifierConfig) *LazyVerifier {
	return &LazyVerifier{cfg: cfg}
}

func (l *LazyVerifier) Verify(ctx context.Context, rawIDToken string) (auth.Claims, error) {
	verifier, err := l.resolve(ctx)
	if err != nil {
		return auth.Claims{}, err
	}
	return verifier.Verify(ctx, rawIDToken)
}

func (l *LazyVerifier) resolve(ctx context.Context) (*auth.Verifier, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.verifier != nil {
		return l.verifier, nil
	}
	verifier, err := auth.NewVerifier(ctx, l.cfg)
	if err != nil {
		return nil, err
	}
	l.verifier = verifier
	return verifier, nil
}
