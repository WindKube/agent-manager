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

// The three identity operations of 003 US2: minting a browser session, ending
// one, and reporting who the request is acting as.
//
// contracts/auth.md is authoritative for all three, and the first of them is the
// feature's sharpest security edge — the one operation in this system whose caller
// is a role rather than a person.

// SessionMintHeader carries the shared secret the web role presents to
// POST /v1/sessions.
//
// Its own header, not Authorization: the bearer requirement means "a session
// token this hub can resolve", and a value that arrived under the same name but
// means something else is how an authentication path grows a second meaning
// nobody audits. Keeping them apart is also what lets authenticate() skip this one
// operation on the strength of what the document declares.
const SessionMintHeader = "X-Session-Mint-Secret"

// SessionMintScheme is the document's name for that secret.
const SessionMintScheme = "sessionMintSecret"

// sessionMintSecurity is the mint's declared requirement. It displaces the
// document's root bearer requirement — but with a real scheme rather than with the
// empty array publicSecurity() uses, because this operation is authenticated and a
// document that called it public would be lying about the most privileged call in
// the system.
func sessionMintSecurity() []map[string][]string {
	return []map[string][]string{{SessionMintScheme: {}}}
}

// ---- POST /v1/sessions -------------------------------------------------------

type createSessionInput struct {
	// Declared as a header parameter so huma parses it; hidden from the document
	// because the security scheme above already describes it, and a parameter
	// beside a scheme for the same header reads as two credentials.
	//
	// The name is spelled out because a struct tag cannot reference
	// SessionMintHeader. What holds the two together is a test: the mint's
	// accept-the-right-secret case sends the header under the constant, so a tag
	// that drifted from it fails rather than silently reading nothing.
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
		// The session being opened is a browser's, whatever reached this endpoint.
		// FR-050's other value, `cli / <host>`, belongs to the device flow.
		Source: auth.SourceWeb,
	})
	if err != nil {
		return nil, mintFailure(log, err)
	}

	// No token, no expiry and no subject in the log line. The response body is the
	// only place the plaintext token exists on this side, and it stays that way.
	log.Info().Str("identity_id", result.IdentityID.String()).Msg("session minted")

	return &createSessionOutput{Body: contract.Session{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
		ExpiresIn: int(time.Until(result.ExpiresAt).Round(time.Second).Seconds()),
	}}, nil
}

// mintFailure maps the mint's refusals onto the wire.
//
// None of the messages carries the secret, the presented secret's length, or the
// verifier's complaint: an ID token that failed verification is the one failure
// contracts/auth.md says is never explained to the browser, and the shared secret
// must not reach an error message at all. The causes go to the log with the
// request's correlation id, which is what joins an operator's report to them.
func mintFailure(log zerolog.Logger, err error) error {
	switch {
	case errors.Is(err, commands.ErrMintNotConfigured):
		// Error and not warn: sign-in is down hub-wide until an operator acts, and
		// this line is the only place that says so.
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

// ---- DELETE /v1/sessions/current ---------------------------------------------

func (s *Server) deleteSession(ctx context.Context, _ *struct{}) (*struct{}, error) {
	log := logging.From(ctx)

	principal, ok := PrincipalFrom(ctx)
	token := sessionTokenFrom(ctx)
	if !ok || token == "" {
		// Unreachable through the router — the operation inherits the bearer
		// requirement, so authenticate has already refused a request with neither.
		// Kept so that losing the declaration is a 401 rather than a sign-out of
		// nothing reported as success.
		return nil, huma.Error401Unauthorized("missing, expired or invalid token")
	}

	if err := commands.SignOut(ctx, s.deps.DB, principal, token); err != nil {
		return nil, fail(log, err)
	}
	return &struct{}{}, nil
}

// ---- GET /v1/viewer ----------------------------------------------------------

type getViewerOutput struct {
	Body contract.Viewer
}

// getViewer reports what authenticate already resolved on THIS request, and
// re-queries nothing.
//
// That is not an optimisation, it is FR-118: auth.Sessions.Resolve joins
// group_role_map on every authenticated request, so an admin's mapping change is
// in force on the next one with no cache to invalidate. Reading the principal here
// keeps exactly one implementation of "who is this and what may they do"; a second
// query would be a second answer, and the two would eventually disagree.
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
		// The role is the empty string when no group this identity holds maps to
		// one. auth.HighestRole returns that rather than a default, and FR-117's
		// screen depends on the distinction surviving the wire.
		HasRole: principal.Role != "",
		Groups:  groups,
	}}, nil
}

// ---- the lazy verifier -------------------------------------------------------

// LazyVerifier defers OIDC discovery to the first session mint.
//
// auth.NewVerifier reaches the network, and doing that in the api's bootstrap
// would make the identity provider a hard dependency of every operation this role
// serves: a provider that is slow to come up, or briefly down at the wrong moment,
// would take the catalog reads, /v1/health and the device flow with it. That is
// the same failure mode config.API.SessionMintSecret is deliberately not
// `required` to avoid, and it would be strange to reintroduce it one field over.
//
// So discovery happens on the first mint and is memoised on success. A failure is
// returned to that one caller — who renders "the hub could not complete sign-in"
// — and retried on the next, so a provider that comes up late needs no restart.
type LazyVerifier struct {
	cfg auth.VerifierConfig

	mu sync.Mutex
	// verifier is nil until discovery has succeeded once. The mutex is held across
	// the network call on purpose: concurrent first mints then perform one
	// discovery between them instead of one each.
	verifier *auth.Verifier
}

// NewLazyVerifier returns a verifier that discovers on first use. It performs no
// I/O, so a role can build one before the provider exists.
func NewLazyVerifier(cfg auth.VerifierConfig) *LazyVerifier {
	return &LazyVerifier{cfg: cfg}
}

// Verify discovers if it has to, then verifies.
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
