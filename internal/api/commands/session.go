package commands

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// ErrMintNotConfigured (no secret, or no verifier) is kept distinct from
// ErrMintUnauthorized because the two mean opposite things to an operator.
var ErrMintNotConfigured = errors.New("session minting is not configured")

var ErrMintUnauthorized = errors.New("the session mint secret is not accepted")

// ErrIDTokenRejected's cause is wrapped for the log but never explained
// to the browser.
var ErrIDTokenRejected = errors.New("the id token was rejected")

// IDTokenVerifier is an interface rather than *auth.Verifier so this package
// stays testable without OIDC discovery over the network.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (auth.Claims, error)
}

// SessionMint is the api's session-minting capability, the most privileged
// call in the system: it can open a session for any subject.
type SessionMint struct {
	// Secret is compared in constant time. An empty Secret refuses every mint:
	// an unauthenticated mint is an account-takeover primitive, and this is the
	// only place that check can live.
	Secret   string
	Verifier IDTokenVerifier
	// TTL non-positive is refused by Login rather than defaulted here.
	TTL time.Duration
}

// MintInput is one session-mint request as it arrived.
type MintInput struct {
	Secret  string
	IDToken string
	Source  string
}

// Mint authenticates the caller, verifies the ID token and opens a session
// for the identity it names. The secret is checked first, so an unconfigured
// hub reaches neither the provider nor the database.
func (m SessionMint) Mint(ctx context.Context, db bun.IDB, in MintInput) (LoginResult, error) {
	if m.Secret == "" {
		return LoginResult{}, ErrMintNotConfigured
	}
	if !secretAccepted(m.Secret, in.Secret) {
		return LoginResult{}, ErrMintUnauthorized
	}
	if m.Verifier == nil {
		return LoginResult{}, ErrMintNotConfigured
	}
	if in.IDToken == "" {
		return LoginResult{}, fmt.Errorf("%w: none was presented", ErrIDTokenRejected)
	}

	claims, err := m.Verifier.Verify(ctx, in.IDToken)
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: %w", ErrIDTokenRejected, err)
	}
	return Login(ctx, db, LoginInput{Claims: claims, SessionTTL: m.TTL, Source: in.Source})
}

// secretAccepted hashes both sides first because subtle.ConstantTimeCompare
// returns early on a length mismatch, which would leak the secret's length.
func secretAccepted(configured, presented string) bool {
	want := sha256.Sum256([]byte(configured))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// SignOut expires only the presented session, not every session the identity
// holds. The audit kind is `login` since the schema has no `logout` value.
func SignOut(ctx context.Context, db bun.IDB, p auth.Principal, token string) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := ExpireSession(ctx, tx, token); err != nil {
			return err
		}

		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindLogin, "signed-out",
			fmt.Sprintf("%s signed out", memberRef(p)), audit.Identity(p.IdentityID)))
	})
}
