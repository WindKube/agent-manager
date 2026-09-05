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
	"agent-manager/internal/store/models"
)

// The api's half of the browser sign-in flow. The web role owns the
// cookie; this role owns the session row, and SessionMint is the whole of
// what crosses that gap — the most privileged call in the system, since
// it can open a session for any subject.

// ErrMintNotConfigured (no secret, or no verifier) is deliberately
// distinguishable from ErrMintUnauthorized: the two mean opposite things
// to an operator, and either tells an unauthenticated prober only that
// sign-in is misconfigured.
var ErrMintNotConfigured = errors.New("session minting is not configured")

var ErrMintUnauthorized = errors.New("the session mint secret is not accepted")

// ErrIDTokenRejected's cause is wrapped for the log but never explained
// to the browser.
var ErrIDTokenRejected = errors.New("the id token was rejected")

// IDTokenVerifier is an interface rather than *auth.Verifier because
// constructing one performs OIDC discovery over the network, which this
// package should stay testable without.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (auth.Claims, error)
}

// SessionMint is the api's session-minting capability.
type SessionMint struct {
	// Secret is compared in constant time. An empty Secret refuses every
	// mint — no default, no "allow when unset" — since an unauthenticated
	// session mint is an account-takeover primitive, and this is the only
	// place that check can live.
	Secret string
	// Verifier does the actual verification, which demotes Secret from
	// the control to defence in depth.
	Verifier IDTokenVerifier
	// TTL non-positive is refused by Login rather than defaulted here, so
	// the two places can't disagree about the default.
	TTL time.Duration
}

// MintInput is one session-mint request as it arrived.
type MintInput struct {
	Secret  string
	IDToken string
	Source  string
}

// Mint authenticates the caller, verifies the ID token and opens a
// session for the identity it names. The secret is checked before
// anything else, so a hub with no secret configured reaches neither the
// provider nor the database.
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

// secretAccepted compares two secrets without leaking which byte differed
// or how long the configured one is. Both sides are hashed first:
// subtle.ConstantTimeCompare returns 0 immediately on a length mismatch,
// so comparing raw strings would leak the configured secret's length one
// probe at a time.
func secretAccepted(configured, presented string) bool {
	want := sha256.Sum256([]byte(configured))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// SignOut expires the session the caller presented and records that it
// happened, in one transaction. The token, not the identity: expiring
// every session an identity holds would be a remote sign-out, a separate
// feature a sign-out button shouldn't do by accident.
//
// The audit kind is `login`, since the schema has no `logout` value; the
// row's text separates the two halves.
func SignOut(ctx context.Context, db bun.IDB, p auth.Principal, token string) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := ExpireSession(ctx, tx, token); err != nil {
			return err
		}

		actor := p.Email
		if actor == "" {
			actor = p.Subject
		}
		return writeAudit(ctx, tx, models.AuditKindLogin, actor, string(models.ActorKindIdentity),
			fmt.Sprintf("%s signed out", actor), p.Source)
	})
}
