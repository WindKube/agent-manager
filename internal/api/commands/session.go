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

// The api's half of the browser sign-in flow (FR-111, contracts/auth.md).
//
// The web role owns the browser's origin and therefore the cookie; this role owns
// the relational schema and therefore the session row. SessionMint is the whole
// of what crosses that gap, which makes it the most privileged call in the
// system: it can open a session for any subject, so everything about it is
// written for a caller that might not be the web role.

// ErrMintNotConfigured is returned when this hub cannot mint sessions at all —
// no shared secret, or no ID-token verifier.
//
// It is deliberately distinguishable from ErrMintUnauthorized. The two mean
// opposite things to an operator ("set the variable" versus "the two values
// disagree") and a sign-in that fails with nothing visibly wrong on either side
// is exactly the failure config.API.SessionMintSecret's comment predicts. What it
// tells an unauthenticated prober is that sign-in is misconfigured, which the
// sign-in screen says out loud anyway.
var ErrMintNotConfigured = errors.New("session minting is not configured")

// ErrMintUnauthorized is returned when the caller presented the wrong secret.
var ErrMintUnauthorized = errors.New("the session mint secret is not accepted")

// ErrIDTokenRejected is returned when the presented ID token did not verify. The
// cause is wrapped for the log; it is never explained to the browser, which is
// the one failure in contracts/auth.md's table that gets no detail.
var ErrIDTokenRejected = errors.New("the id token was rejected")

// IDTokenVerifier verifies a raw ID token and returns its claims.
//
// An interface rather than *auth.Verifier because constructing one performs OIDC
// discovery over the network: the role's bootstrap decides when that happens and
// what to do when the provider is not up yet, and this package stays testable
// without either.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (auth.Claims, error)
}

// SessionMint is the api's session-minting capability: the secret it requires,
// the verifier it checks an ID token with, and how long the session it opens
// lasts.
type SessionMint struct {
	// Secret is the value a caller must present, compared in constant time.
	//
	// An EMPTY Secret refuses every mint. No default, no "allow when unset", no
	// development bypass: an unauthenticated session mint is an account-takeover
	// primitive (contracts/auth.md). The refusal lives HERE and not only in the
	// transport layer because this is the function that can create a session for
	// any subject — a check a future caller can route around is not a check, and
	// config.API deliberately does not mark the variable `required`, so this is
	// the only place the contract exists at all.
	Secret string
	// Verifier verifies the ID token the caller presents. Verification belongs to
	// the role that owns identity rather than to the caller, which is what demotes
	// Secret from THE control to defence in depth (plan.md's Complexity Tracking
	// row).
	Verifier IDTokenVerifier
	// TTL is how long a minted session lasts. A non-positive TTL is refused by
	// Login rather than defaulted here: two places that both know the default is
	// how they come to disagree about it.
	TTL time.Duration
}

// MintInput is one session-mint request as it arrived.
type MintInput struct {
	// Secret is what the caller presented, verbatim.
	Secret string
	// IDToken is the raw ID token, as the provider issued it.
	IDToken string
	// Source is the audit row's source column (FR-050).
	Source string
}

// Mint authenticates the caller, verifies the ID token and opens a session for
// the identity it names.
//
// The order is not arbitrary. The secret is checked before anything else, so a
// hub with no secret configured reaches neither the provider nor the database —
// which is what makes "refused when the secret is unset" a property rather than a
// hope, and what lets its test prove it with no database at all.
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

// secretAccepted compares two secrets without leaking which byte differed, or how
// long the configured one is.
//
// Both sides are hashed first, and that is the part worth stating:
// subtle.ConstantTimeCompare returns 0 immediately when the lengths differ, so
// comparing the raw strings would leak the configured secret's length one probe
// at a time. Hashing makes both operands 32 bytes whatever was presented, and
// sha256 is sound here for the same reason auth.HashToken gives — the values are
// high-entropy secrets, not passwords to grind.
func secretAccepted(configured, presented string) bool {
	want := sha256.Sum256([]byte(configured))
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// SignOut expires the session the caller presented and records that it happened,
// in one transaction (FR-114, FR-115, principle IV).
//
// The token rather than the identity: expiring every session an identity holds
// would sign a person out of every browser and every machine they had connected,
// which is a remote sign-out — a real feature, explicitly out of scope
// (contracts/openapi-additions.md), and not something a sign-out button should do
// by accident.
//
// The audit kind is `login` and not a `logout` value because the schema's
// audit_kind enum has none: adding one is `alter type ... add value`, a migration
// this task does not carry, and models_test asserts the Go value set against
// pg_enum. `login` is the session-lifecycle kind here, and the row's text is what
// separates the two halves of it — which is what the audit screen renders anyway.
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
