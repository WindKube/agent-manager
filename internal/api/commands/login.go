package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// LoginInput is a verified ID token's claims plus how long the session lasts.
// Verification happened before this: a command does not check signatures.
type LoginInput struct {
	Claims     auth.Claims
	SessionTTL time.Duration
	Source     string
}

// LoginResult carries the session token exactly once. It is never stored and
// never logged; what the row holds is its sha256 (auth.HashToken).
type LoginResult struct {
	Token      string
	IdentityID uuid.UUID
	ExpiresAt  time.Time
}

// Login records a sign-in: the identity is upserted, a session is opened and the
// `login` audit row is written, all inside one transaction (FR-050).
//
// It deliberately does not derive the caller's role. auth.Sessions.Resolve does
// that on every request, and having exactly one implementation of the
// groups-to-role mapping is what stops the login path and the request path from
// disagreeing about who someone is.
func Login(ctx context.Context, db bun.IDB, in LoginInput) (LoginResult, error) {
	if in.Claims.Subject == "" {
		return LoginResult{}, fmt.Errorf("login needs a subject claim")
	}
	if in.SessionTTL <= 0 {
		return LoginResult{}, fmt.Errorf("login needs a positive session ttl")
	}

	token, err := auth.NewToken()
	if err != nil {
		return LoginResult{}, err
	}

	now := time.Now().UTC()
	result := LoginResult{Token: token, ExpiresAt: now.Add(in.SessionTTL)}

	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		groups := in.Claims.Groups
		if groups == nil {
			groups = []string{}
		}
		identity := &models.Identity{
			ID:          models.NewID(),
			Subject:     in.Claims.Subject,
			Email:       in.Claims.Email,
			DisplayName: in.Claims.DisplayName(),
			Groups:      groups,
			LastSeenAt:  &now,
		}
		// `groups` is refreshed here and only here, which is what makes FR-045
		// true: losing a mapped group takes effect at the next token issue.
		if _, insertErr := tx.NewInsert().Model(identity).
			On("conflict (subject) do update").
			Set("email = excluded.email").
			Set("display_name = excluded.display_name").
			Set(`"groups" = excluded."groups"`).
			Set("last_seen_at = excluded.last_seen_at").
			Set("updated_at = now()").
			Returning("id").
			Exec(ctx); insertErr != nil {
			return fmt.Errorf("upsert identity: %w", insertErr)
		}
		result.IdentityID = identity.ID

		session := &models.Session{
			ID:         models.NewID(),
			TokenHash:  auth.HashToken(token),
			IdentityID: identity.ID,
			ExpiresAt:  result.ExpiresAt,
		}
		if _, insertErr := tx.NewInsert().Model(session).Exec(ctx); insertErr != nil {
			return fmt.Errorf("open session: %w", insertErr)
		}

		actor := in.Claims.Email
		if actor == "" {
			actor = in.Claims.Subject
		}
		return writeAudit(ctx, tx, models.AuditKindLogin, actor, string(models.ActorKindIdentity),
			fmt.Sprintf("%s signed in", actor), in.Source)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

// ExpireSession ends a session by moving its expiry into the past. It is not a
// DELETE: no database role holds one on `session`, because the row carries
// `expires_at` and an expired session is one whose expiry has passed
// (data-model.md's withheld-grant list).
func ExpireSession(ctx context.Context, db bun.IDB, token string) error {
	res, err := db.NewUpdate().
		Model((*models.Session)(nil)).
		Set("expires_at = now()").
		Set("updated_at = now()").
		Where("token_hash = ?", auth.HashToken(token)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("expire session: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("expire session: %w", err)
	}
	if affected == 0 {
		return auth.ErrUnauthenticated
	}
	return nil
}
