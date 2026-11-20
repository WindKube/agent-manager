package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

var (
	// ErrServiceTokenNeedsAPerson refuses token management by anything but a
	// signed-in person, a service token included.
	ErrServiceTokenNeedsAPerson = errors.New("service tokens are managed only by a signed-in person")
	// ErrServiceTokenNotFound covers both a missing token and one the caller
	// may not manage, so a token id cannot be probed.
	ErrServiceTokenNotFound = errors.New("no such service token")
)

// CreateServiceTokenInput is one creation request as it arrived.
type CreateServiceTokenInput struct {
	Name      string
	Scopes    []string
	ExpiresAt time.Time
}

// CreatedServiceToken carries the only copy of the secret there will ever be.
type CreatedServiceToken struct {
	Token  models.ServiceToken
	Secret string
}

// CreateServiceToken mints a token for a person. Every sync:profile scope must
// name a profile the creator can read right now.
func CreateServiceToken(ctx context.Context, db bun.IDB, p auth.Principal, in CreateServiceTokenInput) (CreatedServiceToken, error) {
	if !mayManageServiceTokens(p) {
		return CreatedServiceToken{}, ErrServiceTokenNeedsAPerson
	}

	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > auth.MaxServiceTokenNameLength {
		return CreatedServiceToken{}, fmt.Errorf("%w: a token needs a name of 1 to %d characters",
			ErrValidation, auth.MaxServiceTokenNameLength)
	}
	scopes, err := auth.ParseScopes(in.Scopes)
	if err != nil {
		return CreatedServiceToken{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	now := time.Now().UTC()
	switch {
	case in.ExpiresAt.IsZero():
		return CreatedServiceToken{}, fmt.Errorf("%w: a token needs an expiry", ErrValidation)
	case !in.ExpiresAt.After(now):
		return CreatedServiceToken{}, fmt.Errorf("%w: the expiry must be in the future", ErrValidation)
	case in.ExpiresAt.After(now.Add(auth.MaxServiceTokenLifetime)):
		return CreatedServiceToken{}, fmt.Errorf("%w: the expiry must be within %d days",
			ErrValidation, int(auth.MaxServiceTokenLifetime.Hours()/24))
	}

	secret, err := auth.NewServiceTokenSecret()
	if err != nil {
		return CreatedServiceToken{}, err
	}
	token := models.ServiceToken{
		ID:                  models.NewID(),
		Name:                name,
		TokenHash:           auth.HashToken(secret),
		Scopes:              make([]string, 0, len(scopes)),
		CreatedByIdentityID: p.IdentityID,
		ExpiresAt:           in.ExpiresAt.UTC(),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	for _, scope := range scopes {
		token.Scopes = append(token.Scopes, string(scope))
	}

	err = db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if readErr := requireReadableProfiles(ctx, tx, p, scopes); readErr != nil {
			return readErr
		}
		if _, insertErr := tx.NewInsert().Model(&token).Exec(ctx); insertErr != nil {
			return fmt.Errorf("insert service token: %w", insertErr)
		}

		entry := identityAudit(p, models.AuditKindToken, "created",
			fmt.Sprintf("created service token %s (%s), expiring %s", name,
				strings.Join(token.Scopes, ", "), token.ExpiresAt.Format(time.DateOnly)),
			audit.ServiceToken(token.ID, name))
		entry.Data = map[string]any{"scopes": token.Scopes, "expiresAt": token.ExpiresAt.Format(time.RFC3339)}
		return writeAudit(ctx, tx, entry)
	})
	if err != nil {
		return CreatedServiceToken{}, err
	}
	return CreatedServiceToken{Token: token, Secret: secret}, nil
}

// RevokeServiceToken revokes a token its creator holds, or any token for a
// catalog-admin. Revoking a revoked token changes nothing and audits nothing.
func RevokeServiceToken(ctx context.Context, db bun.IDB, p auth.Principal, id uuid.UUID) (models.ServiceToken, error) {
	if !mayManageServiceTokens(p) {
		return models.ServiceToken{}, ErrServiceTokenNeedsAPerson
	}

	var token models.ServiceToken
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		err := tx.NewSelect().Model(&token).Where("id = ?", id).For("update").Scan(ctx)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrServiceTokenNotFound
		case err != nil:
			return fmt.Errorf("load service token: %w", err)
		}
		if token.CreatedByIdentityID != p.IdentityID && p.Role != models.OrgRoleCatalogAdmin {
			return ErrServiceTokenNotFound
		}
		if token.RevokedAt != nil {
			return nil
		}

		if err := tx.NewUpdate().Model(&token).
			Set("revoked_at = now()").Set("updated_at = now()").
			Where("id = ?", id).
			Returning("revoked_at, updated_at").
			Scan(ctx); err != nil {
			return fmt.Errorf("revoke service token: %w", err)
		}
		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindToken, "revoked",
			"revoked service token "+token.Name, audit.ServiceToken(token.ID, token.Name)))
	})
	if err != nil {
		return models.ServiceToken{}, err
	}
	return token, nil
}

func mayManageServiceTokens(p auth.Principal) bool {
	return !p.IsServiceToken() && p.IdentityID != uuid.Nil
}

// requireReadableProfiles refuses a sync:profile scope on a profile the
// creator cannot read, without saying whether it exists.
func requireReadableProfiles(ctx context.Context, tx bun.IDB, p auth.Principal, scopes []auth.Scope) error {
	grant := auth.ServiceTokenGrant{Scopes: scopes}
	wanted := grant.Profiles()
	if len(wanted) == 0 {
		return nil
	}

	predicate, args := queries.Readable("p", p)
	var readable []string
	if err := tx.NewRaw("select p.slug from profile as p where p.slug in (?) and "+predicate,
		append([]any{bun.List(wanted)}, args...)...).Scan(ctx, &readable); err != nil {
		return fmt.Errorf("check profile readability: %w", err)
	}
	for _, slug := range wanted {
		if !slices.Contains(readable, slug) {
			return fmt.Errorf("%w: no profile %q that this identity can sync", ErrValidation, slug)
		}
	}
	return nil
}
