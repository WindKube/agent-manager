package queries

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// ServiceTokens lists the tokens p may manage: every token for a
// catalog-admin, otherwise the ones p created. A token lists nothing.
func ServiceTokens(ctx context.Context, db bun.IDB, p auth.Principal) ([]contract.ServiceToken, error) {
	if p.IsServiceToken() || p.IdentityID == uuid.Nil {
		return []contract.ServiceToken{}, nil
	}

	var rows []models.ServiceToken
	q := db.NewSelect().Model(&rows).Relation("CreatedBy").OrderExpr("svt.created_at desc")
	if p.Role != models.OrgRoleCatalogAdmin {
		q = q.Where("svt.created_by_identity_id = ?", p.IdentityID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list service tokens: %w", err)
	}

	now := time.Now()
	out := make([]contract.ServiceToken, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		createdBy := ""
		if row.CreatedBy != nil {
			createdBy = row.CreatedBy.Email
			if createdBy == "" {
				createdBy = row.CreatedBy.Subject
			}
		}
		out = append(out, ServiceTokenWire(row, createdBy, now))
	}
	return out, nil
}

// ServiceTokenWire is a token as the contract lists it, never with its hash.
func ServiceTokenWire(t *models.ServiceToken, createdBy string, now time.Time) contract.ServiceToken {
	status := "active"
	switch {
	case t.RevokedAt != nil:
		status = "revoked"
	case !t.ExpiresAt.After(now):
		status = "expired"
	}
	scopes := append([]string{}, t.Scopes...)
	return contract.ServiceToken{
		ID: t.ID.String(), Name: t.Name, Scopes: scopes, CreatedBy: createdBy,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		Status: status,
	}
}
