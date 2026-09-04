package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// The Storage screen's read (001 FR-053, 003 US7 scenario 2).

type storageOutput struct {
	Body contract.StorageReport
}

// getStorage answers GET /v1/storage, gated to catalog-admin like the hub's
// other administration screens (Organization); the operator this report is for
// holds that role.
func (s *Server) getStorage(ctx context.Context, _ *struct{}) (*storageOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "read the storage report", models.OrgRoleCatalogAdmin); err != nil {
		return nil, err
	}

	report, err := queries.Storage(ctx, s.deps.DB, s.deps.Storage)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &storageOutput{Body: report}, nil
}
