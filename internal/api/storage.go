package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

type storageOutput struct {
	Body contract.StorageReport
}

// getStorage answers GET /v1/storage, gated to catalog-admin like the hub's
// other administration screens.
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
