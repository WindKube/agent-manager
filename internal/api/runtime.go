package api

import (
	"context"
	"time"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

type runtimeOutput struct {
	Body contract.RuntimeReport
}

// getRuntime answers GET /v1/runtime, gated to catalog-admin like the hub's
// other administration screens: queue depth, retry state and runner errors
// are operational detail, not something every viewer should read.
func (s *Server) getRuntime(ctx context.Context, _ *struct{}) (*runtimeOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "read the runtime report", models.OrgRoleCatalogAdmin); err != nil {
		return nil, err
	}

	report, err := queries.Runtime(ctx, s.deps.Queue, time.Now())
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &runtimeOutput{Body: report}, nil
}
