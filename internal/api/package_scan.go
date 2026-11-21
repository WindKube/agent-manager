package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// The package detail screen's security section. It reads the same rows as
// /v1/findings, so the two screens cannot disagree about a finding.

type getPackageScanInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
}

type getPackageScanOutput struct {
	Body contract.PackageScan
}

// getPackageScan refuses a rejected version, as the bundle download does.
func (s *Server) getPackageScan(ctx context.Context, in *getPackageScanInput) (*getPackageScanOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	scan, err := queries.PackageScan(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		if errors.Is(err, queries.ErrRejected) {
			return nil, huma.Error403Forbidden(err.Error())
		}
		return nil, fail(logging.From(ctx), err)
	}
	return &getPackageScanOutput{Body: scan}, nil
}
