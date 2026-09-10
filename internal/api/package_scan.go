package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// The package detail screen's security section (the owner's "collapsible
// section... scan result and approval and comment"): the latest visible
// version's scan, findings and any reviewer decision, scoped to one
// package. It reads the same rows /v1/findings and /v1/findings/{id} do
// (internal/api/queries/package_scan.go), so the two screens cannot render
// two different ideas of a finding.

type getPackageScanInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
}

type getPackageScanOutput struct {
	Body contract.PackageScan
}

// getPackageScan refuses a rejected version exactly as GET
// /v1/bundles/{publisher}/{name}/{version} does (FR-029): a version that is
// never distributed does not have its scan detail served either.
func (s *Server) getPackageScan(ctx context.Context, in *getPackageScanInput) (*getPackageScanOutput, error) {
	scan, err := queries.PackageScan(ctx, s.deps.DB, in.Namespace, in.Name)
	if err != nil {
		if errors.Is(err, queries.ErrRejected) {
			return nil, huma.Error403Forbidden(err.Error())
		}
		return nil, fail(logging.From(ctx), err)
	}
	return &getPackageScanOutput{Body: scan}, nil
}
