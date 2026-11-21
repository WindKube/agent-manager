package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// getPackageInput splits the package id `namespace/name` into two path parameters,
// because they are matched against two columns.
type getPackageInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
}

type getPackageOutput struct {
	Body contract.PackageDetail
}

// getPackage answers the detail screen. The principal scopes the dependent-profiles
// panel and pin counts, so private profiles are not enumerable through a package.
func (s *Server) getPackage(ctx context.Context, in *getPackageInput) (*getPackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	detail, err := queries.Package(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &getPackageOutput{Body: detail}, nil
}
