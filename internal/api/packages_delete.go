package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/logging"
	"agent-manager/internal/store/models"
)

// Deleting from the catalog: withdrawing a version or a whole package, both
// gated on catalog-admin like the hub's other administration surfaces
// (/v1/runtime, /v1/storage, /v1/organization/*). See
// internal/api/commands/packages_delete.go for what "delete" means here and
// why: neither operation removes a row or a blob.

type deleteVersionInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace, as it appears in the catalog."`
	Name      string `path:"name" doc:"The package name within that namespace."`
	Version   string `path:"version" doc:"An exact semver. Ranges and dist-tags are not accepted."`
}

type deleteVersionOutput struct {
	Body contract.VersionDeleted
}

func (s *Server) deleteVersion(ctx context.Context, in *deleteVersionInput) (*deleteVersionOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "delete a version", models.OrgRoleCatalogAdmin); err != nil {
		return nil, err
	}

	out, err := commands.DeleteVersion(ctx, s.deps.DB, principal, in.Namespace, in.Name, in.Version)
	switch {
	case errors.Is(err, commands.ErrPackageNotFound), errors.Is(err, commands.ErrVersionNotFound):
		return nil, huma.Error404NotFound(err.Error())
	case errors.Is(err, commands.ErrAlreadyWithdrawn):
		return nil, huma.Error409Conflict(err.Error())
	case err != nil:
		return nil, fail(logging.From(ctx), err)
	}
	return &deleteVersionOutput{Body: contract.VersionDeleted{PinnedByProfiles: out.PinnedByProfiles}}, nil
}

type deletePackageInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace, as it appears in the catalog."`
	Name      string `path:"name" doc:"The package name within that namespace."`
}

type deletePackageOutput struct {
	Body contract.PackageDeleted
}

func (s *Server) deletePackage(ctx context.Context, in *deletePackageInput) (*deletePackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)
	if err := requireRole(principal.Role, "delete a package", models.OrgRoleCatalogAdmin); err != nil {
		return nil, err
	}

	out, err := commands.DeletePackage(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	switch {
	case errors.Is(err, commands.ErrPackageNotFound):
		return nil, huma.Error404NotFound(err.Error())
	case errors.Is(err, commands.ErrAlreadyWithdrawn):
		return nil, huma.Error409Conflict(err.Error())
	case err != nil:
		return nil, fail(logging.From(ctx), err)
	}
	return &deletePackageOutput{Body: contract.PackageDeleted{VersionsArchived: out.VersionsArchived}}, nil
}
