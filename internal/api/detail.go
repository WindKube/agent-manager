package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// The package detail operation (US3, T058). The web role reaches it through the
// generated client and holds no other door to this data.

// getPackageInput is the package id, spelled out as the two segments it is made
// of.
//
// The frozen contract's inventory calls this `GET /v1/packages/{id}`, and the
// URL is exactly that: `/v1/packages/` followed by the id. The TEMPLATE has two
// parameters because the id is `namespace/name` — two segments — and a single
// `{id}` would have to arrive percent-encoded. It would not survive the trip:
// gin routes on the DECODED path, so `example%2Fplatform-toolkit` reaches the
// router as two segments anyway and matches nothing. Two parameters is the same
// URL, honestly declared, and it is the shape /v1/bundles already uses.
type getPackageInput struct {
	Namespace string `path:"namespace" doc:"The publishing namespace — the FIRST segment of the publisher slug, as it appears in the catalog id. Not the whole slug." example:"example"`
	Name      string `path:"name" doc:"The package name within that namespace." example:"platform-toolkit"`
}

type getPackageOutput struct {
	Body contract.PackageDetail
}

// getPackage answers the detail screen. It inherits the document's root bearer
// requirement, like the catalog: there is no anonymous view.
//
// The principal is passed down rather than used here, because two panels are
// scoped by it — the dependent profiles and each version's pin count. That is
// FR-044 applied to a page it is easy to forget: the profiles a package is used
// by are still profiles, and a private one must not be enumerable through a
// package anyone may open.
func (s *Server) getPackage(ctx context.Context, in *getPackageInput) (*getPackageOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	detail, err := queries.Package(ctx, s.deps.DB, principal, in.Namespace, in.Name)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &getPackageOutput{Body: detail}, nil
}
