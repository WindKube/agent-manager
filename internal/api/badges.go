package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

type badgesOutput struct {
	Body contract.Badges
}

// getBadges answers the sidebar's three counts in one operation, since the shell
// renders on every screen. Only the profile count is visibility-scoped; packages are
// org-visible and findings hang off packages.
func (s *Server) getBadges(ctx context.Context, _ *struct{}) (*badgesOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	counts, err := queries.Badges(ctx, s.deps.DB, principal)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &badgesOutput{Body: counts}, nil
}
