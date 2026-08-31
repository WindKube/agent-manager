package api

import (
	"context"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/logging"
)

// The shell's badge counts (T069, FR-121).

type badgesOutput struct {
	Body contract.Badges
}

// getBadges answers the sidebar's three counts for the caller.
//
// One operation and not three, because the shell renders on every screen: three
// operations would be three round trips per page for three integers. Research R5
// settled that shape, and settled the fallback too — if the counts ever measure
// too slow the answer is to drop a badge, not to add a projection.
//
// The profile count is scoped by FR-044 and the other two are not, which is not
// an oversight: a package is org-visible unconditionally today and a finding hangs
// off a package, so there is nothing to scope them by. See queries/badges.go.
func (s *Server) getBadges(ctx context.Context, _ *struct{}) (*badgesOutput, error) {
	principal, _ := PrincipalFrom(ctx)

	counts, err := queries.Badges(ctx, s.deps.DB, principal)
	if err != nil {
		return nil, fail(logging.From(ctx), err)
	}
	return &badgesOutput{Body: counts}, nil
}
