package queries

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// The shell's badge counts are one operation returning the viewer's own
// counts, called once per full page render and not at all on a fragment
// update. Three counts, not three operations: the shell renders on every
// screen, so three round trips would be three per page. These are indexed
// counts over the base tables, not a materialised view.

// badgeCountsSQL is one statement of three scalar subqueries, so the shell
// costs one round trip. %s is the readability predicate over `profile`.
//
// `packages` reproduces the catalog's own base relation exactly — the
// latest version pointer, `visible`, and `visibility = 'organisation'` —
// because a badge that counted differently from the list under it is a
// badge nobody trusts twice. Both halves of the join condition matter for
// the same reason they do elsewhere: commit-last means a half-published
// version exists as an invisible row, and a package whose only version is
// still being fetched has no pointer.
//
// `profiles` is the readability predicate and nothing else, so the badge is
// exactly the length of the list the Profiles screen renders — a count
// that included a profile the reader cannot open would leak the existence
// of a private profile by arithmetic, the same hazard packageVersions'
// pinned-by count documents at package scope.
//
// `openFindings` is served by `finding_open_version_idx`, a partial index
// on `("version_id") where "state" = 'open'`: a count over it reads only
// the index. The predicate here must stay exactly `state = 'open'` to
// match the index's own; widen it and this becomes a sequential scan of
// every finding ever raised.
const badgeCountsSQL = `
select
  (select count(*)
     from package as pkg
     join version as ver on ver.id = pkg.latest_version_id and ver.visible
    where pkg.visibility = 'organisation'),
  (select count(*) from profile as prf where %s),
  (select count(*) from finding as fnd where fnd.state = 'open')`

// Badges answers the shell's counts for one principal.
func Badges(ctx context.Context, db bun.IDB, p auth.Principal) (contract.Badges, error) {
	predicate, args := Readable("prf", p)

	var out contract.Badges
	if err := db.QueryRowContext(ctx, fmt.Sprintf(badgeCountsSQL, predicate), args...).
		Scan(&out.Packages, &out.Profiles, &out.OpenFindings); err != nil {
		return contract.Badges{}, fmt.Errorf("read the badge counts: %w", err)
	}
	return out, nil
}
