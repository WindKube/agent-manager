package queries

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// The shell's badge counts (003 FR-121, T069).
//
// FR-121 forbids the compiled-in `10 / 4 / 4` the sidebar carries today, and
// research R5 already decided the shape this answers in: ONE operation returning
// the viewer's own counts, called once per full page render and not at all on a
// fragment update. Three counts, not three operations — the shell is rendered on
// every screen, so three round trips would be three per page.
//
// PRINCIPLE VIII IS NOT SPENT HERE. These are indexed counts over the base
// tables, not a materialised view: `catalog_entry` is the one projection the
// constitution sanctions and 001's R12 left that allowance unspent. R5 records
// the fallback if these ever measure too slow — drop a badge — precisely so the
// decision is not relitigated under deadline, and this comment is where the next
// person reads it.

// badgeCountsSQL is one statement of three scalar subqueries, so the shell costs
// one round trip. %s is the FR-044 predicate over `profile`.
//
// `packages` reproduces the catalog's own base relation exactly — the latest
// version pointer, `visible`, and `visibility = 'organisation'` — because the
// badge sits beside a screen that reports its own total, and a badge that
// counted differently from the list under it is a badge nobody trusts twice.
// Both halves of the join condition are load-bearing for the same reason they
// are there: commit-last means a half-published version exists as an invisible
// row, and a package whose only version is still being fetched has no pointer.
//
// `profiles` is the FR-044 predicate and nothing else, so the badge is exactly
// the length of the list the Profiles screen renders. It has to be: a count that
// included a profile the reader cannot open would leak the existence of a private
// profile by arithmetic, which is the hazard packageVersions' pinned-by count
// already documents at package scope. A nav badge is that hazard at global scope.
//
// `openFindings` is served by `finding_open_version_idx`, the partial index on
// `("version_id") where "state" = 'open'` — a count over a partial index reads
// only the index, and only the open minority is in it. The predicate here must
// stay exactly `state = 'open'` to match the index's own; widen it and this
// becomes a sequential scan of every finding ever raised.
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
