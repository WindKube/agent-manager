package queries

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
)

// badgeCountsSQL is one round trip of three scalar subqueries; the first %s
// is PackageReadable over `package`, the second Readable over `profile`.
// `packages` must match the catalog's base relation (latest pointer, visible,
// readability) and `profiles` the Profiles list, or the badge disagrees with
// the list or leaks private profiles by arithmetic. `openFindings` must stay
// exactly `state = 'open'` to use the partial index finding_open_version_idx.
const badgeCountsSQL = `
select
  (select count(*)
     from package as pkg
     join version as ver on ver.id = pkg.latest_version_id and ver.visible
    where %s),
  (select count(*) from profile as prf where %s),
  (select count(*) from finding as fnd where fnd.state = 'open')`

// Badges answers the shell's counts for one principal.
func Badges(ctx context.Context, db bun.IDB, p auth.Principal) (contract.Badges, error) {
	packagePredicate, packageArgs := PackageReadable("pkg", p)
	profilePredicate, profileArgs := Readable("prf", p)
	args := append(append([]any{}, packageArgs...), profileArgs...)

	var out contract.Badges
	if err := db.QueryRowContext(ctx, fmt.Sprintf(badgeCountsSQL, packagePredicate, profilePredicate), args...).
		Scan(&out.Packages, &out.Profiles, &out.OpenFindings); err != nil {
		return contract.Badges{}, fmt.Errorf("read the badge counts: %w", err)
	}
	return out, nil
}
