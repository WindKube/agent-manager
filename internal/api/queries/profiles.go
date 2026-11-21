package queries

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// listProfilesSQL takes head revision and package count from a lateral join.
// The first %s is the role subquery (shared with readProfile), the second the
// readability predicate. Skipped entries live in a sibling array, so
// jsonb_array_length(entries) excludes them.
const listProfilesSQL = `
select
  p.slug,
  p.name,
  p.visibility::text,
  coalesce(head.seq, 0) as head_revision,
  coalesce(jsonb_array_length(head.lockfile -> 'entries'), 0) as package_count,
  %s as role
from profile as p
left join lateral (
  select r.seq, r.lockfile
  from revision as r
  where r.profile_id = p.id
  order by r.seq desc
  limit 1
) as head on true
where %s
order by p.name`

// ReadableProfiles returns exactly the profiles this principal may read.
func ReadableProfiles(ctx context.Context, db bun.IDB, p auth.Principal) ([]contract.Profile, error) {
	predicate, args := Readable("p", p)

	role := "null::text"
	subject, subjectArgs, matchable := subjectPredicate("m", p)
	if matchable {
		role = "(select min(m.role)::text from membership as m where m.profile_id = p.id and " + subject + ")"
	}

	// The role subquery precedes the WHERE clause, so its arguments come first.
	query := fmt.Sprintf(listProfilesSQL, role, predicate)
	queryArgs := append(append([]any{}, subjectArgs...), args...)

	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("list readable profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	profiles := []contract.Profile{}
	for rows.Next() {
		var (
			prof     contract.Profile
			roleText sql.NullString
		)
		if err := rows.Scan(&prof.Slug, &prof.Name, &prof.Visibility, &prof.HeadRevision,
			&prof.PackageCount, &roleText); err != nil {
			return nil, fmt.Errorf("scan readable profile: %w", err)
		}
		prof.CanCurate = models.MembershipRole(roleText.String).MayCurate()
		profiles = append(profiles, prof)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list readable profiles: %w", err)
	}
	return profiles, nil
}

// RevisionLockfile returns one published revision's lockfile. seq nil means the
// head revision. An unreadable profile is indistinguishable from a missing one.
func RevisionLockfile(ctx context.Context, db bun.IDB, p auth.Principal, slug string, seq *int) (contract.Lockfile, error) {
	predicate, args := Readable("p", p)

	query := `
select r.lockfile
from revision as r
join profile as p on p.id = r.profile_id
where p.slug = ? and ` + predicate
	queryArgs := append([]any{slug}, args...)
	if seq != nil {
		query += " and r.seq = ?"
		queryArgs = append(queryArgs, *seq)
	}
	query += " order by r.seq desc limit 1"

	var raw json.RawMessage
	err := db.QueryRowContext(ctx, query, queryArgs...).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.Lockfile{}, ErrNotFound
	case err != nil:
		return contract.Lockfile{}, fmt.Errorf("read revision lockfile: %w", err)
	}

	var lock contract.Lockfile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return contract.Lockfile{}, fmt.Errorf("decode stored lockfile for %s: %w", slug, err)
	}
	// The contract requires these arrays, and an older stored lockfile may lack them.
	if lock.Entries == nil {
		lock.Entries = []contract.LockfileEntry{}
	}
	if lock.Skipped == nil {
		lock.Skipped = []contract.LockfileSkip{}
	}
	if lock.Targets == nil {
		lock.Targets = []string{}
	}
	return lock, nil
}

// RevisionRef is the identity of a published revision, for a caller that needs
// to write a row referencing it.
type RevisionRef struct {
	ProfileID  uuid.UUID
	RevisionID uuid.UUID
	Seq        int
}

// ReadableRevisionRef resolves a readable profile slug and revision number to
// ids. It takes a bun.IDB so a command can call it inside its transaction.
func ReadableRevisionRef(ctx context.Context, db bun.IDB, p auth.Principal, slug string, seq int) (RevisionRef, error) {
	predicate, args := Readable("p", p)

	query := `
select p.id, r.id, r.seq
from revision as r
join profile as p on p.id = r.profile_id
where p.slug = ? and r.seq = ? and ` + predicate

	var ref RevisionRef
	err := db.QueryRowContext(ctx, query, append([]any{slug, seq}, args...)...).
		Scan(&ref.ProfileID, &ref.RevisionID, &ref.Seq)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return RevisionRef{}, ErrNotFound
	case err != nil:
		return RevisionRef{}, fmt.Errorf("resolve revision %s@r%d: %w", slug, seq, err)
	}
	return ref, nil
}
