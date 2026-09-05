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
)

// listProfilesSQL: head revision and package count come from a lateral join
// over `revision` rather than loading every revision of every profile and
// counting in Go. %s is the readability predicate. jsonb_array_length over
// the head revision's `entries` array excludes skipped entries structurally,
// since `skipped` is a sibling array.
const listProfilesSQL = `
select
  p.slug,
  p.name,
  p.visibility::text,
  coalesce(head.seq, 0) as head_revision,
  coalesce(jsonb_array_length(head.lockfile -> 'entries'), 0) as package_count
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

	rows, err := db.QueryContext(ctx, fmt.Sprintf(listProfilesSQL, predicate), args...)
	if err != nil {
		return nil, fmt.Errorf("list readable profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	profiles := []contract.Profile{}
	for rows.Next() {
		var prof contract.Profile
		if err := rows.Scan(&prof.Slug, &prof.Name, &prof.Visibility, &prof.HeadRevision, &prof.PackageCount); err != nil {
			return nil, fmt.Errorf("scan readable profile: %w", err)
		}
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
	// The contract types entries, skipped and targets as required arrays, and a nil
	// Go slice marshals to null. A stored lockfile written before one of these
	// existed must not turn into a document that violates its own schema.
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

// ReadableRevisionRef resolves a profile slug and revision number to ids, under
// the same readability predicate as everything else. It takes a bun.IDB so a
// command can call it inside its own transaction.
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
