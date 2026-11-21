package queries

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/domain/resolve"
	"agent-manager/internal/domain/signer"
	"agent-manager/internal/store/models"
)

// The statements below only load facts; internal/domain/resolve decides what
// they mean, so never encode gate logic in SQL here. They run sequentially
// because PublishRevision resolves inside its own transaction (one connection).

// ProfileFacts is the profile row and the caller's standing on it.
// ForkedFrom is lineage only; HeadRevision is 0 when nothing is published.
type ProfileFacts struct {
	ID            uuid.UUID
	Slug          string
	Name          string
	Description   string
	OwnerTeam     string
	Visibility    models.ProfileVisibility
	DefaultPolicy models.VersionPolicy
	ForkedFrom    string
	Role          models.MembershipRole
	HeadRevision  int
}

// ProfileResolution is one profile resolved under the organisation's gate.
// The detail screen and the publish command share it, so a revision freezes
// exactly what the screen displayed.
type ProfileResolution struct {
	Profile           ProfileFacts
	Gate              models.ScanGate
	RequireSignatures bool
	// Targets are the enabled sync targets in the vocabulary's own order.
	Targets []string
	Result  resolve.Result
	// entries is index-aligned with Result.Entries.
	entries []profileEntryRow
}

type profileEntryRow struct {
	packageID     uuid.UUID
	id            string
	name          string
	kind          string
	mode          models.EntryMode
	rangeExpr     string
	pinnedID      string
	pinnedSemver  string
	latestSemver  string
	latestVerdict string
}

func (r ProfileResolution) Lockfile(revision int, note string, at time.Time) contract.Lockfile {
	return contract.LockfileFrom(
		contract.LockfileProfile{
			Slug:       r.Profile.Slug,
			Name:       r.Profile.Name,
			Visibility: string(r.Profile.Visibility),
		},
		revision, note, at, string(r.Profile.DefaultPolicy), r.Targets, r.Result,
	)
}

// ErrNoPolicy is returned when `org_policy` holds no singleton row. There is
// no safe default: allowing everything is a bypass, blocking everything an outage.
var ErrNoPolicy = errors.New("org_policy holds no row, so there is no scan gate to resolve under")

// profileFactsSQL identifies the profile and the caller's standing on it.
// The first %s is the caller's role, the second the readability predicate.
// `min(role)` is the most privileged role, as `membership_role` is declared
// privilege-first.
const profileFactsSQL = `
select
  p.id,
  p.slug,
  p.name,
  coalesce(p.description, ''),
  coalesce(p.owner_team, ''),
  p.visibility::text,
  p.default_policy::text,
  coalesce(up.slug, ''),
  %s,
  coalesce((select max(r.seq) from revision as r where r.profile_id = p.id), 0)
from profile as p
left join profile as up on up.id = p.forked_from_id
where p.slug = ? and %s`

// Profile reads one readable profile row; an unreadable one is ErrNotFound.
func Profile(ctx context.Context, db bun.IDB, p auth.Principal, slug string) (ProfileFacts, error) {
	return readProfile(ctx, db, p, slug, false)
}

// LockProfile is Profile with the row locked until the caller's transaction
// ends (`for update of p`: Postgres refuses to lock the outer join's nullable
// side). HeadRevision may still be stale under READ COMMITTED, so allocators
// re-read it after locking.
func LockProfile(ctx context.Context, tx bun.IDB, p auth.Principal, slug string) (ProfileFacts, error) {
	return readProfile(ctx, tx, p, slug, true)
}

func readProfile(ctx context.Context, db bun.IDB, p auth.Principal, slug string,
	forUpdate bool,
) (ProfileFacts, error) {
	predicate, args := Readable("p", p)

	role := "null::text"
	subject, subjectArgs, matchable := subjectPredicate("m", p)
	if matchable {
		role = "(select min(m.role)::text from membership as m where m.profile_id = p.id and " + subject + ")"
	}

	// The role subquery precedes the WHERE clause, so its arguments come first.
	query := fmt.Sprintf(profileFactsSQL, role, predicate)
	if forUpdate {
		query += " for update of p"
	}
	queryArgs := append(append([]any{}, subjectArgs...), slug)
	queryArgs = append(queryArgs, args...)

	var (
		facts    ProfileFacts
		roleText sql.NullString
	)
	err := db.QueryRowContext(ctx, query, queryArgs...).Scan(
		&facts.ID, &facts.Slug, &facts.Name, &facts.Description, &facts.OwnerTeam,
		&facts.Visibility, &facts.DefaultPolicy, &facts.ForkedFrom, &roleText, &facts.HeadRevision)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ProfileFacts{}, ErrNotFound
	case err != nil:
		return ProfileFacts{}, fmt.Errorf("read profile %s: %w", slug, err)
	}
	facts.Role = models.MembershipRole(roleText.String)
	return facts, nil
}

// ResolveProfile loads everything the gate reads and applies it.
func ResolveProfile(ctx context.Context, db bun.IDB, p auth.Principal, slug string) (ProfileResolution, error) {
	facts, err := Profile(ctx, db, p, slug)
	if err != nil {
		return ProfileResolution{}, err
	}
	return ResolveProfileFacts(ctx, db, facts, p)
}

// ResolveProfileFacts resolves an already identified profile. p is who the
// resolution is for: packages p cannot read offer no candidates.
func ResolveProfileFacts(ctx context.Context, db bun.IDB, facts ProfileFacts, p auth.Principal) (ProfileResolution, error) {
	out := ProfileResolution{Profile: facts}

	err := db.QueryRowContext(ctx,
		`select scan_gate::text, require_signed_bundles from org_policy where id = ?`,
		models.OrgPolicySingletonID).Scan(&out.Gate, &out.RequireSignatures)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ProfileResolution{}, ErrNoPolicy
	case err != nil:
		return ProfileResolution{}, fmt.Errorf("read the org scan gate: %w", err)
	}

	if out.Targets, err = profileTargets(ctx, db, facts.ID); err != nil {
		return ProfileResolution{}, err
	}
	if out.entries, err = profileEntries(ctx, db, p, facts.ID); err != nil {
		return ProfileResolution{}, err
	}

	input := resolve.Input{
		Gate:              resolve.Gate(out.Gate),
		RequireSignatures: out.RequireSignatures,
		At:                time.Now().UTC(),
		Entries:           make([]resolve.Entry, 0, len(out.entries)),
	}
	candidates, err := profileCandidates(ctx, db, p, out.entries)
	if err != nil {
		return ProfileResolution{}, err
	}
	for i := range out.entries {
		row := &out.entries[i]
		input.Entries = append(input.Entries, resolve.Entry{
			ID:         row.id,
			Kind:       row.kind,
			Mode:       resolve.Mode(row.mode),
			PinnedID:   row.pinnedID,
			Range:      row.rangeExpr,
			Candidates: candidates[row.packageID],
		})
	}

	if out.Result, err = resolve.Resolve(input); err != nil {
		// Not a 404: the stored rows are a combination the resolver refuses.
		return ProfileResolution{}, fmt.Errorf("resolve profile %s: %w", facts.Slug, err)
	}
	return out, nil
}

// profileEntriesSQL is the profile's ordered entry set. `latest` is the
// catalog's latest version, deliberately not the resolver's pick, so a
// fallback version can't make a package look clean. `position` is not unique,
// hence the tie-break. %s is PackageReadable in the `latest` join, not the
// WHERE clause: a narrowed package still lists, but with no latest version,
// indistinguishable from an unpublished one.
const profileEntriesSQL = `
select
  pkg.id,
  pkg.namespace || '/' || pkg.name,
  pkg.name,
  pkg.kind::text,
  pent.mode::text,
  coalesce(pent.range_expr, ''),
  coalesce(pent.pinned_version_id::text, ''),
  coalesce(pinned.semver, ''),
  coalesce(latest.semver, ''),
  coalesce(latest.verdict::text, '')
from profile_entry as pent
join package as pkg on pkg.id = pent.package_id
left join version as pinned on pinned.id = pent.pinned_version_id
left join version as latest on latest.id = pkg.latest_version_id and latest.visible and %s
where pent.profile_id = ?
order by pent.position, pkg.namespace, pkg.name`

func profileEntries(ctx context.Context, db bun.IDB, p auth.Principal, profileID uuid.UUID) ([]profileEntryRow, error) {
	readable, readableArgs := PackageReadable("pkg", p)
	query := fmt.Sprintf(profileEntriesSQL, readable)
	args := append(append([]any{}, readableArgs...), profileID)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read profile entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []profileEntryRow{}
	for rows.Next() {
		var row profileEntryRow
		if err := rows.Scan(&row.packageID, &row.id, &row.name, &row.kind, &row.mode,
			&row.rangeExpr, &row.pinnedID, &row.pinnedSemver, &row.latestSemver,
			&row.latestVerdict); err != nil {
			return nil, fmt.Errorf("scan a profile entry: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read profile entries: %w", err)
	}
	return out, nil
}

// profileCandidatesSQL is every published version of a profile's packages,
// not just the latest, since `block` falls back to the newest clean one.
// `digest is not null` drops versions whose bytes have not landed. `flag`
// ignores finding state so a rejection still names its rule; `acc` is the
// acceptance that lapses soonest. %s is PackageReadable on the package join:
// an unreadable package offers no candidates, so it reads exactly like one
// with no clean version rather than revealing it exists.
const profileCandidatesSQL = `
select
  ver.package_id,
  ver.id::text,
  ver.semver,
  ver.verdict::text,
  ver.visible and ver.dist_tag <> 'archived',
  ver.digest,
  ver.object_key,
  case when sig.kind = 'cosign-bundle' then coalesce(sig.ref, '') else '' end,
  coalesce(sig.result::text, ''),
  coalesce(sig.signer_issuer, ''),
  coalesce(sig.signer_identity, ''),
  coalesce(pkg.expected_signer_issuer, ''),
  coalesce(pkg.expected_signer_identity, ''),
  coalesce(flag.rule_id, ''),
  coalesce(flag.evidence_path, ''),
  exists (select 1 from finding as open_fnd
           where open_fnd.version_id = ver.id and open_fnd.state = 'open'),
  coalesce(acc.reviewer, ''),
  coalesce(acc.note, ''),
  acc.expires_at
from version as ver
join package as pkg on pkg.id = ver.package_id and %s
left join signature as sig on sig.version_id = ver.id
left join lateral (
  select fnd.rule_id, coalesce(fnd.evidence_path, '') as evidence_path
  from finding as fnd
  where fnd.version_id = ver.id
  order by fnd.severity desc, fnd.created_at, fnd.id
  limit 1
) as flag on true
left join lateral (
  select
    coalesce(nullif(idt.email, ''), idt.subject) as reviewer,
    coalesce(ovr.note, '') as note,
    ovr.expires_at
  from finding as fnd
  join override as ovr on ovr.finding_id = fnd.id
  join identity as idt on idt.id = ovr.reviewer_identity_id
  where fnd.version_id = ver.id and fnd.state = 'approved'
  order by ovr.expires_at nulls last, ovr.finding_id
  limit 1
) as acc on true
where ver.package_id in (?) and ver.digest is not null`

func profileCandidates(ctx context.Context, db bun.IDB, p auth.Principal,
	entries []profileEntryRow,
) (map[uuid.UUID][]resolve.Candidate, error) {
	out := map[uuid.UUID][]resolve.Candidate{}
	if len(entries) == 0 {
		return out, nil
	}

	ids := make([]uuid.UUID, 0, len(entries))
	for i := range entries {
		ids = append(ids, entries[i].packageID)
	}

	readable, readableArgs := PackageReadable("pkg", p)
	query := fmt.Sprintf(profileCandidatesSQL, readable)
	args := append(append([]any{}, readableArgs...), bun.List(ids))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read the versions a profile may resolve to: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			packageID uuid.UUID
			candidate resolve.Candidate
			digest    []byte
			ref       string
			observed  signer.Observed
			expected  signer.Expected
			ruleID    string
			path      string
			hasOpen   bool
			reviewer  string
			note      string
			expires   sql.NullTime
		)
		if err := rows.Scan(&packageID, &candidate.ID, &candidate.Semver, &candidate.Verdict,
			&candidate.Visible, &digest, &candidate.ObjectKey, &ref,
			&observed.Result, &observed.Issuer, &observed.Identity, &expected.Issuer, &expected.Identity,
			&ruleID, &path,
			&hasOpen, &reviewer, &note, &expires); err != nil {
			return nil, fmt.Errorf("scan a candidate version: %w", err)
		}

		candidate.Digest = "sha256:" + hex.EncodeToString(digest)
		// Evaluated against the current expected signer, so changing it
		// re-decides every version.
		if ref != "" {
			candidate.Signature = resolve.NewSignature(ref, signer.Evaluate(observed, expected),
				observed.Issuer, observed.Identity)
		}
		candidate.FlagDetail = flagDetail(ruleID, path)
		// An acceptance permits nothing while any finding is still open.
		if !hasOpen && reviewer != "" {
			candidate.Override = &resolve.Override{Reviewer: reviewer, Note: note}
			if expires.Valid {
				at := expires.Time
				candidate.Override.ExpiresAt = &at
			}
		}
		out[packageID] = append(out[packageID], candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the versions a profile may resolve to: %w", err)
	}
	return out, nil
}

// flagDetail renders a finding as internal/seed does. It is bundle content:
// escape it at render.
func flagDetail(ruleID, path string) string {
	switch {
	case ruleID == "":
		return ""
	case path == "":
		return ruleID
	default:
		return ruleID + " in " + path
	}
}

func profileTargets(ctx context.Context, db bun.IDB, profileID uuid.UUID) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`select target::text from sync_target where profile_id = ? and enabled`, profileID)
	if err != nil {
		return nil, fmt.Errorf("read the profile's sync targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	enabled := []string{}
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, fmt.Errorf("scan a sync target: %w", err)
		}
		enabled = append(enabled, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the profile's sync targets: %w", err)
	}

	// Vocabulary order, so row order never shows up as a change.
	out := make([]string, 0, len(enabled))
	for _, target := range models.EnumTypes()[models.PGSyncTargetKind] {
		if slices.Contains(enabled, target) {
			out = append(out, target)
		}
	}
	return out, nil
}

// ProfileDetail answers the profile screen.
func ProfileDetail(ctx context.Context, db bun.IDB, p auth.Principal,
	slug string,
) (contract.ProfileDetail, error) {
	resolution, err := ResolveProfile(ctx, db, p, slug)
	if err != nil {
		return contract.ProfileDetail{}, err
	}
	facts := resolution.Profile

	out := contract.ProfileDetail{
		Slug:          facts.Slug,
		Name:          facts.Name,
		Description:   facts.Description,
		Visibility:    string(facts.Visibility),
		OwnerTeam:     facts.OwnerTeam,
		DefaultPolicy: string(facts.DefaultPolicy),
		Gate:          string(resolution.Gate),
		HeadRevision:  facts.HeadRevision,
		ForkedFrom:    facts.ForkedFrom,
		Role:          string(facts.Role),
		Permissions: contract.ProfilePermissions{
			Curate:  facts.Role.MayCurate(),
			Share:   facts.Role.MayShare(),
			Publish: facts.Role.MayPublish(),
			Delete:  facts.Role.MayDelete(),
		},
		Entries: entriesOf(resolution),
		Targets: targetsOf(resolution.Targets),
	}
	if out.Members, err = profileMembers(ctx, db, facts.ID); err != nil {
		return contract.ProfileDetail{}, err
	}
	if out.Revisions, err = profileRevisions(ctx, db, facts.ID); err != nil {
		return contract.ProfileDetail{}, err
	}

	head, err := headLockfile(ctx, db, facts.ID)
	if err != nil {
		return contract.ProfileDetail{}, err
	}
	out.UnpublishedChanges = markUnpublished(out.Entries, resolution.Targets, head,
		facts.HeadRevision > 0)
	return out, nil
}

func entriesOf(resolution ProfileResolution) []contract.ProfileEntry {
	out := make([]contract.ProfileEntry, 0, len(resolution.entries))
	for i := range resolution.entries {
		row := &resolution.entries[i]
		resolved := resolution.Result.Entries[i]
		entry := contract.ProfileEntry{
			ID:            row.id,
			Name:          row.name,
			Kind:          row.kind,
			Mode:          string(row.mode),
			Range:         row.rangeExpr,
			PinnedVersion: row.pinnedSemver,
			LatestVersion: row.latestSemver,
			LatestVerdict: row.latestVerdict,
			Outcome:       string(resolved.Outcome),
			Note:          resolved.Note,
			Override:      contract.OverrideFrom(resolved.Override),
		}
		if resolved.Version != nil {
			entry.Version = resolved.Version.Semver
			entry.Verdict = string(resolved.Version.Verdict)
			entry.Digest = resolved.Version.Digest
		}
		if resolved.Skip != nil {
			skip := contract.SkipFrom(*resolved.Skip)
			entry.Skip = &skip
		}
		out = append(out, entry)
	}
	return out
}

func targetsOf(enabled []string) []contract.ProfileTarget {
	vocabulary := models.EnumTypes()[models.PGSyncTargetKind]
	out := make([]contract.ProfileTarget, 0, len(vocabulary))
	for _, target := range vocabulary {
		out = append(out, contract.ProfileTarget{
			Target: target, Enabled: slices.Contains(enabled, target),
		})
	}
	return out
}

// profileMembersSQL is the sharing panel, most privileged first by enum
// order. The identity lateral only supplies a display name; a membership
// may match by email or subject, hence the limit.
const profileMembersSQL = `
select mem.subject_kind::text, mem.subject_ref, mem.role::text, coalesce(who.display_name, '')
from membership as mem
left join lateral (
  select idt.display_name
  from identity as idt
  where mem.subject_kind = 'user' and (idt.email = mem.subject_ref or idt.subject = mem.subject_ref)
  order by (idt.email = mem.subject_ref) desc, idt.created_at
  limit 1
) as who on true
where mem.profile_id = ?
order by mem.role, mem.subject_kind, mem.subject_ref`

func profileMembers(ctx context.Context, db bun.IDB,
	profileID uuid.UUID,
) ([]contract.ProfileMember, error) {
	rows, err := db.QueryContext(ctx, profileMembersSQL, profileID)
	if err != nil {
		return nil, fmt.Errorf("read the profile's members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []contract.ProfileMember{}
	for rows.Next() {
		var member contract.ProfileMember
		if err := rows.Scan(&member.Kind, &member.Ref, &member.Role, &member.DisplayName); err != nil {
			return nil, fmt.Errorf("scan a member: %w", err)
		}
		out = append(out, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the profile's members: %w", err)
	}
	return out, nil
}

func profileRevisions(ctx context.Context, db bun.IDB,
	profileID uuid.UUID,
) ([]contract.ProfileRevision, error) {
	rows, err := db.QueryContext(ctx,
		`select seq, coalesce(note, ''), created_at, created_by
		   from revision where profile_id = ? order by seq desc`, profileID)
	if err != nil {
		return nil, fmt.Errorf("read the profile's revisions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []contract.ProfileRevision{}
	for rows.Next() {
		var revision contract.ProfileRevision
		if err := rows.Scan(&revision.Revision, &revision.Note, &revision.PublishedAt,
			&revision.PublishedBy); err != nil {
			return nil, fmt.Errorf("scan a revision: %w", err)
		}
		out = append(out, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the profile's revisions: %w", err)
	}
	return out, nil
}

func headLockfile(ctx context.Context, db bun.IDB, profileID uuid.UUID) (contract.Lockfile, error) {
	var raw json.RawMessage
	err := db.QueryRowContext(ctx,
		`select lockfile from revision where profile_id = ? order by seq desc limit 1`,
		profileID).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.Lockfile{}, nil
	case err != nil:
		return contract.Lockfile{}, fmt.Errorf("read the head revision's lockfile: %w", err)
	}

	var head contract.Lockfile
	if err := json.Unmarshal(raw, &head); err != nil {
		return contract.Lockfile{}, fmt.Errorf("decode the head revision's lockfile: %w", err)
	}
	return head, nil
}

// markUnpublished sets each row's Unpublished flag and reports whether the
// profile has anything to publish. It compares only what reaches a machine,
// not skip detail text, so a reworded finding doesn't mark profiles edited.
func markUnpublished(entries []contract.ProfileEntry, targets []string,
	head contract.Lockfile, published bool,
) bool {
	if !published {
		for i := range entries {
			entries[i].Unpublished = true
		}
		return true
	}

	frozen := make(map[string]contract.LockfileEntry, len(head.Entries))
	for i := range head.Entries {
		frozen[head.Entries[i].ID] = head.Entries[i]
	}
	skipped := make(map[string]contract.LockfileSkip, len(head.Skipped))
	for _, skip := range head.Skipped {
		skipped[skip.ID] = skip
	}

	changed := !slices.Equal(targets, head.Targets)
	seen := 0
	for i := range entries {
		entry := &entries[i]
		if entry.Skip != nil {
			was, ok := skipped[entry.ID]
			entry.Unpublished = !ok || was.Reason != entry.Skip.Reason ||
				was.WouldHaveResolvedTo != entry.Skip.WouldHaveResolvedTo
		} else {
			was, ok := frozen[entry.ID]
			entry.Unpublished = !ok || was.Version != entry.Version ||
				was.Resolution != entry.Mode || was.Verdict != entry.Verdict ||
				(was.Override == nil) != (entry.Override == nil)
		}
		changed = changed || entry.Unpublished
		seen++
	}
	// Catches entries removed since the head revision.
	return changed || seen != len(head.Entries)+len(head.Skipped)
}
