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
	"agent-manager/internal/store/models"
)

// The profile detail read (003 T078, 001 US5).
//
// THE GATE IS NOT IN THIS FILE. Every statement below loads facts — entries,
// versions, verdicts, findings, acceptances, memberships — and
// internal/domain/resolve decides what they mean. T078 states the rule and the
// reason: two implementations of the gate is how the screen and the CLI start
// disagreeing about what is installed, and a `case when verdict = 'flagged'` in
// SQL here would be the second one.
//
// Every statement runs on a bun.IDB and none of them is concurrent, unlike
// Package's four goroutines. That is deliberate: PublishRevision resolves inside
// its own transaction, a bun.Tx is one connection, and a resolution that could
// only run on a pool would force the publish to read the profile outside the
// transaction it then writes — which is how a revision comes to freeze a
// resolution nobody ever saw.

// ProfileFacts is the profile row and the caller's standing on it.
type ProfileFacts struct {
	ID            uuid.UUID
	Slug          string
	Name          string
	Description   string
	OwnerTeam     string
	Visibility    models.ProfileVisibility
	DefaultPolicy models.VersionPolicy
	// ForkedFrom is the upstream's slug, empty when this profile is not a fork.
	// It is lineage: nothing reads it to decide what a fork resolves to (FR-038).
	ForkedFrom string
	// Role is the caller's membership role, empty when they hold none — which is
	// the ordinary case for a profile everybody may read.
	Role models.MembershipRole
	// HeadRevision is 0 when nothing has been published yet.
	HeadRevision int
}

// ProfileResolution is one profile resolved under the organisation's gate: the
// facts, the resolver's answer, and enough catalog detail per entry for a screen
// to draw the row.
//
// Both the detail screen and the publish command build from this, which is the
// point. A revision must freeze exactly the resolution the screen displayed
// (003 US5 scenario 3), and the only way to be sure of that is for there to be
// one function that produces it.
type ProfileResolution struct {
	Profile ProfileFacts
	Gate    models.ScanGate
	// RequireSignatures is org_policy.require_signed_bundles, passed through to
	// the resolver rather than evaluated here (FR-047, FR-048).
	RequireSignatures bool
	// Targets are the enabled sync targets in the vocabulary's own order. FR-039:
	// advisory to a client, never read by anything here.
	Targets []string
	Result  resolve.Result

	// entries carries the per-row catalog facts the resolver does not deal in —
	// the package's display name, and the newest version the catalog offers. It is
	// index-aligned with Result.Entries, which Resolve guarantees by returning one
	// resolution per input entry in input order.
	entries []profileEntryRow
}

// profileEntryRow is one `profile_entry` and the catalog facts about it.
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

// Lockfile assembles the document a revision would publish from this resolution.
// The mapping itself lives in internal/api/contract beside the frozen types.
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

// ErrNoPolicy is returned when `org_policy` holds no singleton row.
//
// It is an error and not a default. The gate decides what a machine is allowed to
// install, and the only defaults available are "let everything through", which is
// a bypass, and "block everything", which is an outage dressed as safety. A
// deployment whose policy row is missing is broken and should say so.
var ErrNoPolicy = errors.New("org_policy holds no row, so there is no scan gate to resolve under")

// profileFactsSQL identifies the profile and the caller's standing on it in one
// statement. %s is the FR-044 predicate; %s is the caller's role, which is a
// scalar subquery over the same membership rows the predicate tests.
//
// `min(role)` is the most privileged role the caller holds, and it is min rather
// than max because `membership_role` is declared owner, maintainer, reviewer,
// consumer — privilege first — so the enum's own ordering is the precedence.
// Somebody holding a direct owner membership AND sitting in a group with
// consumer holds the union of the two, which for a single-role answer is the
// stronger of them. That is the same reading auth.HighestRole applies to org
// roles.
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

// Profile reads one profile row under the FR-044 predicate.
//
// An unreadable profile is indistinguishable from a missing one — queries.go's
// ErrNotFound comment says why, and it applies with more force here than on the
// list: a 403 on this path would confirm that a private profile with this exact
// slug exists, which is the enumeration FR-044 forbids.
func Profile(ctx context.Context, db bun.IDB, p auth.Principal, slug string) (ProfileFacts, error) {
	return readProfile(ctx, db, p, slug, false)
}

// LockProfile is the same read with the profile row locked until the caller's
// transaction ends. Every command that changes a profile takes it, so the role
// check, the invariant it then enforces and the write all decide against one
// state.
//
// `for update of p` and not a bare `for update`: the statement outer-joins the
// upstream a fork was made from, and Postgres refuses a row lock on the nullable
// side of an outer join.
//
// It does NOT make the head revision number it returns safe to allocate from.
// The lock serialises two publishes, but under READ COMMITTED the snapshot this
// statement reads was taken before it blocked, so the max(seq) beside the lock
// can be one behind a publish that committed while it waited. Whoever allocates
// a sequence re-reads it in a statement of its own, after the lock is held —
// see commands.PublishRevision.
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

	// The role subquery is rendered before the WHERE clause, so its arguments
	// come first.
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

// ResolveProfile loads everything the gate reads and applies it (T078).
func ResolveProfile(ctx context.Context, db bun.IDB, p auth.Principal, slug string) (ProfileResolution, error) {
	facts, err := Profile(ctx, db, p, slug)
	if err != nil {
		return ProfileResolution{}, err
	}
	return ResolveProfileFacts(ctx, db, facts)
}

// ResolveProfileFacts is the half a caller that has already identified the
// profile — and already checked what the caller may do to it — runs. The publish
// command holds the profile row under a lock before it resolves, so re-reading it
// through the readability predicate would be a second, weaker answer.
func ResolveProfileFacts(ctx context.Context, db bun.IDB, facts ProfileFacts) (ProfileResolution, error) {
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
	if out.entries, err = profileEntries(ctx, db, facts.ID); err != nil {
		return ProfileResolution{}, err
	}

	input := resolve.Input{
		Gate:              resolve.Gate(out.Gate),
		RequireSignatures: out.RequireSignatures,
		At:                time.Now().UTC(),
		Entries:           make([]resolve.Entry, 0, len(out.entries)),
	}
	candidates, err := profileCandidates(ctx, db, out.entries)
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
		// Not a client error and not a 404: the stored rows are a combination the
		// resolver refuses, which is corruption or a range expression that was
		// accepted by an older validator. Naming the profile is what makes it
		// findable.
		return ProfileResolution{}, fmt.Errorf("resolve profile %s: %w", facts.Slug, err)
	}
	return out, nil
}

// profileEntriesSQL is the ordered set FR-032 describes, with the catalog facts
// the row renders.
//
// `latest` joins through `package.latest_version_id`, which is the same relation
// the catalog and the scanner summary read: the screen's Scan badge then says
// what the catalog says about this package, whatever the gate afterwards decides
// to resolve. The join is deliberately NOT the newest candidate the resolver
// picked from — those are two different questions, and answering both from one
// value is how a row ends up claiming a package is clean because the version it
// fell back to is.
//
// The order-by carries a tie-break because `position` has no unique constraint:
// two entries at the same position must still come out in the same order twice.
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
left join version as latest on latest.id = pkg.latest_version_id and latest.visible
where pent.profile_id = ?
order by pent.position, pkg.namespace, pkg.name`

func profileEntries(ctx context.Context, db bun.IDB, profileID uuid.UUID) ([]profileEntryRow, error) {
	rows, err := db.QueryContext(ctx, profileEntriesSQL, profileID)
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

// profileCandidatesSQL is EVERY published version of the packages a profile
// holds, with the three facts the gate reads about each one: its verdict, how its
// flag reads to a human, and whether a reviewer has accepted every finding on it.
//
// It is every version and not the latest, because that is the resolver's
// contract: `block` falls back to the most recent CLEAN version, and a query that
// handed over only the latest row would produce a plausible, wrong answer with no
// error anywhere.
//
// `digest is not null` drops a version whose bytes have not landed. The schema's
// `check (digest is not null or verdict = 'scanning')` makes that exactly the
// set that has never been published, and a pin at one must be `pin-target-missing`
// rather than a resolution to a bundle the object store does not hold.
//
// The two laterals answer two different questions and are not one query:
//
//   - `flag` is how this version's problem READS — the most severe finding on it,
//     rendered the same way internal/seed renders it, "SH-NET-002 in
//     postinstall.sh". It ignores the finding's state because a rejected version's
//     exclusion should still name the rule that rejected it.
//   - `acc` is the acceptance the gate reads, and it is the one that lapses
//     SOONEST. A version carrying two accepted findings stops being accepted when
//     the first acceptance does, so min is the only correct choice — and the
//     reviewer named beside it is the one whose decision needs renewing. A null
//     expiry sorts last because an acceptance with no expiry never lapses.
//
// `has_open` is the other half of that: an acceptance means nothing while any
// finding on the version is still open, so the caller passes no override at all
// in that case. The two together are what makes "unapproved flagged version"
// (FR-035) a property of the version rather than of one finding on it.
const profileCandidatesSQL = `
select
  ver.package_id,
  ver.id::text,
  ver.semver,
  ver.verdict::text,
  ver.visible and ver.dist_tag <> 'archived',
  ver.digest,
  ver.object_key,
  coalesce(sig.ref, ''),
  coalesce(flag.rule_id, ''),
  coalesce(flag.evidence_path, ''),
  exists (select 1 from finding as open_fnd
           where open_fnd.version_id = ver.id and open_fnd.state = 'open'),
  coalesce(acc.reviewer, ''),
  coalesce(acc.note, ''),
  acc.expires_at
from version as ver
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

func profileCandidates(ctx context.Context, db bun.IDB,
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

	rows, err := db.QueryContext(ctx, profileCandidatesSQL, bun.List(ids))
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
			ruleID    string
			path      string
			hasOpen   bool
			reviewer  string
			note      string
			expires   sql.NullTime
		)
		if err := rows.Scan(&packageID, &candidate.ID, &candidate.Semver, &candidate.Verdict,
			&candidate.Visible, &digest, &candidate.ObjectKey, &ref, &ruleID, &path,
			&hasOpen, &reviewer, &note, &expires); err != nil {
			return nil, fmt.Errorf("scan a candidate version: %w", err)
		}

		candidate.Digest = "sha256:" + hex.EncodeToString(digest)
		if ref != "" {
			candidate.Signature = &resolve.Signature{Ref: ref}
		}
		candidate.FlagDetail = flagDetail(ruleID, path)
		// An acceptance permits nothing while a finding on the same version is
		// still open: FR-035's `approval` gate asks whether the VERSION has been
		// approved, and one signed-off finding beside an unexamined one has not
		// answered that.
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

// flagDetail renders a finding the way internal/seed renders it, so a lockfile
// published here and one the representative dataset seeded read the same. It is
// bundle content: escape it at render (FR-055).
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

	// The vocabulary's order and not the rows' order: a lockfile is compared
	// against the previous one to decide whether anything is unpublished, and two
	// documents differing only in the order Postgres happened to return two rows
	// would report a change nobody made.
	out := make([]string, 0, len(enabled))
	for _, target := range models.EnumTypes()[models.PGSyncTargetKind] {
		if slices.Contains(enabled, target) {
			out = append(out, target)
		}
	}
	return out, nil
}

// ProfileDetail answers the profile screen (T078).
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

// entriesOf turns the resolution into the screen's rows. It reads the resolver's
// answer and re-decides nothing: Outcome, Note and Skip are carried across
// verbatim.
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

// profileMembersSQL is the sharing panel (FR-037).
//
// `order by mem.role` is the enum's order — owner, maintainer, reviewer,
// consumer — so the panel lists the most privileged first without the screen
// holding a copy of the precedence.
//
// The identity join is a lateral with a limit because a membership names an
// email OR a subject and two different identity rows could match one of each. It
// is a display name and nothing else: a membership row is authoritative on its
// own, and a person who has never signed in has no row here and simply shows as
// their address.
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
// profile as a whole has anything to publish (001 US5 scenario 1).
//
// What it compares is what would actually REACH A MACHINE: the resolved version,
// the mode it resolved under, its verdict, whether an override let it through,
// which entries are excluded and why, and the target list. It deliberately does
// not compare the gate: a lockfile records the gate for explanation, and an
// organisation flipping the gate without changing what any profile resolves to
// has not left anybody with an unpublished change to make.
//
// It also does not compare a skip's DETAIL. That text is the rule pack's, and a
// rescan that rewords a finding would otherwise mark every affected profile as
// edited by nobody.
func markUnpublished(entries []contract.ProfileEntry, targets []string,
	head contract.Lockfile, published bool,
) bool {
	if !published {
		// Nothing has been published, so everything is unpublished — including a
		// profile with no entries at all, which still has a revision to make.
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
	// An id the head revision holds and the draft does not. Unreachable while
	// `am_api` holds no DELETE on profile_entry, and checked anyway: the day that
	// grant widens, a removal that published nothing would be the silent half.
	return changed || seen != len(head.Entries)+len(head.Skipped)
}
