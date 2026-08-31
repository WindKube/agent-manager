package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/domain/resolve"
	"agent-manager/internal/store/models"
)

// The profile write path (003 T079-T083, 001 US5).
//
// Five commands, one transaction each, one audit row each. They share a shape
// worth stating once:
//
//  1. the profile is read under the FR-044 predicate AND under a row lock
//     (queries.LockProfile), so an unreadable profile is a not-found and the
//     role check, the invariant and the write all decide against one state;
//  2. the caller's MEMBERSHIP role decides what they may do — not their
//     organisation role. A catalog admin who is not a member of a private
//     profile cannot read it at all, so letting one publish an organisation-
//     visible profile they hold no membership on would be an authorisation model
//     with two answers. The one exception is creating a profile, which has no
//     membership to consult and is gated on the organisation role by the
//     operation;
//  3. nothing is DELETED. `am_api` holds no DELETE on profile_entry, membership
//     or revision, and each absence is argued in data-model.md's withheld-grant
//     list. Every command below is therefore an insert or an update, and where a
//     caller might expect a removal it is refused and named rather than silently
//     ignored.
//
// What is deliberately absent: any mechanism by which a fork could learn about
// the upstream's later revisions (FR-038). ForkOf copies entries once and writes
// `forked_from_id` as lineage; no read anywhere follows that column the other
// way, and PublishRevision writes exactly one revision for exactly one profile.

// ErrProfileExists is returned when the slug is taken. FR-032 gives a profile a
// slug that is unique across the organisation and it is the URL, so this is a
// conflict rather than a validation failure.
var ErrProfileExists = errors.New("a profile with this slug already exists")

// ErrProfileRefused is a request the caller could fix — an unknown package, a
// pin at a version this hub does not hold, a range that is not a constraint, a
// body that would leave the profile with no owner.
var ErrProfileRefused = errors.New("the profile change was refused")

// uniqueProfileSlugConstraint is the index behind the slug's uniqueness.
// Postgres reports the constraint and not the requirement, and a bare "duplicate
// key" tells a person creating a profile nothing about why it was refused.
const uniqueProfileSlugConstraint = "profile_slug_key"

// NotPermittedError is a refusal by MEMBERSHIP role, and it names what the
// action needed.
//
// A typed error rather than a sentinel because the 403 body has to carry all
// three parts. api.requireRole's comment makes the argument for naming them: a
// refusal that says only "forbidden" leaves a person unable to tell "I am not a
// member of this profile" from "I am the wrong kind of member", and those have
// different remedies.
type NotPermittedError struct {
	// Action reads as a verb phrase: "publish a revision of".
	Action string
	// Needs names the roles that would have worked.
	Needs string
	Held  models.MembershipRole
}

func (e *NotPermittedError) Error() string {
	held := "holds no role on it"
	if e.Held != "" {
		held = "holds " + string(e.Held)
	}
	return "this identity may not " + e.Action + " this profile: that needs " + e.Needs +
		", and this identity " + held
}

func notPermitted(action, needs string, held models.MembershipRole) error {
	return &NotPermittedError{Action: action, Needs: needs, Held: held}
}

// refused wraps a caller-fixable refusal so the operation can answer 422 with the
// sentence rather than with a status alone.
func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProfileRefused, fmt.Sprintf(format, args...))
}

// ProfileCreation is one create request, reduced to what the command needs.
type ProfileCreation struct {
	Slug          string
	Name          string
	Description   string
	OwnerTeam     string
	Visibility    models.ProfileVisibility
	DefaultPolicy models.VersionPolicy
	// ForkOf is the slug of the profile whose entries are copied, empty for a
	// profile built from nothing.
	ForkOf string
}

func (c ProfileCreation) normalise() ProfileCreation {
	c.Slug = strings.TrimSpace(c.Slug)
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	c.OwnerTeam = strings.TrimSpace(c.OwnerTeam)
	c.ForkOf = strings.TrimSpace(c.ForkOf)
	if c.Visibility == "" {
		// Private, not organisation. A profile nobody chose to publish is not
		// readable by the whole organisation, and defaulting the other way round
		// means a mistake is visible to everyone before anybody notices (FR-037).
		c.Visibility = models.ProfileVisibilityPrivate
	}
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = models.VersionPolicyFloatingLatest
	}
	return c
}

// CreateProfile creates a profile and makes its creator the owner (T079).
//
// The owner membership is not a courtesy. Authorisation on every other command
// here is the caller's MEMBERSHIP role, so a profile created without one would
// be readable and permanently uneditable — by its author most of all — and there
// is no DELETE on `membership` with which to repair that afterwards.
func CreateProfile(ctx context.Context, db bun.IDB, p auth.Principal,
	in ProfileCreation,
) (contract.Profile, error) {
	in = in.normalise()
	if !in.Visibility.Valid() {
		return contract.Profile{}, refused("%q is not a profile visibility", in.Visibility)
	}
	if !in.DefaultPolicy.Valid() {
		return contract.Profile{}, refused("%q is not a version policy", in.DefaultPolicy)
	}
	if in.Name == "" {
		return contract.Profile{}, refused("a profile needs a name")
	}
	// The slug becomes an object-store prefix the moment a revision is published,
	// so it is validated by the same function that will build that key rather
	// than by a second pattern that could be looser.
	if _, err := blob.ProfileRevisionKey(in.Slug, 1); err != nil {
		return contract.Profile{}, refused("%s", err.Error())
	}

	owner := memberRef(p)
	if owner == "" {
		return contract.Profile{}, refused(
			"this identity carries neither an email nor a subject, so nothing can be recorded as the owner")
	}

	profile := &models.Profile{
		ID:            models.NewID(),
		Slug:          in.Slug,
		Name:          in.Name,
		Description:   in.Description,
		Visibility:    in.Visibility,
		OwnerTeam:     in.OwnerTeam,
		DefaultPolicy: in.DefaultPolicy,
	}

	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		forked := ""
		if in.ForkOf != "" {
			// Under the readability predicate: forking a profile is a way of reading
			// it, so a profile FR-044 hides must not be forkable either.
			upstream, txErr := queries.Profile(ctx, tx, p, in.ForkOf)
			if txErr != nil {
				return txErr
			}
			profile.ForkedFromID = &upstream.ID
			forked = upstream.Slug
		}

		if _, txErr := tx.NewInsert().Model(profile).Exec(ctx); txErr != nil {
			var pgErr *pgconn.PgError
			if errors.As(txErr, &pgErr) && pgErr.Code == "23505" &&
				strings.Contains(pgErr.ConstraintName, uniqueProfileSlugConstraint) {
				return ErrProfileExists
			}
			return fmt.Errorf("create profile %s: %w", in.Slug, txErr)
		}

		if _, txErr := tx.NewInsert().Model(&models.Membership{
			ProfileID:   profile.ID,
			SubjectKind: models.SubjectKindUser,
			SubjectRef:  owner,
			Role:        models.MembershipRoleOwner,
		}).Exec(ctx); txErr != nil {
			return fmt.Errorf("record %s as the owner of %s: %w", owner, in.Slug, txErr)
		}

		copied := 0
		if profile.ForkedFromID != nil {
			var txErr error
			// The upstream's CURRENT entries, copied once. This is the whole of what
			// a fork inherits (FR-038): the entries as they stand at this instant,
			// and never a revision the upstream publishes afterwards. There is no
			// row, column or statement anywhere that would carry one across.
			if copied, txErr = copyEntries(ctx, tx, *profile.ForkedFromID, profile.ID); txErr != nil {
				return txErr
			}
		}

		text := fmt.Sprintf("created profile %s (%s)", in.Slug, in.Visibility)
		if forked != "" {
			text = fmt.Sprintf("forked %s from %s with %s, which inherits no later revision of it",
				in.Slug, forked, counted(copied, "package", "packages"))
		}
		return writeProfileAudit(ctx, tx, p, models.AuditKindProfile, text)
	})
	if err != nil {
		return contract.Profile{}, err
	}

	return contract.Profile{
		Slug:       profile.Slug,
		Name:       profile.Name,
		Visibility: string(profile.Visibility),
	}, nil
}

// copyEntries duplicates one profile's entries onto another, preserving order and
// each entry's mode, pin and range.
func copyEntries(ctx context.Context, tx bun.IDB, from, to uuid.UUID) (int, error) {
	res, err := tx.ExecContext(ctx, `
insert into profile_entry (profile_id, package_id, mode, pinned_version_id, range_expr, position)
select ?, package_id, mode, pinned_version_id, range_expr, position
from profile_entry where profile_id = ?`, to, from)
	if err != nil {
		return 0, fmt.Errorf("copy the entries of the profile being forked: %w", err)
	}
	copied, _ := res.RowsAffected()
	return int(copied), nil
}

// SetProfileEntries replaces the profile's ordered set of packages (T080).
//
// 001 US5 scenario 1: the change is NOT durable until a revision is published.
// That is exactly what this writes — `profile_entry` is the draft, the head
// revision's lockfile is what machines have, and nothing here touches the
// second. The profile detail reports the difference per row so a screen can say
// which change is still unpublished.
func SetProfileEntries(ctx context.Context, db bun.IDB, p auth.Principal,
	slug string, in contract.ProfileEntries,
) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, err := queries.LockProfile(ctx, tx, p, slug)
		if err != nil {
			return err
		}
		if !facts.Role.MayCurate() {
			return notPermitted("change the packages in", "owner or maintainer", facts.Role)
		}

		rows, changed, err := entryRowsFor(ctx, tx, facts.ID, slug, in.Entries)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			if _, err := tx.NewInsert().Model(&rows).
				On("conflict (profile_id, package_id) do update").
				Set("mode = excluded.mode").
				Set("pinned_version_id = excluded.pinned_version_id").
				Set("range_expr = excluded.range_expr").
				Set("position = excluded.position").
				Set("updated_at = now()").
				Exec(ctx); err != nil {
				return fmt.Errorf("write the entries of %s: %w", slug, err)
			}
		}

		return writeProfileAudit(ctx, tx, p, models.AuditKindProfile, fmt.Sprintf(
			"set the packages in %s: %s, %d changed", slug,
			counted(len(rows), "entry", "entries"), changed))
	})
}

// entryRowsFor turns the request into rows, refusing everything the database
// would otherwise refuse less legibly — and one thing it would not refuse at all.
//
// That one thing is an entry the profile HOLDS and the body does not name. There
// is no DELETE on `profile_entry` (data-model.md: removal is unspecified and no
// screen carries the control), so keeping it silently would answer 200 to a
// request whose stored result disagrees with what was sent. Naming it is the only
// honest option until that grant is widened deliberately.
func entryRowsFor(ctx context.Context, tx bun.IDB, profileID uuid.UUID, slug string,
	settings []contract.ProfileEntrySetting,
) ([]models.ProfileEntry, int, error) {
	held, err := heldEntries(ctx, tx, profileID)
	if err != nil {
		return nil, 0, err
	}

	rows := make([]models.ProfileEntry, 0, len(settings))
	named := make(map[string]bool, len(settings))
	changed := 0

	for position, setting := range settings {
		id := strings.TrimSpace(setting.ID)
		if named[id] {
			return nil, 0, refused("%s is named twice, so its position is undefined", id)
		}
		named[id] = true

		namespace, name, ok := strings.Cut(id, "/")
		if !ok || namespace == "" || name == "" {
			return nil, 0, refused("%q is not a package id: it is namespace/name", setting.ID)
		}
		mode := models.EntryMode(setting.Mode)
		if !mode.Valid() {
			return nil, 0, refused("%q is not latest, pinned or range", setting.Mode)
		}

		row := models.ProfileEntry{
			ProfileID: profileID,
			Mode:      mode,
			Position:  int32(position),
		}
		if row.PackageID, err = packageID(ctx, tx, namespace, name); err != nil {
			return nil, 0, err
		}

		version := strings.TrimSpace(setting.Version)
		switch mode {
		case models.EntryModePinned:
			pinned, pinErr := versionID(ctx, tx, row.PackageID, id, version)
			if pinErr != nil {
				return nil, 0, pinErr
			}
			row.PinnedVersionID = &pinned
		case models.EntryModeRange:
			if rangeErr := resolve.ValidRange(version); rangeErr != nil {
				return nil, 0, refused("%s: %s", id, rangeErr.Error())
			}
			row.RangeExpr = version
		case models.EntryModeLatest:
			// Neither a pin nor a range. Said explicitly because the upsert writes
			// both columns on every row: an entry moved from pinned to latest has to
			// have its pin cleared, and "unpin" is that update (data-model.md).
		}

		was, existed := held[row.PackageID]
		if !existed || was.differs(row) {
			changed++
		}
		delete(held, row.PackageID)
		rows = append(rows, row)
	}

	if len(held) > 0 {
		missing := make([]string, 0, len(held))
		for _, entry := range held {
			missing = append(missing, entry.id)
		}
		slices.Sort(missing)
		return nil, 0, refused(
			"%s holds %s that this request does not name (%s), and removing a package from a "+
				"profile is not an operation this hub has: send the whole set",
			slug, counted(len(missing), "package", "packages"), strings.Join(missing, ", "))
	}
	return rows, changed, nil
}

// heldEntry is one entry as it stands, for the comparison that counts changes.
type heldEntry struct {
	id        string
	mode      models.EntryMode
	pinnedID  *uuid.UUID
	rangeExpr string
	position  int32
}

func (h heldEntry) differs(row models.ProfileEntry) bool {
	switch {
	case h.mode != row.Mode, h.rangeExpr != row.RangeExpr, h.position != row.Position:
		return true
	case h.pinnedID == nil || row.PinnedVersionID == nil:
		return (h.pinnedID == nil) != (row.PinnedVersionID == nil)
	default:
		return *h.pinnedID != *row.PinnedVersionID
	}
}

func heldEntries(ctx context.Context, tx bun.IDB,
	profileID uuid.UUID,
) (map[uuid.UUID]heldEntry, error) {
	rows, err := tx.QueryContext(ctx, `
select pent.package_id, pkg.namespace || '/' || pkg.name, pent.mode::text,
       pent.pinned_version_id, coalesce(pent.range_expr, ''), pent.position
from profile_entry as pent
join package as pkg on pkg.id = pent.package_id
where pent.profile_id = ?`, profileID)
	if err != nil {
		return nil, fmt.Errorf("read the entries a profile already holds: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[uuid.UUID]heldEntry{}
	for rows.Next() {
		var (
			id    uuid.UUID
			entry heldEntry
		)
		if err := rows.Scan(&id, &entry.id, &entry.mode, &entry.pinnedID, &entry.rangeExpr,
			&entry.position); err != nil {
			return nil, fmt.Errorf("scan an entry a profile already holds: %w", err)
		}
		out[id] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the entries a profile already holds: %w", err)
	}
	return out, nil
}

func packageID(ctx context.Context, tx bun.IDB, namespace, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx,
		`select id from package where namespace = ? and name = ?`, namespace, name).Scan(&id)
	if err != nil {
		return uuid.Nil, refused("no package %s/%s is registered here", namespace, name)
	}
	return id, nil
}

// versionID resolves a pin. `visible` is deliberately not required: withdrawing a
// version from the catalog is not the same as withdrawing it from the profiles
// that already chose it, which is the same reading resolve.Candidate.Visible
// carries. `digest is not null` is required, because a version whose bytes never
// landed cannot be installed and pinning to one would produce a lockfile naming
// an object the store does not hold.
func versionID(ctx context.Context, tx bun.IDB, pkg uuid.UUID, id, semver string) (uuid.UUID, error) {
	if semver == "" {
		return uuid.Nil, refused("%s is pinned, so it needs the version to pin to", id)
	}
	var version uuid.UUID
	err := tx.QueryRowContext(ctx,
		`select id from version where package_id = ? and semver = ? and digest is not null`,
		pkg, semver).Scan(&version)
	if err != nil {
		return uuid.Nil, refused("this hub holds no published %s@%s to pin to", id, semver)
	}
	return version, nil
}

// SetProfileSharing sets the role each named subject holds (T081, FR-037).
//
// An UPSERT and not a replacement: a subject the body does not name keeps its
// role, because `am_api` holds no DELETE on `membership` and FR-037 is about
// roles rather than about a set that gets emptied. A demotion is an update of
// `role`, which is what data-model.md's withheld-grant list says it is.
func SetProfileSharing(ctx context.Context, db bun.IDB, p auth.Principal,
	slug string, in contract.ProfileSharing,
) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, err := queries.LockProfile(ctx, tx, p, slug)
		if err != nil {
			return err
		}
		if !facts.Role.MayShare() {
			return notPermitted("change who can see", "owner", facts.Role)
		}

		rows, err := membershipRowsFor(ctx, tx, facts.ID, in.Members)
		if err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(&rows).
			On("conflict (profile_id, subject_kind, subject_ref) do update").
			Set("role = excluded.role").
			Set("updated_at = now()").
			Exec(ctx); err != nil {
			return fmt.Errorf("share %s: %w", slug, err)
		}

		return writeProfileAudit(ctx, tx, p, models.AuditKindShare,
			"shared "+slug+" with "+describeShares(in.Members))
	})
}

// membershipRowsFor validates the body and enforces the one invariant sharing
// has: the profile keeps an owner.
//
// It has to, and the reason is the missing DELETE again. Nothing can remove a
// membership, so a body that demoted the last owner would leave a profile whose
// sharing can never be changed again by anybody — the failure is silent, total
// and unrepairable through the API. The check is against the RESULTING set:
// owners the body does not mention still count.
func membershipRowsFor(ctx context.Context, tx bun.IDB, profileID uuid.UUID,
	shares []contract.ProfileShare,
) ([]models.Membership, error) {
	if len(shares) == 0 {
		return nil, refused("a sharing change has to name at least one member")
	}

	rows := make([]models.Membership, 0, len(shares))
	named := make(map[string]bool, len(shares))
	owners := 0

	for _, share := range shares {
		kind := models.SubjectKind(share.Kind)
		role := models.MembershipRole(share.Role)
		ref := strings.TrimSpace(share.Ref)
		switch {
		case !kind.Valid():
			return nil, refused("%q is not user or group", share.Kind)
		case !role.Valid():
			return nil, refused("%q is not owner, maintainer, reviewer or consumer", share.Role)
		case ref == "":
			return nil, refused("a %s membership needs something to name", kind)
		case named[string(kind)+"\x00"+ref]:
			return nil, refused("%s %s is named twice with two roles", kind, ref)
		}
		named[string(kind)+"\x00"+ref] = true
		if role == models.MembershipRoleOwner {
			owners++
		}
		rows = append(rows, models.Membership{
			ProfileID: profileID, SubjectKind: kind, SubjectRef: ref, Role: role,
		})
	}

	if owners == 0 {
		remaining, err := ownersUntouched(ctx, tx, profileID, named)
		if err != nil {
			return nil, err
		}
		if remaining == 0 {
			return nil, refused(
				"this would leave the profile with no owner, and nothing can add one back: " +
					"only an owner may change sharing")
		}
	}
	return rows, nil
}

// ownersUntouched counts the owners this request does not rewrite.
func ownersUntouched(ctx context.Context, tx bun.IDB, profileID uuid.UUID,
	named map[string]bool,
) (int, error) {
	rows, err := tx.QueryContext(ctx,
		`select subject_kind::text, subject_ref from membership
		  where profile_id = ? and role = 'owner'`, profileID)
	if err != nil {
		return 0, fmt.Errorf("count the profile's owners: %w", err)
	}
	defer func() { _ = rows.Close() }()

	remaining := 0
	for rows.Next() {
		var kind, ref string
		if err := rows.Scan(&kind, &ref); err != nil {
			return 0, fmt.Errorf("scan an owner: %w", err)
		}
		if !named[kind+"\x00"+ref] {
			remaining++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("count the profile's owners: %w", err)
	}
	return remaining, nil
}

func describeShares(shares []contract.ProfileShare) string {
	parts := make([]string, 0, len(shares))
	for _, share := range shares {
		parts = append(parts, share.Kind+" "+strings.TrimSpace(share.Ref)+" as "+share.Role)
	}
	return strings.Join(parts, ", ")
}

// SetProfileTargets records which agent directories a client should write (T082,
// FR-039).
//
// It changes nothing about what the server stores or resolves — 001 US5 scenario
// 7 is explicit that a target affects only what a CLIENT writes locally — which
// is why the row it touches is a boolean beside the profile and not anything the
// resolver reads. The lockfile carries the list so a client knows where to put
// what it already resolved.
//
// A replacement rather than an upsert of the named ones, and it can be one with
// no DELETE grant because `enabled` is a column: an omitted target is set false.
func SetProfileTargets(ctx context.Context, db bun.IDB, p auth.Principal,
	slug string, in contract.ProfileTargetSelection,
) error {
	vocabulary := models.EnumTypes()[models.PGSyncTargetKind]
	wanted := make(map[string]bool, len(in.Targets))
	for _, target := range in.Targets {
		if !slices.Contains(vocabulary, target) {
			return refused("%q is not a sync target this hub writes; it knows %s",
				target, strings.Join(vocabulary, " and "))
		}
		wanted[target] = true
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, err := queries.LockProfile(ctx, tx, p, slug)
		if err != nil {
			return err
		}
		if !facts.Role.MayCurate() {
			return notPermitted("change the sync targets of", "owner or maintainer", facts.Role)
		}

		rows := make([]models.SyncTarget, 0, len(vocabulary))
		for _, target := range vocabulary {
			rows = append(rows, models.SyncTarget{
				ProfileID: facts.ID,
				Target:    models.SyncTargetKind(target),
				Enabled:   wanted[target],
			})
		}
		if _, err := tx.NewInsert().Model(&rows).
			On("conflict (profile_id, target) do update").
			Set("enabled = excluded.enabled").
			Set("updated_at = now()").
			Exec(ctx); err != nil {
			return fmt.Errorf("set the sync targets of %s: %w", slug, err)
		}

		enabled := "nothing"
		if len(in.Targets) > 0 {
			ordered := make([]string, 0, len(in.Targets))
			for _, target := range vocabulary {
				if wanted[target] {
					ordered = append(ordered, target)
				}
			}
			enabled = strings.Join(ordered, ", ")
		}
		return writeProfileAudit(ctx, tx, p, models.AuditKindProfile,
			"set the sync targets of "+slug+" to "+enabled)
	})
}

// PublishRevision freezes the current resolution as the next revision (T083,
// FR-033, FR-034).
//
// Three properties, and each is a mechanism rather than a promise:
//
//   - the lockfile comes from internal/domain/resolve, through the same
//     queries.ResolveProfileFacts the detail screen calls, so a revision cannot
//     freeze a resolution the screen never displayed (003 US5 scenario 3);
//   - the sequence is allocated by the server under a row lock on the profile,
//     so a client has no number to name and no number to overwrite;
//   - `unique (profile_id, seq)` refuses a duplicate outright, and `am_api` holds
//     no DELETE or on-conflict path to it. Republishing r14 is refused by the
//     database, not by a branch (principle IV, FR-034).
func PublishRevision(ctx context.Context, db bun.IDB, p auth.Principal,
	slug, note string,
) (contract.Lockfile, error) {
	note = strings.TrimSpace(note)

	var lockfile contract.Lockfile
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, txErr := queries.LockProfile(ctx, tx, p, slug)
		if txErr != nil {
			return txErr
		}
		if !facts.Role.MayPublish() {
			return notPermitted("publish a revision of", "owner or maintainer", facts.Role)
		}

		// A statement of its own, AFTER the lock is held. queries.LockProfile
		// returns a head revision read from the snapshot this transaction's first
		// statement took, which under READ COMMITTED predates a publish that
		// committed while this one waited for the lock; this read takes a fresh
		// snapshot and sees it. Getting that wrong does not corrupt anything — the
		// unique index refuses the second r15 — but it turns a serialised publish
		// into a 500.
		// int32, because `revision.seq` is a Postgres `integer`. Reading it as a Go
		// `int` and narrowing at the insert is the same value and a conversion the
		// compiler cannot prove is safe.
		var head int32
		if txErr = tx.QueryRowContext(ctx,
			`select coalesce(max(seq), 0) from revision where profile_id = ?`,
			facts.ID).Scan(&head); txErr != nil {
			return fmt.Errorf("read the head revision of %s: %w", slug, txErr)
		}
		seq := head + 1
		revision := int(seq)

		resolution, txErr := queries.ResolveProfileFacts(ctx, tx, facts)
		if txErr != nil {
			return txErr
		}
		key, txErr := blob.ProfileRevisionKey(facts.Slug, revision)
		if txErr != nil {
			return fmt.Errorf("name the object key for %s r%d: %w", slug, seq, txErr)
		}

		lockfile = resolution.Lockfile(revision, note, time.Now().UTC())
		encoded, txErr := json.Marshal(lockfile)
		if txErr != nil {
			return fmt.Errorf("encode the lockfile for %s r%d: %w", slug, seq, txErr)
		}

		if _, txErr = tx.NewInsert().Model(&models.Revision{
			ID:        models.NewID(),
			ProfileID: facts.ID,
			Seq:       seq,
			Note:      note,
			Lockfile:  encoded,
			// The key the mirrored copy WOULD live under. This role writes the row
			// and not the object: `api` holds a blob reader and no writer
			// (principle VII), and the lockfile a client reads is served from this
			// column by GET /v1/profiles/{slug}/revisions/{revision}. Widening Deps
			// to a blob.Writer would hand the request path Delete over every bundle
			// in the bucket, which is a decision to argue rather than a line to add.
			ObjectKey: key,
			CreatedBy: memberRef(p),
		}).Exec(ctx); txErr != nil {
			return fmt.Errorf("publish %s r%d: %w", slug, seq, txErr)
		}

		text := fmt.Sprintf("published %s r%d", facts.Name, seq)
		if note != "" {
			text += " — " + note
		}
		return writeProfileAudit(ctx, tx, p, models.AuditKindProfile, text)
	})
	if err != nil {
		return contract.Lockfile{}, err
	}
	return lockfile, nil
}

// memberRef is the value a membership row or an audit actor names this principal
// by: the email where there is one, the subject otherwise. The readability
// predicate matches either, so the two are interchangeable for access — but the
// sharing panel lists a person by address, so the address is preferred.
func memberRef(p auth.Principal) string {
	if p.Email != "" {
		return p.Email
	}
	return p.Subject
}

func writeProfileAudit(ctx context.Context, tx bun.IDB, p auth.Principal,
	kind models.AuditKind, text string,
) error {
	return writeAudit(ctx, tx, kind, memberRef(p), string(models.ActorKindIdentity), text, p.Source)
}

// counted renders "1 entry" / "4 entries" for an audit line, so a row reads as a
// sentence rather than as a number and a noun that disagrees with it.
func counted(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
