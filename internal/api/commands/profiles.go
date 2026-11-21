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
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// Profile commands lock the profile row so every check decides against one
// state, and gate on the caller's membership role rather than org role.
// Revisions are never deleted.

// ErrProfileExists is a conflict, not a validation failure: the slug is the URL.
var ErrProfileExists = errors.New("a profile with this slug already exists")

var ErrProfileRefused = errors.New("the profile change was refused")

// ErrProfileHasRevisions refuses deleting a published profile: revisions are
// never deleted and a client may already have synced one.
var ErrProfileHasRevisions = errors.New("this profile has published revisions and cannot be deleted")

const uniqueProfileSlugConstraint = "profile_slug_key"

// NotPermittedError is typed so the 403 body can tell "not a member" from
// "wrong kind of member".
type NotPermittedError struct {
	Action string
	Needs  string
	Held   models.MembershipRole
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

// refused wraps a caller-fixable refusal answered as 422 with the sentence.
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
	// ForkOf is the slug of the profile whose entries are copied, if any.
	ForkOf string
}

func (c ProfileCreation) normalise() ProfileCreation {
	c.Slug = strings.TrimSpace(c.Slug)
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	c.OwnerTeam = strings.TrimSpace(c.OwnerTeam)
	c.ForkOf = strings.TrimSpace(c.ForkOf)
	if c.Visibility == "" {
		// Private, so a mistake isn't visible to everyone.
		c.Visibility = models.ProfileVisibilityPrivate
	}
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = models.VersionPolicyFloatingLatest
	}
	return c
}

// CreateProfile creates a profile and makes its creator the owner; without
// that membership the profile would be permanently uneditable.
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
	if in.Visibility == models.ProfileVisibilityPrivate {
		policy, err := queries.Policy(ctx, db)
		if err != nil {
			return contract.Profile{}, err
		}
		if !policy.AllowPersonalProfiles {
			return contract.Profile{}, refused("private profiles are disabled by organisation policy")
		}
	}
	// Validated by the function that builds the object key, not a looser copy.
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
			// Forking is reading, so an unreadable profile isn't forkable.
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
			// Copied once; a fork never inherits later revisions.
			if copied, txErr = copyEntries(ctx, tx, *profile.ForkedFromID, profile.ID); txErr != nil {
				return txErr
			}
		}

		subject := audit.Profile(profile.ID, in.Slug)
		if forked != "" {
			audit := identityAudit(p, models.AuditKindProfile, "forked",
				fmt.Sprintf("forked %s from %s with %s, which inherits no later revision of it",
					in.Slug, forked, counted(copied, "package", "packages")), subject)
			audit.Data = map[string]any{"forkedFrom": forked, "entries": copied}
			return writeAudit(ctx, tx, audit)
		}
		audit := identityAudit(p, models.AuditKindProfile, "created",
			fmt.Sprintf("created profile %s (%s)", in.Slug, in.Visibility), subject)
		audit.Data = map[string]any{"visibility": string(in.Visibility)}
		return writeAudit(ctx, tx, audit)
	})
	if err != nil {
		return contract.Profile{}, err
	}

	return contract.Profile{
		Slug:       profile.Slug,
		Name:       profile.Name,
		Visibility: string(profile.Visibility),
		CanCurate:  true,
	}, nil
}

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

// SetProfileEntries replaces the profile's ordered set of packages in the
// draft; machines see it only once a revision is published.
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

		audit := identityAudit(p, models.AuditKindProfile, "entries-set", fmt.Sprintf(
			"set the packages in %s: %s, %d changed", slug,
			counted(len(rows), "entry", "entries"), changed), audit.Profile(facts.ID, slug))
		audit.Data = map[string]any{"entries": len(rows), "changed": changed}
		return writeAudit(ctx, tx, audit)
	})
}

// entryRowsFor turns the request into rows, refusing legibly what the database
// would refuse, plus an omitted held entry: silently keeping it would answer
// 200 to a request whose stored result disagrees with what was sent.
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
			// Leaving both empty is what clears a pin on "unpin".
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

// versionID resolves a pin. `visible` isn't required (withdrawing from the
// catalog doesn't withdraw from profiles); a digest is.
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

// RemoveProfileEntry takes one package out of a profile. It is the explicit
// removal, so SetProfileEntries can keep refusing a body that omits an entry.
func RemoveProfileEntry(ctx context.Context, db bun.IDB, p auth.Principal, slug, id string) error {
	namespace, name, ok := strings.Cut(id, "/")
	if !ok || namespace == "" || name == "" {
		return refused("%q is not a package id: it is namespace/name", id)
	}

	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, err := queries.LockProfile(ctx, tx, p, slug)
		if err != nil {
			return err
		}
		if !facts.Role.MayCurate() {
			return notPermitted("change the packages in", "owner or maintainer", facts.Role)
		}

		pkgID, err := packageID(ctx, tx, namespace, name)
		if err != nil {
			return err
		}

		res, err := tx.NewDelete().Model((*models.ProfileEntry)(nil)).
			Where("profile_id = ? and package_id = ?", facts.ID, pkgID).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("remove %s from %s: %w", id, slug, err)
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return refused("%s does not hold %s, so there is nothing to remove", slug, id)
		}

		audit := identityAudit(p, models.AuditKindProfile, "entry-removed",
			fmt.Sprintf("removed %s from %s", id, slug), audit.Profile(facts.ID, slug))
		audit.Data = map[string]any{"package": id}
		return writeAudit(ctx, tx, audit)
	})
}

// SetProfileSharing upserts the role each named subject holds; an omitted
// subject keeps its role.
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

		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindShare, "shared",
			"shared "+slug+" with "+describeShares(in.Members), audit.Profile(facts.ID, slug)))
	})
}

// membershipRowsFor validates the body and enforces that the profile keeps an
// owner, counted over the resulting set; otherwise it would be unrepairable.
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

// SetProfileTargets records which agent directories a client should write.
// An omitted target is set disabled; the resolver never reads these rows.
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

		ordered := make([]string, 0, len(in.Targets))
		for _, target := range vocabulary {
			if wanted[target] {
				ordered = append(ordered, target)
			}
		}
		enabled := "nothing"
		if len(ordered) > 0 {
			enabled = strings.Join(ordered, ", ")
		}
		audit := identityAudit(p, models.AuditKindProfile, "targets-set",
			"set the sync targets of "+slug+" to "+enabled, audit.Profile(facts.ID, slug))
		audit.Data = map[string]any{"targets": ordered}
		return writeAudit(ctx, tx, audit)
	})
}

// PublishRevision freezes the current resolution as the next revision, via
// the same queries.ResolveProfileFacts the detail screen uses. The seq is
// allocated under the row lock; `unique (profile_id, seq)` backs it up.
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

		// Read after the lock is held, so it sees a publish that committed
		// while this one waited.
		var head int32
		if txErr = tx.QueryRowContext(ctx,
			`select coalesce(max(seq), 0) from revision where profile_id = ?`,
			facts.ID).Scan(&head); txErr != nil {
			return fmt.Errorf("read the head revision of %s: %w", slug, txErr)
		}
		seq := head + 1
		revision := int(seq)

		resolution, txErr := queries.ResolveProfileFacts(ctx, tx, facts, p)
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

		revisionID := models.NewID()
		if _, txErr = tx.NewInsert().Model(&models.Revision{
			ID:        revisionID,
			ProfileID: facts.ID,
			Seq:       seq,
			Note:      note,
			Lockfile:  encoded,
			// This role only writes the row; it holds no blob writer.
			ObjectKey: key,
			CreatedBy: memberRef(p),
		}).Exec(ctx); txErr != nil {
			return fmt.Errorf("publish %s r%d: %w", slug, seq, txErr)
		}

		text := fmt.Sprintf("published %s r%d", facts.Name, seq)
		if note != "" {
			text += " — " + note
		}
		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindProfile, "published", text,
			audit.Revision(revisionID, facts.ID, facts.Slug, revision)))
	})
	if err != nil {
		return contract.Lockfile{}, err
	}
	return lockfile, nil
}

// DeleteProfile permanently removes a profile that has never been published.
// The revision foreign key refuses the rest, so there is no check-then-delete
// race.
func DeleteProfile(ctx context.Context, db bun.IDB, p auth.Principal, slug string) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		facts, err := queries.LockProfile(ctx, tx, p, slug)
		if err != nil {
			return err
		}
		if !facts.Role.MayDelete() {
			return notPermitted("delete", "owner", facts.Role)
		}

		// am_api holds DELETE on exactly these three; revision is left to the FK.
		if _, err := tx.NewDelete().Model((*models.ProfileEntry)(nil)).
			Where("profile_id = ?", facts.ID).Exec(ctx); err != nil {
			return fmt.Errorf("clear the entries of %s before deleting it: %w", slug, err)
		}
		if _, err := tx.NewDelete().Model((*models.Membership)(nil)).
			Where("profile_id = ?", facts.ID).Exec(ctx); err != nil {
			return fmt.Errorf("clear the membership of %s before deleting it: %w", slug, err)
		}
		if _, err := tx.NewDelete().Model((*models.SyncTarget)(nil)).
			Where("profile_id = ?", facts.ID).Exec(ctx); err != nil {
			return fmt.Errorf("clear the sync targets of %s before deleting it: %w", slug, err)
		}

		if _, err := tx.NewDelete().Model((*models.Profile)(nil)).
			Where("id = ?", facts.ID).Exec(ctx); err != nil {
			if isForeignKeyViolation(err) {
				return fmt.Errorf("%w: %s has published revisions that a client may already "+
					"have synced", ErrProfileHasRevisions, slug)
			}
			return fmt.Errorf("delete %s: %w", slug, err)
		}

		return writeAudit(ctx, tx, identityAudit(p, models.AuditKindProfile, "deleted",
			fmt.Sprintf("deleted profile %s (%s)", slug, facts.Name), audit.Profile(facts.ID, slug)))
	})
}

// memberRef is the principal's email, or its subject when there is none.
func memberRef(p auth.Principal) string {
	if p.Email != "" {
		return p.Email
	}
	return p.Subject
}

func counted(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
