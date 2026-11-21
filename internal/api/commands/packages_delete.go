package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

// Catalog deletes archive (dist_tag = 'archived') rather than remove rows:
// version digest/object_key/verdict are write-once, and revisions and pinned
// entries still reference them. Archived versions leave the floating pool and
// the catalog but keep resolving for explicit pins. Blobs are never touched;
// only worker fetcher holds object-store write access.

var (
	ErrPackageNotFound = errors.New("no such package")
	ErrVersionNotFound = errors.New("no such version")
	// ErrAlreadyWithdrawn is a version whose dist_tag is already 'archived',
	// or a package every one of whose versions already is.
	ErrAlreadyWithdrawn = errors.New("already withdrawn from the catalog")
)

// VersionWithdrawal is what a version delete reports back: the pin count is
// read at the moment of the decision and never stored.
type VersionWithdrawal struct {
	PinnedByProfiles int
}

// DeleteVersion archives one version. References from profile entries or
// revisions are not a reason to refuse; they are why it archives.
func DeleteVersion(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name, semver string) (VersionWithdrawal, error) {
	var out VersionWithdrawal
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		pkg, err := lookupPackage(ctx, tx, namespace, name)
		if err != nil {
			return err
		}

		version := new(models.Version)
		if selErr := tx.NewSelect().Model(version).
			Where("package_id = ? and semver = ?", pkg.ID, semver).
			Scan(ctx); selErr != nil {
			if errors.Is(selErr, sql.ErrNoRows) {
				return ErrVersionNotFound
			}
			return fmt.Errorf("locate version %s/%s@%s: %w", namespace, name, semver, selErr)
		}
		if version.DistTag == models.DistTagArchived {
			return ErrAlreadyWithdrawn
		}

		if out.PinnedByProfiles, err = countPins(ctx, tx, version.ID); err != nil {
			return err
		}

		if _, updErr := tx.NewUpdate().Model((*models.Version)(nil)).
			Set("dist_tag = ?", models.DistTagArchived).
			Where("id = ?", version.ID).
			Exec(ctx); updErr != nil {
			return fmt.Errorf("archive version %s/%s@%s: %w", namespace, name, semver, updErr)
		}

		if pkg.LatestVersionID != nil && *pkg.LatestVersionID == version.ID {
			if promErr := promoteLatest(ctx, tx, pkg.ID, version.ID); promErr != nil {
				return promErr
			}
		}

		text := fmt.Sprintf("deleted version %s of %s/%s from the catalog (archived; %s)",
			semver, namespace, name, pinNote(out.PinnedByProfiles))
		audit := catalogDeleteAudit(p, text, audit.Version(namespace, name, semver))
		audit.Data = map[string]any{"pinnedByProfiles": out.PinnedByProfiles}
		return writeAudit(ctx, tx, audit)
	})
	if err != nil {
		return VersionWithdrawal{}, err
	}
	return out, nil
}

// PackageWithdrawal mirrors VersionWithdrawal at package scope.
type PackageWithdrawal struct {
	VersionsArchived int
}

// DeletePackage archives every version of a package and clears
// latest_version_id, which is what the catalog joins on.
func DeletePackage(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name string) (PackageWithdrawal, error) {
	var out PackageWithdrawal
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		pkg, err := lookupPackage(ctx, tx, namespace, name)
		if err != nil {
			return err
		}

		res, updErr := tx.NewUpdate().Model((*models.Version)(nil)).
			Set("dist_tag = ?", models.DistTagArchived).
			Where("package_id = ? and dist_tag <> ?", pkg.ID, models.DistTagArchived).
			Exec(ctx)
		if updErr != nil {
			return fmt.Errorf("archive the versions of %s/%s: %w", namespace, name, updErr)
		}
		affected, raErr := res.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("archive the versions of %s/%s: %w", namespace, name, raErr)
		}
		if affected == 0 {
			return ErrAlreadyWithdrawn
		}
		out.VersionsArchived = int(affected)

		if _, clrErr := tx.NewUpdate().Model((*models.Package)(nil)).
			Set("latest_version_id = NULL").
			Where("id = ?", pkg.ID).
			Exec(ctx); clrErr != nil {
			return fmt.Errorf("clear the latest version of %s/%s: %w", namespace, name, clrErr)
		}

		text := fmt.Sprintf("deleted package %s/%s from the catalog (archived %d version(s))",
			namespace, name, out.VersionsArchived)
		audit := catalogDeleteAudit(p, text, audit.Package(namespace, name))
		audit.Data = map[string]any{"versionsArchived": out.VersionsArchived}
		return writeAudit(ctx, tx, audit)
	})
	if err != nil {
		return PackageWithdrawal{}, err
	}
	return out, nil
}

func lookupPackage(ctx context.Context, tx bun.IDB, namespace, name string) (*models.Package, error) {
	pkg := new(models.Package)
	err := tx.NewSelect().Model(pkg).
		Where("namespace = ? and name = ?", namespace, name).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrPackageNotFound
	case err != nil:
		return nil, fmt.Errorf("locate package %s/%s: %w", namespace, name, err)
	}
	return pkg, nil
}

// promoteLatest hands `latest` to the next newest visible, non-archived
// version, or clears latest_version_id when there is none.
func promoteLatest(ctx context.Context, tx bun.Tx, packageID, archivedID uuid.UUID) error {
	var nextID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		select id from version
		 where package_id = ? and id <> ? and visible and dist_tag <> 'archived'
		 order by semver_sort desc
		 limit 1`, packageID, archivedID).Scan(&nextID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, clrErr := tx.NewUpdate().Model((*models.Package)(nil)).
			Set("latest_version_id = NULL").
			Where("id = ?", packageID).
			Exec(ctx)
		return clrErr
	case err != nil:
		return fmt.Errorf("find the next latest version of package %s: %w", packageID, err)
	}

	if _, updErr := tx.NewUpdate().Model((*models.Version)(nil)).
		Set("dist_tag = ?", models.DistTagLatest).
		Where("id = ?", nextID).
		Exec(ctx); updErr != nil {
		return fmt.Errorf("promote %s to latest: %w", nextID, updErr)
	}
	_, err = tx.NewUpdate().Model((*models.Package)(nil)).
		Set("latest_version_id = ?", nextID).
		Where("id = ?", packageID).
		Exec(ctx)
	return err
}

func countPins(ctx context.Context, tx bun.IDB, versionID uuid.UUID) (int, error) {
	n, err := tx.NewSelect().Model((*models.ProfileEntry)(nil)).
		Where("pinned_version_id = ?", versionID).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count pins on version %s: %w", versionID, err)
	}
	return n, nil
}

func pinNote(n int) string {
	switch n {
	case 0:
		return "not pinned by any profile entry"
	case 1:
		return "pinned by 1 profile entry, which keeps resolving it"
	default:
		return fmt.Sprintf("pinned by %d profile entries, which keep resolving it", n)
	}
}

// catalogDeleteAudit reuses AuditKindFetch, the catalog-lifecycle kind, rather
// than a dedicated audit_kind value.
func catalogDeleteAudit(p auth.Principal, text string, subject audit.Subject) audit.Entry {
	return identityAudit(p, models.AuditKindFetch, "deleted", text, subject)
}
