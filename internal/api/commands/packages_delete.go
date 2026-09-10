package commands

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// Deleting from the catalog.
//
// Neither delete below removes a row. version.digest, version.object_key and
// version.verdict are the write-once trio principle IV protects, and
// 03-constraints.sql's own comment on package_latest_version_id_fkey already
// assumes a version is never physically deleted ("the only way this reference
// can block a delete is a delete that should not be happening"). A published
// revision's lockfile is a jsonb snapshot with no foreign key of its own, and
// a profile_entry can pin a version directly — a hard delete would either
// trip a NO ACTION foreign key or silently rewrite a historical record the
// schema was built not to allow.
//
// What "delete" means instead is what dist_tag = 'archived' already means,
// unused by any code path until now: resolve.Candidate.Visible's own doc
// comment states the exact semantics wanted here — "withdrawing a version
// from the shelf isn't the same as withdrawing it from machines that chose
// it." Archiving a version takes it out of poolFor's floating/range pool
// (internal/domain/resolve/resolve.go) and, when it held the package's
// `latest_version_id`, out of the catalog and the package detail screen —
// both join through that column. An explicit pin or a revision that already
// recorded this semver keeps resolving, because digest, object_key, verdict
// and `visible` never change. Deleting a package is the same act applied to
// every one of its versions, plus clearing `latest_version_id`, which is what
// makes catalogFrom's own join stop finding the package at all — the same
// 404 an unpublished package already answers with.
//
// This is also the only delete `serve api` could perform: principle II gives
// object-store write access to `worker fetcher` alone, so this role holds no
// credential to remove a blob even where a hard delete would otherwise be
// safe. Blobs are never touched by either function below.

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

// DeleteVersion archives one version. It refuses only on not-found or a
// version already archived — a reference from a profile entry or a revision
// is not a reason to refuse; it is the reason archiving exists instead of a
// hard delete.
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
		return writeCatalogDeleteAudit(ctx, tx, p, text)
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

// DeletePackage archives every version of a package not archived already,
// and clears latest_version_id so the catalog and the package detail
// screen's own join — both keyed on that column — stop finding it.
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
		return writeCatalogDeleteAudit(ctx, tx, p, text)
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

// promoteLatest hands `latest` and latest_version_id to the next newest
// committed, non-archived version, mirroring the comparison
// worker/fetcher/publish.go makes at publish time. No candidate is not an
// error: package.latest_version_id is nullzero for exactly this case.
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

// writeCatalogDeleteAudit reuses AuditKindFetch rather than adding a
// dedicated audit_kind value: that enum is a Postgres type, and a new value
// needs an Atlas-generated migration (`.bin/atlas`, unavailable in this
// worktree — see the branch's report). `fetch` is already this codebase's
// catalog-lifecycle kind (registerPackage's own audit row uses it for
// "registered X from Y"), and the free-text below states the actual action
// without ambiguity, which is what an operator reading the audit log acts on.
func writeCatalogDeleteAudit(ctx context.Context, tx bun.IDB, p auth.Principal, text string) error {
	actor := p.Email
	if actor == "" {
		actor = p.Subject
	}
	return writeAudit(ctx, tx, models.AuditKindFetch, actor, string(models.ActorKindIdentity), text, p.Source)
}
