package fetcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/scanner"
)

// errAlreadyPublished is the transaction finding the version already committed.
var errAlreadyPublished = errors.New("version already has committed bytes")

// publish is the one transaction FR-008 hangs on.
//
// Everything before it is reversible by doing nothing: the bytes are in the
// bucket but no row points at them, and `visible` is false, so the version is
// unreadable. This transaction makes the digest, the size, the manifest, the
// tags, the components, the dist tag, the `visible` flip, the scan hand-off and
// the audit row land together or not at all. A crash in the middle leaves
// orphaned objects, which is the failure mode the design chose over a version
// that is half-published.
// It returns whether it published, and whether this version took the package's
// `latest` dist tag.
func (w *Worker) publish(ctx context.Context, job Job, pkg *pkgspec.Package, commit blob.Commit) (published, latest bool, err error) {
	err = w.deps.DB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// The row lock is what closes the window the pre-flight idempotency check
		// cannot: two deliveries of the same job can both pass that check, and only
		// one of them may write. `for update` serialises them and the re-read
		// decides, so the second one finds the digest the first wrote.
		var (
			sortKey   string
			committed bool
			packageID uuid.UUID
		)
		lockErr := tx.QueryRowContext(ctx,
			`select semver_sort, digest is not null, package_id from version where id = ? for update`,
			job.VersionID).Scan(&sortKey, &committed, &packageID)
		switch {
		case errors.Is(lockErr, sql.ErrNoRows):
			// The registration writes the version row and the outbox row in one
			// transaction, so a job whose row is missing cannot be a race — it is a
			// payload that no longer describes anything.
			return fmt.Errorf("publish %s: no version row %s", job, job.VersionID)
		case lockErr != nil:
			return fmt.Errorf("lock version %s: %w", job.VersionID, lockErr)
		case committed:
			return errAlreadyPublished
		case packageID != job.PackageID:
			return fmt.Errorf("publish %s: version %s belongs to package %s, not %s",
				job, job.VersionID, packageID, job.PackageID)
		}

		// Whether this release is the package's newest is decided here rather than
		// assumed: re-registering an older tag is a legitimate operator action, and
		// it must not steal `latest` from a higher version. semver_sort is a byte
		// order that IS semver precedence order, so this is a comparison and not a
		// parse.
		var newest bool
		if compareErr := tx.QueryRowContext(ctx,
			`select not exists (
			   select 1 from version
			    where package_id = ? and id <> ? and digest is not null and semver_sort > ?
			 )`, job.PackageID, job.VersionID, sortKey).Scan(&newest); compareErr != nil {
			return fmt.Errorf("compare %s against the package's other versions: %w", job, compareErr)
		}

		// The package's KIND is settled here and nowhere else. It is decided by which
		// manifest sits at the tree root, which is knowable only once the bytes are
		// in hand, so the registration wrote a provisional value — authoritative for
		// an upload, a default for a URL source. A package with a published version
		// already keeps its kind: a plugin does not become a skill between releases,
		// and a tree that claims otherwise is a manifest failure rather than a
		// correction.
		derived := models.PackageKind(pkg.Kind)
		if !derived.Valid() {
			return fmt.Errorf("%s: %q is not a package kind", job, pkg.Kind)
		}
		var (
			currentKind    models.PackageKind
			otherPublished bool
		)
		if kindErr := tx.QueryRowContext(ctx,
			`select p.kind,
			        exists (select 1 from version v
			                 where v.package_id = p.id and v.id <> ? and v.digest is not null)
			   from package p where p.id = ?`,
			job.VersionID, job.PackageID).Scan(&currentKind, &otherPublished); kindErr != nil {
			return fmt.Errorf("read the kind of %s/%s: %w", job.Namespace, job.Name, kindErr)
		}
		switch {
		case otherPublished && currentKind != derived:
			return fmt.Errorf("%w: %s/%s is registered as a %s and this tree is a %s",
				pkgspec.ErrManifestInvalid, job.Namespace, job.Name, currentKind, derived)
		case currentKind != derived:
			if _, kindErr := tx.NewUpdate().Model((*models.Package)(nil)).
				Set("kind = ?", derived).
				Set("updated_at = now()").
				Where("id = ?", job.PackageID).
				Exec(ctx); kindErr != nil {
				return fmt.Errorf("set the kind of %s/%s: %w", job.Namespace, job.Name, kindErr)
			}
		}

		latest = newest
		distTag := models.DistTagNone
		if newest {
			distTag = models.DistTagLatest
			// Exactly one version per package carries `latest`, so the incumbent is
			// demoted in the same transaction that promotes the successor.
			if _, demoteErr := tx.NewUpdate().Model((*models.Version)(nil)).
				Set("dist_tag = ?", models.DistTagNone).
				Where("package_id = ? and id <> ? and dist_tag = ?", job.PackageID, job.VersionID, models.DistTagLatest).
				Exec(ctx); demoteErr != nil {
				return fmt.Errorf("demote the previous latest version of %s/%s: %w", job.Namespace, job.Name, demoteErr)
			}
		}

		tags := versionTags(pkg.Keywords)

		// `and digest is null` makes this a compare-and-set on top of the row lock.
		// The lock is what actually serialises the two deliveries; this predicate is
		// what makes a lost lock a failed update rather than a silent overwrite of
		// bytes that are supposed to be immutable (FR-007).
		res, updateErr := tx.NewUpdate().Model((*models.Version)(nil)).
			Set("digest = ?", commit.Bundle.Digest[:]).
			Set("size_bytes = ?", commit.Bundle.Size).
			Set("object_key = ?", commit.Bundle.Key).
			Set("manifest = ?", pkg.ManifestJSON).
			Set("tags = ?", pgTextArray(tags)).
			Set("dist_tag = ?", distTag).
			Set("visible = ?", true).
			Where("id = ? and digest is null", job.VersionID).
			Exec(ctx)
		if updateErr != nil {
			return fmt.Errorf("record the stored bundle for %s: %w", job, updateErr)
		}
		affected, updateErr := res.RowsAffected()
		if updateErr != nil {
			return fmt.Errorf("record the stored bundle for %s: %w", job, updateErr)
		}
		if affected != 1 {
			return errAlreadyPublished
		}

		if tagErr := insertVersionTags(ctx, tx, job.VersionID, tags); tagErr != nil {
			return tagErr
		}
		if componentErr := insertComponents(ctx, tx, job.VersionID, pkg.Components); componentErr != nil {
			return componentErr
		}

		// A signature row of kind `none` is registry-side metadata and states that
		// nothing was supplied (R9). It exists so "unsigned" is a row the UI can
		// read rather than a missing row it has to interpret, which is what FR-048a
		// asks for. `capability` is deliberately not written here: am_fetcher holds
		// no grant on it, and the expected set stays recoverable from
		// version.manifest.
		if _, signatureErr := tx.NewInsert().Model(&models.Signature{
			VersionID: job.VersionID,
			Kind:      models.SignatureKindNone,
		}).On("conflict (version_id) do nothing").Exec(ctx); signatureErr != nil {
			return fmt.Errorf("record the signature state for %s: %w", job, signatureErr)
		}

		if newest {
			if _, pointErr := tx.NewUpdate().Model((*models.Package)(nil)).
				Set("latest_version_id = ?", job.VersionID).
				Set("updated_at = now()").
				Where("id = ?", job.PackageID).
				Exec(ctx); pointErr != nil {
				return fmt.Errorf("point %s/%s at its latest version: %w", job.Namespace, job.Name, pointErr)
			}
		}

		// The scan hand-off rides the same transaction (principle IX): a version is
		// not published until the scan that will give it a verdict is durably
		// enqueued, so there is no committed version that nothing will ever scan.
		//
		// The payload type belongs to the CONSUMER (contracts/worker.md): the scanner
		// owns the shape it has to be able to read, and its OutboxJob leaves
		// SubjectVersion empty on purpose, because the scan idempotency key is
		// (scan, version id, RULE-PACK version) and the rule-pack version is the
		// scanner's own. A producer that guessed it would suppress the first real scan
		// or fail to suppress a redelivery.
		scanJob, scanErr := scanner.Job{
			VersionID: job.VersionID,
			PackageID: job.PackageID,
			Namespace: job.Namespace,
			Name:      job.Name,
			Semver:    job.Semver,
			ObjectKey: commit.Bundle.Key,
		}.OutboxJob()
		if scanErr != nil {
			return fmt.Errorf("enqueue the scan of %s: %w", job, scanErr)
		}

		// FR-030 and 001 US4 scenario 5: publishing a version re-enqueues the
		// package's already-scanned versions, so a rule pack that has moved on since
		// they were judged gets to judge them again and a new finding reopens an
		// approved version.
		//
		// It rides this transaction and carries no policy decision. Whether
		// rescan-on-new-version is enabled is read by the SCANNER, because am_scanner
		// holds the grant on org_policy and am_fetcher deliberately does not — so the
		// sweep is enqueued unconditionally and the role that can read the setting is
		// the role that acts on it. The cost of a disabled policy is one outbox row
		// and one query per publish.
		sweepJob, sweepErr := scanner.SweepJob{
			PackageID:        job.PackageID,
			TriggerVersionID: job.VersionID,
			Namespace:        job.Namespace,
			Name:             job.Name,
		}.OutboxJob()
		if sweepErr != nil {
			return fmt.Errorf("enqueue the rescan sweep of %s/%s: %w", job.Namespace, job.Name, sweepErr)
		}

		if _, enqueueErr := w.enqueue.Enqueue(ctx, tx, scanJob, sweepJob); enqueueErr != nil {
			return fmt.Errorf("enqueue the scan of %s: %w", job, enqueueErr)
		}

		if auditErr := writeFetchAudit(ctx, tx, storedText(job, pkg, commit)); auditErr != nil {
			return auditErr
		}
		if attemptErr := writeFetchAttempt(ctx, tx, job, models.FetchOutcomeOK, ""); attemptErr != nil {
			return attemptErr
		}

		published = true
		return nil
	})

	switch {
	case errors.Is(err, errAlreadyPublished):
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	return published, latest, nil
}

// versionTags is the manifest's keywords as the version's tags: deduplicated and
// ordered, because version_tag is keyed on (version_id, tag) and version.tags is
// the same set denormalised for the catalog's GIN index (R4).
func versionTags(keywords []string) []string {
	out := make([]string, 0, len(keywords))
	for _, tag := range keywords {
		if tag != "" && !slices.Contains(out, tag) {
			out = append(out, tag)
		}
	}
	slices.Sort(out)
	return out
}

func insertVersionTags(ctx context.Context, tx bun.IDB, versionID uuid.UUID, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	rows := make([]models.VersionTag, 0, len(tags))
	for _, tag := range tags {
		rows = append(rows, models.VersionTag{VersionID: versionID, Tag: tag})
	}
	if _, err := tx.NewInsert().Model(&rows).
		On("conflict (version_id, tag) do nothing").Exec(ctx); err != nil {
		return fmt.Errorf("write the tags of version %s: %w", versionID, err)
	}
	return nil
}

// insertComponents writes what the FILE TREE said the version contains. The
// manifest is not consulted here: no field in either published spec enumerates
// components (R1), so a component row is evidence about the bytes.
func insertComponents(ctx context.Context, tx bun.IDB, versionID uuid.UUID, components []pkgspec.Component) error {
	if len(components) == 0 {
		return nil
	}
	rows := make([]models.Component, 0, len(components))
	for _, component := range components {
		kind := models.ComponentKind(component.Kind)
		if !kind.Valid() {
			return fmt.Errorf("component %q of version %s has kind %q, which the schema does not allow",
				component.Path, versionID, component.Kind)
		}
		rows = append(rows, models.Component{
			VersionID: versionID,
			Path:      component.Path,
			Kind:      kind,
			Name:      component.Name,
			Note:      component.Note,
		})
	}
	if _, err := tx.NewInsert().Model(&rows).
		On("conflict (version_id, path) do nothing").Exec(ctx); err != nil {
		return fmt.Errorf("write the components of version %s: %w", versionID, err)
	}
	return nil
}

// pgTextArray renders a Go slice as a text[] literal.
//
// bun's `array` tag handles this on a model field, but this update is expressed
// as a Set on a column rather than a whole-model write, and a []string handed to
// Set arrives as a jsonb-ish string that text[] refuses.
func pgTextArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	out := make([]byte, 0, len(values)*8+2)
	out = append(out, '{')
	for i, v := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '"')
		for j := 0; j < len(v); j++ {
			if v[j] == '"' || v[j] == '\\' {
				out = append(out, '\\')
			}
			out = append(out, v[j])
		}
		out = append(out, '"')
	}
	return string(append(out, '}'))
}
