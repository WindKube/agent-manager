package outbox

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Delivery is at-least-once (principle IX), so every handler must be able to tell
// a redelivery from a new instruction. The answer comes from the job's TARGET ROW
// and never from the queue — the queue has no memory to consult, which is the
// whole reason the idempotency key is (job_kind, subject_id, subject_version)
// persisted in the application database (R5).
//
// The predicates live here rather than in each handler so the fetcher's answer and
// the scanner's cannot drift apart.

// Delivered reports whether the work a job describes is already on record.
//
// SubjectID is the version id for both real kinds. SubjectVersion is the semver
// for a fetch and the rule-pack version for a scan, which is what makes "rescan
// under a new rule pack" work: the key moves, so the guard opens.
func Delivered(ctx context.Context, db bun.IDB, job Job) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("idempotency check for %s: no database handle", job.Kind)
	}

	switch job.Kind {
	case KindFetch:
		return bytesCommitted(ctx, db, job.SubjectID)
	case KindScan:
		return scanRecorded(ctx, db, job.SubjectID, job.SubjectVersion)
	case KindRescanSweep:
		// A sweep is not guarded here. It reads the catalog and fans out to
		// per-version scan jobs, and each of those carries the guard above, so
		// suppressing the sweep itself would only skip a fan-out that is already
		// idempotent.
		return false, nil
	default:
		return false, fmt.Errorf("idempotency check: unknown job kind %q", job.Kind)
	}
}

// bytesCommitted answers "does this version already have committed bytes?". The
// digest is the record that they landed: it is written in the same transaction as
// the object key and never mutated afterwards (principle IV).
func bytesCommitted(ctx context.Context, db bun.IDB, versionID uuid.UUID) (bool, error) {
	if versionID == uuid.Nil {
		return false, fmt.Errorf("fetch idempotency check: no subject version id")
	}

	// bun formats raw SQL with `?` and passes no arguments to the driver, so a `$1`
	// here would reach Postgres unbound.
	var committed bool
	err := db.QueryRowContext(ctx,
		`select coalesce((select digest is not null from version where id = ?), false)`,
		versionID).Scan(&committed)
	if err != nil {
		return false, fmt.Errorf("read committed bytes for version %s: %w", versionID, err)
	}
	return committed, nil
}

// scanRecorded answers "has this version been scanned at this rule-pack version?".
// It is the Go-side reading of the `unique (version_id, pack_version)` key, so a
// handler can skip the work instead of inserting and catching a constraint
// violation.
func scanRecorded(ctx context.Context, db bun.IDB, versionID uuid.UUID, packVersion string) (bool, error) {
	if versionID == uuid.Nil {
		return false, fmt.Errorf("scan idempotency check: no subject version id")
	}
	if packVersion == "" {
		return false, fmt.Errorf("scan idempotency check for version %s: no pack version", versionID)
	}

	var recorded bool
	err := db.QueryRowContext(ctx,
		`select exists (select 1 from scan where version_id = ? and pack_version = ?)`,
		versionID, packVersion).Scan(&recorded)
	if err != nil {
		return false, fmt.Errorf("read scan history for version %s: %w", versionID, err)
	}
	return recorded, nil
}
