package outbox

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Delivery is at-least-once; redeliveries are detected from the job's target
// row, never the queue, and the predicates live here so handlers cannot drift.

// Delivered reports whether the work a job describes is already on record.
// For a scan SubjectVersion is the rule-pack version, so a new pack reopens the guard.
func Delivered(ctx context.Context, db bun.IDB, job Job) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("idempotency check for %s: no database handle", job.Kind)
	}

	switch job.Kind {
	case KindFetch:
		return bytesCommitted(ctx, db, job.SubjectID)
	case KindScan:
		return scanRecorded(ctx, db, job.SubjectID, job.SubjectVersion)
	case KindNotify:
		return webhookDelivered(ctx, db, job.SubjectID, job.SubjectVersion)
	case KindRescanSweep:
		// The per-version scan jobs a sweep fans out to are guarded themselves.
		return false, nil
	default:
		return false, fmt.Errorf("idempotency check: unknown job kind %q", job.Kind)
	}
}

// bytesCommitted reports whether the version has a digest, which is written
// with the object key and never mutated.
func bytesCommitted(ctx context.Context, db bun.IDB, versionID uuid.UUID) (bool, error) {
	if versionID == uuid.Nil {
		return false, fmt.Errorf("fetch idempotency check: no subject version id")
	}

	// bun formats raw SQL with `?` and passes no driver args, so `$1` would be unbound.
	var committed bool
	err := db.QueryRowContext(ctx,
		`select coalesce((select digest is not null from version where id = ?), false)`,
		versionID).Scan(&committed)
	if err != nil {
		return false, fmt.Errorf("read committed bytes for version %s: %w", versionID, err)
	}
	return committed, nil
}

// scanRecorded checks the `unique (version_id, pack_version)` key up front so a
// handler can skip work instead of catching a constraint violation.
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

// webhookDelivered reports whether the receiver already accepted the event with a 2xx.
func webhookDelivered(ctx context.Context, db bun.IDB, subscriptionID uuid.UUID, eventID string) (bool, error) {
	if subscriptionID == uuid.Nil || eventID == "" {
		return false, fmt.Errorf("notify idempotency check: no subscription or event")
	}
	var delivered bool
	err := db.QueryRowContext(ctx,
		`select exists (select 1 from webhook_delivery
		 where subscription_id = ? and event_id = ?::uuid and status_code between 200 and 299)`,
		subscriptionID, eventID).Scan(&delivered)
	if err != nil {
		return false, fmt.Errorf("read deliveries of event %s to webhook %s: %w", eventID, subscriptionID, err)
	}
	return delivered, nil
}
