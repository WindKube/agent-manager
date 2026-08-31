package queries

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
)

// The audit log's reads (001 FR-050..FR-052, 003 T067-T068).
//
// The table is append-only by revoked grant, so nothing here can be wrong about
// history — but it is also the one table in this schema designed to grow without
// bound, which is what shapes both reads below: the page is bounded and the
// export never holds more than one row in memory.
//
// NO INDEX IS ADDED FOR EITHER, and none is needed. `audit_event_occurred_at_idx`
// on `("occurred_at" desc)` — created by 001 T017 — is the access path: both
// statements are an unfiltered `order by occurred_at desc`, which is a forward
// scan of that index, and the page's `limit`/`offset` stops it early. The `id`
// tiebreak below is not in the index and does not need to be: it only orders rows
// that share an instant, which Postgres finishes with an incremental sort over
// each tied group while the index still supplies the leading key.
//
// There is deliberately NO filter on either operation, and the two facts are the
// same fact. FR-051 requires the export to be "the full CURRENT SCOPE, not merely
// the visible page": with no filters, the current scope is the whole log and the
// export is unambiguously it. A filter added to the page later MUST be added to
// the export in the same commit, or FR-051 quietly stops holding — and it would
// also need its own index, because a selective predicate over a desc scan reads
// everything the predicate rejects.

// The audit page and its cap. The design's audit screen shows a screenful; the
// cap is here because the page size arrives from a client.
const (
	DefaultAuditPageSize = 50
	MaxAuditPageSize     = 200
)

// auditSelect is the row shape both reads share, so the page and the export
// cannot come to describe the same row differently.
const auditSelect = `
select
  aud.id,
  aud.occurred_at,
  aud.actor,
  aud.actor_kind::text,
  aud.kind::text,
  aud.text,
  coalesce(aud.source, '')
from audit_event as aud
order by aud.occurred_at desc, aud.id desc`

// Audit returns one page of the audit log, most recent first (T067).
func Audit(ctx context.Context, db bun.IDB, page, pageSize int) (contract.AuditPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = DefaultAuditPageSize
	}
	if pageSize > MaxAuditPageSize {
		pageSize = MaxAuditPageSize
	}

	var total int
	if err := db.QueryRowContext(ctx, "select count(*) from audit_event").Scan(&total); err != nil {
		return contract.AuditPage{}, fmt.Errorf("count the audit log: %w", err)
	}
	// Clamped and re-read at the last page rather than answered empty, as the
	// catalog and the findings list are.
	if pages := (total + pageSize - 1) / pageSize; total > 0 && page > pages {
		page = pages
	}

	rows, err := db.QueryContext(ctx, auditSelect+"\nlimit ? offset ?", pageSize, (page-1)*pageSize)
	if err != nil {
		return contract.AuditPage{}, fmt.Errorf("read the audit page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := contract.AuditPage{Entries: []contract.AuditEntry{}, Total: total, Page: page, PageSize: pageSize}
	for rows.Next() {
		entry, scanErr := scanAuditEntry(rows)
		if scanErr != nil {
			return contract.AuditPage{}, scanErr
		}
		out.Entries = append(out.Entries, entry)
	}
	if err := rows.Err(); err != nil {
		return contract.AuditPage{}, fmt.Errorf("read the audit page: %w", err)
	}
	return out, nil
}

// AuditExport streams the WHOLE log to emit, one row at a time (T068, FR-051).
//
// It takes a callback rather than returning a slice, an iterator or a channel,
// and that signature IS the requirement. FR-051 asks for the full current scope
// and `audit_event` is the one table in this schema designed to grow without
// bound, so a function that returned `[]contract.AuditEntry` would hold the whole
// log in the api's heap before a single byte reached the client — and would do it
// on the one operation whose response size an operator cannot bound. Building the
// slice is the bug; there is no size at which it becomes correct.
//
// The row therefore travels straight from the driver's cursor to the caller's
// encoder: `rows.Next()` reads one row off the connection at a time, emit writes
// it, and nothing accumulates. The count returned is the number emitted, which is
// what lets the caller close the stream with a sentinel saying how many there
// were.
//
// The cost of that is a connection held for the length of the export, and no
// statement timeout is imposed here: cutting off an operator's export halfway
// would produce a truncated file that looks complete, which is worse than a slow
// one. It is authenticated, and that is the control.
func AuditExport(ctx context.Context, db bun.IDB, emit func(contract.AuditEntry) error) (int, error) {
	rows, err := db.QueryContext(ctx, auditSelect)
	if err != nil {
		return 0, fmt.Errorf("read the audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	written := 0
	for rows.Next() {
		entry, scanErr := scanAuditEntry(rows)
		if scanErr != nil {
			return written, scanErr
		}
		if err := emit(entry); err != nil {
			return written, err
		}
		written++
	}
	if err := rows.Err(); err != nil {
		return written, fmt.Errorf("read the audit log: %w", err)
	}
	return written, nil
}

func scanAuditEntry(rows *sql.Rows) (contract.AuditEntry, error) {
	var entry contract.AuditEntry
	if err := rows.Scan(&entry.ID, &entry.OccurredAt, &entry.Actor, &entry.ActorKind,
		&entry.Kind, &entry.Text, &entry.Source); err != nil {
		return contract.AuditEntry{}, fmt.Errorf("scan an audit row: %w", err)
	}
	entry.OccurredAt = entry.OccurredAt.UTC()
	return entry, nil
}
