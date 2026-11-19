package queries

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
)

// The table is append-only by revoked grant, so nothing here can be wrong
// about history — but it is also the one table in this schema designed to
// grow without bound, which shapes both reads: the page is bounded and the
// export never holds more than one row in memory.
//
// Unfiltered, `audit_event_occurred_at_idx` on `("occurred_at" desc)` is the
// access path — a forward scan of that index, stopped early by the page's
// `limit`/`offset`. The `id` tiebreak is not in
// the index and does not need to be: it only orders rows sharing an
// instant, which Postgres finishes with an incremental sort per tied group.
//
// Both reads take the same AuditFilter, so the export is always the page's
// full current scope. Each filter has its own index: a selective predicate
// over a desc scan of occurred_at reads everything it rejects.

// The audit page and its cap: the page size arrives from a client.
const (
	DefaultAuditPageSize = 50
	MaxAuditPageSize     = 200
)

// AuditFilter narrows both reads. A package subject also matches the rows
// about its versions and findings, which carry it as data.package, so a
// package's history is one filter.
type AuditFilter struct {
	SubjectKind string
	SubjectID   string
	Namespace   string
}

func (f AuditFilter) where() (clause string, args []any) {
	var clauses []string
	switch {
	case f.SubjectKind == "package" && f.SubjectID != "":
		clauses = append(clauses, `((aud.subject_kind = 'package' and aud.subject_id = ?)
    or (aud.subject_kind in ('version', 'finding') and aud.data->>'package' = ?))`)
		args = append(args, f.SubjectID, f.SubjectID)
	case f.SubjectKind != "" && f.SubjectID != "":
		clauses = append(clauses, "aud.subject_kind = ?::audit_subject_kind and aud.subject_id = ?")
		args = append(args, f.SubjectKind, f.SubjectID)
	case f.SubjectKind != "":
		clauses = append(clauses, "aud.subject_kind = ?::audit_subject_kind")
		args = append(args, f.SubjectKind)
	}
	if f.Namespace != "" {
		clauses = append(clauses, "aud.namespace = ?")
		args = append(args, f.Namespace)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "\nwhere " + strings.Join(clauses, "\n  and "), args
}

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
  coalesce(aud.source, ''),
  coalesce(aud.subject_kind::text, ''),
  coalesce(aud.subject_id, ''),
  coalesce(aud.namespace, ''),
  aud.data
from audit_event as aud`

const auditOrder = "\norder by aud.occurred_at desc, aud.id desc"

// Audit returns one page of the audit log, most recent first.
func Audit(ctx context.Context, db bun.IDB, filter AuditFilter, page, pageSize int) (contract.AuditPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = DefaultAuditPageSize
	}
	if pageSize > MaxAuditPageSize {
		pageSize = MaxAuditPageSize
	}

	where, args := filter.where()
	var total int
	if err := db.QueryRowContext(ctx, "select count(*) from audit_event as aud"+where, args...).Scan(&total); err != nil {
		return contract.AuditPage{}, fmt.Errorf("count the audit log: %w", err)
	}
	// Clamped and re-read at the last page rather than answered empty, as the
	// catalog and the findings list are.
	if pages := (total + pageSize - 1) / pageSize; total > 0 && page > pages {
		page = pages
	}

	rows, err := db.QueryContext(ctx, auditSelect+where+auditOrder+"\nlimit ? offset ?",
		append(args, pageSize, (page-1)*pageSize)...)
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

// AuditExport streams the whole log to emit, one row at a time. It takes a
// callback rather than returning a slice: `audit_event` is designed to grow
// without bound, so a function returning `[]contract.AuditEntry` would hold
// the whole log in the api's heap before a single byte reached the client.
// The row travels straight from the driver's cursor to the caller's
// encoder, so nothing accumulates. The count returned is the number
// emitted, letting the caller close the stream with a sentinel saying how
// many there were.
//
// The cost is a connection held for the length of the export, and no
// statement timeout is imposed: cutting off an operator's export halfway
// would produce a truncated file that looks complete, worse than a slow
// one. It is authenticated, and that is the control.
func AuditExport(ctx context.Context, db bun.IDB, filter AuditFilter, emit func(contract.AuditEntry) error) (int, error) {
	where, args := filter.where()
	rows, err := db.QueryContext(ctx, auditSelect+where+auditOrder, args...)
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
	var data []byte
	if err := rows.Scan(&entry.ID, &entry.OccurredAt, &entry.Actor, &entry.ActorKind,
		&entry.Kind, &entry.Text, &entry.Source,
		&entry.SubjectKind, &entry.SubjectID, &entry.Namespace, &data); err != nil {
		return contract.AuditEntry{}, fmt.Errorf("scan an audit row: %w", err)
	}
	if err := json.Unmarshal(data, &entry.Data); err != nil {
		return contract.AuditEntry{}, fmt.Errorf("decode the data of audit row %s: %w", entry.ID, err)
	}
	if len(entry.Data) == 0 {
		entry.Data = nil
	}
	entry.OccurredAt = entry.OccurredAt.UTC()
	return entry, nil
}
