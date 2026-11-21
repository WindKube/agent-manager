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

// audit_event grows without bound, so the page is capped and the export
// never holds more than one row in memory. Each filter needs its own index:
// a selective predicate over a desc scan of occurred_at reads everything it
// rejects.

// The audit page size arrives from a client, hence the cap.
const (
	DefaultAuditPageSize = 50
	MaxAuditPageSize     = 200
)

// AuditFilter narrows both reads. A package subject also matches its
// versions' and findings' rows, which carry it as data.package.
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

// auditSelect is the row shape shared by the page and the export.
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
	// Clamp to the last page rather than answer empty, as the catalog does.
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

// AuditExport streams the whole log to emit one row at a time, so the
// unbounded table never accumulates in memory, and returns the count emitted.
// No statement timeout on purpose: a cut-off export would look complete.

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
