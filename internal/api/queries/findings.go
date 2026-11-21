package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// Scanner summary window bounds; an unbounded window is a full table scan.
const (
	DefaultScannerPeriodDays = 30
	MaxScannerPeriodDays     = 365
)

// scannerSummarySQL is one round trip of independent scalar subqueries.
// `quarantined` counts only latest visible versions, since a superseded one
// exposes no profile. The median runs from scan start, not version creation,
// so queue latency isn't reported as scan time.
const scannerSummarySQL = `
select
  (select count(distinct scn.version_id)
     from scan as scn
    where scn.finished_at is not null
      and scn.finished_at >= now() - make_interval(days => ?)),
  (select count(*)
     from package as pkg
     join version as ver on ver.id = pkg.latest_version_id and ver.visible
    where ver.verdict = 'flagged'),
  (select count(*)
     from override as ovr
     join finding as fnd on fnd.id = ovr.finding_id
    where fnd.state = 'approved'
      and (ovr.expires_at is null or ovr.expires_at > now())),
  (select min(ovr.expires_at)
     from override as ovr
     join finding as fnd on fnd.id = ovr.finding_id
    where fnd.state = 'approved'
      and ovr.expires_at > now()),
  (select percentile_cont(0.5) within group (
            order by extract(epoch from (scn.finished_at - scn.started_at)))
     from scan as scn
    where scn.finished_at is not null
      and scn.finished_at >= now() - make_interval(days => ?))`

// ScannerSummary answers the Scanner screen's headline card.
func ScannerSummary(ctx context.Context, db bun.IDB, periodDays int) (contract.ScannerSummary, error) {
	if periodDays < 1 {
		periodDays = DefaultScannerPeriodDays
	}
	if periodDays > MaxScannerPeriodDays {
		periodDays = MaxScannerPeriodDays
	}

	out := contract.ScannerSummary{PeriodDays: periodDays}
	// Nullable: "no scans yet" is not zero.
	var (
		expiry sql.NullTime
		median sql.NullFloat64
	)
	err := db.QueryRowContext(ctx, scannerSummarySQL, periodDays, periodDays).Scan(
		&out.VersionsScanned, &out.Quarantined, &out.OverridesActive, &expiry, &median)
	if err != nil {
		return contract.ScannerSummary{}, fmt.Errorf("read the scanner summary: %w", err)
	}
	if expiry.Valid {
		at := expiry.Time.UTC()
		out.NearestExpiry = &at
	}
	if median.Valid {
		out.MedianSeconds = &median.Float64
	}
	return out, nil
}

// FindingFilter is one findings-list request. Empty State and Severity mean all.
type FindingFilter struct {
	State    models.FindingState
	Severity models.FindingSeverity
	Page     int
	PageSize int
	// Principal is whose readability applies: findings quote bundle contents,
	// so an unfiltered list would leak private packages.
	Principal auth.Principal
	// EveryPackage lifts that filter for a caller who may decide findings, so
	// no private package escapes review.
	EveryPackage bool
}

// The findings page size and its cap.
const (
	DefaultFindingsPageSize = 20
	MaxFindingsPageSize     = 100
)

func (f FindingFilter) normalise() FindingFilter {
	switch f.State {
	case models.FindingStateOpen, models.FindingStateApproved, models.FindingStateRejected:
	default:
		f.State = ""
	}
	switch f.Severity {
	case models.FindingSeverityLow, models.FindingSeverityMedium, models.FindingSeverityHigh:
	default:
		f.Severity = ""
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = DefaultFindingsPageSize
	}
	if f.PageSize > MaxFindingsPageSize {
		f.PageSize = MaxFindingsPageSize
	}
	return f
}

// findingFrom is the relation every findings statement reads; the subject
// is joined through `package` so it renders `namespace/name@semver`.
const findingFrom = `
from finding as fnd
join version as ver on ver.id = fnd.version_id
join package as pkg on pkg.id = ver.package_id`

// findingOrder is severity first (enum order), then newest. The alias
// qualification matters: a bare `order by severity` binds to the ::text
// output column and sorts alphabetically.
const findingOrder = `order by fnd.severity desc, fnd.created_at desc, fnd.id`

func (f FindingFilter) predicates() *predicates {
	p := &predicates{}
	if f.State != "" {
		p.add("fnd.state = ?", f.State)
	}
	if f.Severity != "" {
		p.add("fnd.severity = ?", f.Severity)
	}
	if !f.EveryPackage {
		readable, args := PackageReadable("pkg", f.Principal)
		p.add(readable, args...)
	}
	return p
}

func Findings(ctx context.Context, db bun.IDB, filter FindingFilter) (contract.FindingsPage, error) {
	filter = filter.normalise()
	where := filter.predicates()

	total, err := findingCount(ctx, db, where)
	if err != nil {
		return contract.FindingsPage{}, err
	}

	if pages := (total + filter.PageSize - 1) / filter.PageSize; total > 0 && filter.Page > pages {
		filter.Page = pages
	}

	query := `
select
  fnd.id,
  fnd.rule_id,
  fnd.engine,
  fnd.severity::text,
  fnd.state::text,
  fnd.title,
  coalesce(fnd.detail, ''),
  pkg.namespace || '/' || pkg.name,
  ver.semver,
  ver.verdict::text,
  fnd.created_at,
  coalesce(fnd.evidence_path, ''),
  fnd.evidence_line` + findingFrom + `
` + where.where() + `
` + findingOrder + `
limit ? offset ?`

	args := append([]any{}, where.args...)
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return contract.FindingsPage{}, fmt.Errorf("read the findings page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	page := contract.FindingsPage{
		Findings: []contract.FindingSummary{},
		Total:    total,
		Page:     filter.Page,
		PageSize: filter.PageSize,
	}
	for rows.Next() {
		var (
			entry contract.FindingSummary
			line  sql.NullInt32
		)
		if err := rows.Scan(&entry.ID, &entry.RuleID, &entry.Engine, &entry.Severity, &entry.State, &entry.Title,
			&entry.Detail, &entry.PackageID, &entry.Version, &entry.Verdict, &entry.RaisedAt,
			&entry.EvidencePath, &line); err != nil {
			return contract.FindingsPage{}, fmt.Errorf("scan a findings row: %w", err)
		}
		entry.EvidenceLine = lineOf(line)
		page.Findings = append(page.Findings, entry)
	}
	if err := rows.Err(); err != nil {
		return contract.FindingsPage{}, fmt.Errorf("read the findings page: %w", err)
	}
	return page, nil
}

func findingCount(ctx context.Context, db bun.IDB, where *predicates) (int, error) {
	// findingFrom, not a bare `from finding`: the readability predicate needs
	// `package`, and the count must match the page.
	var total int
	query := "select count(*)" + findingFrom + "\n" + where.where()
	if err := db.QueryRowContext(ctx, query, where.args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count the findings: %w", err)
	}
	return total, nil
}

// findingDetailSQL is the header of the detail pane, in one round trip.
const findingDetailSQL = `
select
  fnd.id,
  fnd.rule_id,
  fnd.engine,
  fnd.severity::text,
  fnd.state::text,
  fnd.title,
  coalesce(fnd.detail, ''),
  pkg.namespace || '/' || pkg.name,
  ver.semver,
  ver.verdict::text,
  fnd.created_at,
  scn.pack_version,
  scn.started_at,
  scn.finished_at,
  scn.verdict::text,
  scn.timed_out,
  ovr.finding_id is not null,
  coalesce(nullif(idt.email, ''), idt.subject, ''),
  coalesce(ovr.note, ''),
  ovr.expires_at,
  ovr.created_at` + findingFrom + `
join scan as scn on scn.id = fnd.scan_id
left join override as ovr on ovr.finding_id = fnd.id
left join identity as idt on idt.id = ovr.reviewer_identity_id
where fnd.id = ? and %s`

// Finding answers the detail pane: the header, every check the scan ran and
// every evidence location, sequentially since each is a cheap index lookup.
func Finding(ctx context.Context, db bun.IDB, id uuid.UUID, p auth.Principal, everyPackage bool) (contract.FindingDetail, error) {
	var (
		out       contract.FindingDetail
		scan      contract.FindingScan
		finished  sql.NullTime
		hasOvr    bool
		reviewer  string
		note      string
		expires   sql.NullTime
		decidedAt sql.NullTime
	)
	readable, readableArgs := PackageReadable("pkg", p)
	if everyPackage {
		readable, readableArgs = "true", nil
	}
	err := db.QueryRowContext(ctx, fmt.Sprintf(findingDetailSQL, readable),
		append([]any{id}, readableArgs...)...).Scan(
		&out.ID, &out.RuleID, &out.Engine, &out.Severity, &out.State, &out.Title, &out.Detail,
		&out.PackageID, &out.Version, &out.Verdict, &out.RaisedAt,
		&scan.PackVersion, &scan.StartedAt, &finished, &scan.Verdict, &scan.TimedOut,
		&hasOvr, &reviewer, &note, &expires, &decidedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.FindingDetail{}, ErrNotFound
	case err != nil:
		return contract.FindingDetail{}, fmt.Errorf("read finding %s: %w", id, err)
	}
	if finished.Valid {
		at := finished.Time.UTC()
		scan.FinishedAt = &at
	}
	out.Scan = scan
	if hasOvr {
		override := contract.FindingOverride{Reviewer: reviewer, Note: note}
		if expires.Valid {
			at := expires.Time.UTC()
			override.ExpiresAt = &at
		}
		if decidedAt.Valid {
			override.DecidedAt = decidedAt.Time.UTC()
		}
		out.Override = &override
	}

	if out.Checks, err = findingChecks(ctx, db, id); err != nil {
		return contract.FindingDetail{}, err
	}
	if out.Evidence, err = findingEvidence(ctx, db, id); err != nil {
		return contract.FindingDetail{}, err
	}
	return out, nil
}

// findingChecks reads every check the raising scan ran, passes included, so
// a missing finding is distinguishable from a missing check. Rows share one
// transaction timestamp, so within an engine the order is effectively check_id.
func findingChecks(ctx context.Context, db bun.IDB, id uuid.UUID) ([]contract.FindingCheck, error) {
	const query = `
select schk.check_id, schk.engine, schk.label, schk.explain, schk.result::text, schk.warn_count
from scan_check as schk
join finding as fnd on fnd.scan_id = schk.scan_id
where fnd.id = ?
order by schk.engine, schk.created_at, schk.check_id`

	rows, err := db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("read the checks behind finding %s: %w", id, err)
	}
	defer func() { _ = rows.Close() }()

	checks := []contract.FindingCheck{}
	for rows.Next() {
		var check contract.FindingCheck
		if err := rows.Scan(&check.CheckID, &check.Engine, &check.Label, &check.Explain,
			&check.Result, &check.WarnCount); err != nil {
			return nil, fmt.Errorf("scan a check row: %w", err)
		}
		checks = append(checks, check)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the checks behind finding %s: %w", id, err)
	}
	return checks, nil
}

// findingEvidence reads every location, `primary` first by enum order.
func findingEvidence(ctx context.Context, db bun.IDB, id uuid.UUID) ([]contract.FindingEvidence, error) {
	const query = `
select fev.path, fev.line, coalesce(fev.quote, ''), fev.role::text
from finding_evidence as fev
where fev.finding_id = ?
order by fev.role, fev.path, fev.line`

	rows, err := db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("read the evidence for finding %s: %w", id, err)
	}
	defer func() { _ = rows.Close() }()

	evidence := []contract.FindingEvidence{}
	for rows.Next() {
		var (
			item contract.FindingEvidence
			line sql.NullInt32
		)
		if err := rows.Scan(&item.Path, &line, &item.Quote, &item.Role); err != nil {
			return nil, fmt.Errorf("scan an evidence row: %w", err)
		}
		item.Line = lineOf(line)
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the evidence for finding %s: %w", id, err)
	}
	return evidence, nil
}

func lineOf(line sql.NullInt32) *int {
	if !line.Valid {
		return nil
	}
	number := int(line.Int32)
	return &number
}
