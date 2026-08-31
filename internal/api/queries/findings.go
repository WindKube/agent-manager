package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/store/models"
)

// The Scanner screen's reads (001 US4, 003 T062-T064).
//
// None of these compose the FR-044 predicate, and that is deliberate rather than
// forgotten. Readable() is a predicate over `profile`; a finding hangs off a
// version, and `package.visibility = 'organisation'` is unconditional across the
// whole product today — the catalog's own comment records that `team` and
// `private` are invisible to everyone, publisher included, because the table
// names no owning identity to compare a caller to. There is therefore nothing
// here to scope a finding by, and inventing one would be a guess wearing an
// access check. What IS scoped is the decision: accepting or rejecting a finding
// is a scanner-reviewer act, enforced in the operation (FR-126).
//
// The one scoping choice worth stating: these reads do NOT filter on
// package.visibility. The catalog does, so a flagged package that browse cannot
// show would be quarantined and unreachable — a reviewer who cannot see the
// finding cannot clear it. The governance surface reports what needs a decision;
// the catalog reports what may be adopted.

// ScannerPeriod bounds the summary's window. The design's card says "last 30
// days"; the parameter exists so the caption is read from the answer (FR-121)
// rather than compiled into the screen, and it is capped because the window is a
// caller's choice and an unbounded one turns a bounded aggregate into a full
// scan of a table that grows with every publish.
const (
	DefaultScannerPeriodDays = 30
	MaxScannerPeriodDays     = 365
)

// scannerSummarySQL is one statement of four scalar subqueries.
//
// One statement rather than four round trips, and scalar subqueries rather than a
// join, because the four figures share no relation: two read `scan`, one reads
// the latest-version pointer and one reads `override`. Joining them would
// multiply rows and then need distinct counts to undo it. It is also what lets
// this run on a bun.Tx as well as a pool, unlike Catalog's concurrent pair.
//
// `quarantined` is the LATEST VISIBLE flagged version count and not the flagged
// version count, and the difference is not cosmetic: the representative dataset
// carries three flagged versions while the design's card reads 2, because one of
// them has been superseded by a newer release. Nothing resolves to a superseded
// version, so it quarantines nothing — counting it would report a risk no
// profile is exposed to. `ver.id = pkg.latest_version_id and ver.visible` is the
// same relation the catalog reads, which is what keeps the two screens agreeing
// about what "latest" means.
//
// `rejected` is deliberately NOT counted here. A rejected version is terminal:
// it has had its decision and is never served (FR-029), so it is not awaiting
// one, and the card's note is "blocked from publish ... until a reviewer
// approves or the publisher ships a fix".
//
// The median is the scan's OWN start to its own verdict. The design labels it
// "fetch to verdict" and the schema offers no fetch instant to measure from:
// `version.created_at` is when the registration was accepted, so measuring from
// it would fold queue latency and fetch backoff into a figure captioned as scan
// time — and would move when the queue is busy while the scanner's behaviour is
// unchanged. `percentile_cont` interpolates, which is what makes the answer a
// median of two rows rather than one of them.
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

// ScannerSummary answers the Scanner screen's headline card (001 US4 scenario 1).
func ScannerSummary(ctx context.Context, db bun.IDB, periodDays int) (contract.ScannerSummary, error) {
	if periodDays < 1 {
		periodDays = DefaultScannerPeriodDays
	}
	if periodDays > MaxScannerPeriodDays {
		periodDays = MaxScannerPeriodDays
	}

	out := contract.ScannerSummary{PeriodDays: periodDays}
	// Both nullable: no active override has no nearest expiry, and no finished
	// scan has no median. Neither is zero, and a screen has to be able to tell the
	// difference — "18s" and "no scans yet" are not the same card.
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

// FindingFilter is one findings-list request.
type FindingFilter struct {
	// State and Severity are empty for "every one of them". The screen's default
	// view is the open findings, and it says so by passing the filter: an API that
	// defaulted to open would be applying a filter its caller cannot see and
	// cannot turn off.
	State    models.FindingState
	Severity models.FindingSeverity
	Page     int
	PageSize int
}

// The findings page and its cap, for the same reason the catalog has both: the
// page size arrives from a client and an unbounded one turns a paged read into a
// full dump.
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

// findingFrom is the relation every findings statement reads. The subject is
// spelled out through `package` because a finding's rendered subject is
// `namespace/name@semver`, the same id the catalog renders.
const findingFrom = `
from finding as fnd
join version as ver on ver.id = fnd.version_id
join package as pkg on pkg.id = ver.package_id`

// findingOrder is severity first, then newest.
//
// `fnd.severity desc` sorts by the Postgres enum's declaration order — low,
// medium, high — so descending is high first. It is alias-qualified and NOT cast
// to text, and both halves matter: casting the column to text in the select list
// makes the output column shadow the input, and an unqualified `order by
// severity` would then sort alphabetically (high, low, medium), which is a
// shipped defect this codebase has already had once in package.go.
//
// fnd.id last so a page boundary cannot repeat or drop a row when several
// findings share a severity and an instant — uuid v7 makes the tiebreak creation
// order.
const findingOrder = `order by fnd.severity desc, fnd.created_at desc, fnd.id`

func (f FindingFilter) predicates() *predicates {
	p := &predicates{}
	if f.State != "" {
		p.add("fnd.state = ?", f.State)
	}
	if f.Severity != "" {
		p.add("fnd.severity = ?", f.Severity)
	}
	return p
}

// Findings answers one page of the findings list (T063).
func Findings(ctx context.Context, db bun.IDB, filter FindingFilter) (contract.FindingsPage, error) {
	filter = filter.normalise()
	where := filter.predicates()

	total, err := findingCount(ctx, db, where)
	if err != nil {
		return contract.FindingsPage{}, err
	}

	// A page number that outran the result set is re-read at the last page rather
	// than answered with an empty table, so a stale `page` in a URL after a
	// narrowing filter still shows results. Same rule as the catalog's, and the
	// total is already in hand, so it costs nothing to apply.
	if pages := (total + filter.PageSize - 1) / filter.PageSize; total > 0 && filter.Page > pages {
		filter.Page = pages
	}

	query := `
select
  fnd.id,
  fnd.rule_id,
  fnd.severity::text,
  fnd.state::text,
  fnd.title,
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
		if err := rows.Scan(&entry.ID, &entry.RuleID, &entry.Severity, &entry.State, &entry.Title,
			&entry.PackageID, &entry.Version, &entry.Verdict, &entry.RaisedAt,
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
	// No join: every column the filters read is on `finding` itself, and the
	// subject's relations only decorate a row. Counting through them would be
	// three joins to reach the same number.
	var total int
	query := "select count(*) from finding as fnd\n" + where.where()
	if err := db.QueryRowContext(ctx, query, where.args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("count the findings: %w", err)
	}
	return total, nil
}

// findingDetailSQL is the header of the detail pane: the finding, its subject,
// the scan that raised it and the override that resolved it, in one round trip.
//
// The reviewer's name comes from `identity`, not from the audit row that recorded
// the decision: the override row is the decision, and reading the name off a
// second table would let the two disagree about who decided.
const findingDetailSQL = `
select
  fnd.id,
  fnd.rule_id,
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
where fnd.id = ?`

// Finding answers the detail pane (T064, 001 US4 scenario 2).
//
// Three statements: the header above, every check the scan ran, and every
// evidence location. They are sequential rather than concurrent — each is an
// index lookup on a primary or foreign key returning a handful of rows, and the
// concurrency Catalog and Package need is for statements that scan.
func Finding(ctx context.Context, db bun.IDB, id uuid.UUID) (contract.FindingDetail, error) {
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
	err := db.QueryRowContext(ctx, findingDetailSQL, id).Scan(
		&out.ID, &out.RuleID, &out.Severity, &out.State, &out.Title, &out.Detail,
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

// findingChecks reads EVERY check the raising scan ran, passes included (FR-025).
//
// This is the requirement it is easiest to satisfy wrongly: a pane fed only the
// failing check cannot be told apart from one where nothing else ran, and 001
// US4 scenario 2 asks for "every check that ran with a pass / fail / warn-count
// result" precisely so the absence of a finding is distinguishable from the
// absence of a check. The scan is the relation — not the finding — because a
// check that passed raised nothing and so has no finding to hang off.
//
// The order is the scan's own insertion order, which the runner takes from the
// check registry, so a newly registered check appears in the matrix in its
// registered position with no renderer change. uuid v7 does not help here — the
// primary key is (scan_id, check_id) — so it is `created_at, check_id`, and the
// check_id tiebreak is what keeps a matrix written in one transaction stable
// across two reads.
func findingChecks(ctx context.Context, db bun.IDB, id uuid.UUID) ([]contract.FindingCheck, error) {
	const query = `
select schk.check_id, schk.label, schk.result::text, schk.warn_count
from scan_check as schk
join finding as fnd on fnd.scan_id = schk.scan_id
where fnd.id = ?
order by schk.created_at, schk.check_id`

	rows, err := db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("read the checks behind finding %s: %w", id, err)
	}
	defer func() { _ = rows.Close() }()

	checks := []contract.FindingCheck{}
	for rows.Next() {
		var check contract.FindingCheck
		if err := rows.Scan(&check.CheckID, &check.Label, &check.Result, &check.WarnCount); err != nil {
			return nil, fmt.Errorf("scan a check row: %w", err)
		}
		checks = append(checks, check)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the checks behind finding %s: %w", id, err)
	}
	return checks, nil
}

// findingEvidence reads every location, cause first.
//
// `order by role, path, line` is the order data-model.md fixes, and it is why
// there is no position column: `primary` sorts before `supporting` in the enum's
// declaration order, so the cause leads without a column to maintain.
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
