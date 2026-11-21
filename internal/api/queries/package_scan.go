package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// ErrRejected refuses a rejected version's scan detail, just as
// BundleRef.Distributable refuses its bytes.
var ErrRejected = errors.New("this version was rejected and its scan is not served")

// latestScanVersionSQL must match LatestBundle's predicate (bundles.go).
// %s is PackageReadable.
const latestScanVersionSQL = `
select v.id, v.semver, v.verdict::text
from package as pkg
join version as v on v.id = pkg.latest_version_id and v.visible
where pkg.namespace = ? and pkg.name = ? and %s`

// PackageScan answers the package detail's security section: the latest
// visible version's scan, its findings and any reviewer decisions.
func PackageScan(ctx context.Context, db bun.IDB, p auth.Principal, namespace, name string) (contract.PackageScan, error) {
	var (
		versionID string
		verdict   models.Verdict
		out       contract.PackageScan
	)
	out.Checks = []contract.FindingCheck{}
	out.Findings = []contract.PackageScanFinding{}

	readable, readableArgs := PackageReadable("pkg", p)
	args := append([]any{namespace, name}, readableArgs...)
	err := db.QueryRowContext(ctx, fmt.Sprintf(latestScanVersionSQL, readable), args...).
		Scan(&versionID, &out.Version, &verdict)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contract.PackageScan{}, ErrNotFound
	case err != nil:
		return contract.PackageScan{}, fmt.Errorf("locate the latest version of %s/%s: %w", namespace, name, err)
	}
	if verdict == models.VerdictRejected {
		return contract.PackageScan{}, ErrRejected
	}

	scanID, err := packageScanRow(ctx, db, versionID, &out.Scan)
	switch {
	case errors.Is(err, ErrNotFound):
		// Never scanned: a version can be visible before its scan lands.
		return out, nil
	case err != nil:
		return contract.PackageScan{}, err
	}
	out.Scanned = true

	if out.Checks, err = packageScanChecks(ctx, db, scanID); err != nil {
		return contract.PackageScan{}, err
	}
	if out.Findings, err = packageScanFindings(ctx, db, scanID); err != nil {
		return contract.PackageScan{}, err
	}
	return out, nil
}

// packageScanRow reads a version's latest scan (rescans add more) into scan
// and returns its id.
func packageScanRow(ctx context.Context, db bun.IDB, versionID string, scan *contract.FindingScan) (string, error) {
	const query = `
select id, pack_version, started_at, finished_at, verdict::text, timed_out
from scan
where version_id = ?
order by started_at desc
limit 1`

	var (
		scanID   string
		finished sql.NullTime
	)
	err := db.QueryRowContext(ctx, query, versionID).
		Scan(&scanID, &scan.PackVersion, &scan.StartedAt, &finished, &scan.Verdict, &scan.TimedOut)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", ErrNotFound
	case err != nil:
		return "", fmt.Errorf("read the scan for version %s: %w", versionID, err)
	}
	if finished.Valid {
		at := finished.Time.UTC()
		scan.FinishedAt = &at
	}
	return scanID, nil
}

// packageScanChecks mirrors findingChecks' ordering: one block per engine.
func packageScanChecks(ctx context.Context, db bun.IDB, scanID string) ([]contract.FindingCheck, error) {
	const query = `
select check_id, engine, label, result::text, warn_count
from scan_check
where scan_id = ?
order by engine, created_at, check_id`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("read the checks for scan %s: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	checks := []contract.FindingCheck{}
	for rows.Next() {
		var check contract.FindingCheck
		if err := rows.Scan(&check.CheckID, &check.Engine, &check.Label, &check.Result, &check.WarnCount); err != nil {
			return nil, fmt.Errorf("scan a check row: %w", err)
		}
		checks = append(checks, check)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the checks for scan %s: %w", scanID, err)
	}
	return checks, nil
}

// packageScanFindings reads every finding the scan raised with its override,
// then attaches evidence in one further statement.
func packageScanFindings(ctx context.Context, db bun.IDB, scanID string) ([]contract.PackageScanFinding, error) {
	const query = `
select
  fnd.id, fnd.rule_id, fnd.engine, fnd.severity::text, fnd.state::text, fnd.title,
  coalesce(fnd.detail, ''), fnd.created_at,
  ovr.finding_id is not null,
  coalesce(nullif(idt.email, ''), idt.subject, ''),
  coalesce(ovr.note, ''),
  ovr.expires_at,
  ovr.created_at
from finding as fnd
left join override as ovr on ovr.finding_id = fnd.id
left join identity as idt on idt.id = ovr.reviewer_identity_id
where fnd.scan_id = ?
order by fnd.severity desc, fnd.created_at desc, fnd.id`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("read the findings for scan %s: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	findings := []contract.PackageScanFinding{}
	for rows.Next() {
		var (
			finding   contract.PackageScanFinding
			hasOvr    bool
			reviewer  string
			note      string
			expires   sql.NullTime
			decidedAt sql.NullTime
		)
		if err := rows.Scan(&finding.ID, &finding.RuleID, &finding.Engine, &finding.Severity, &finding.State,
			&finding.Title, &finding.Detail, &finding.RaisedAt,
			&hasOvr, &reviewer, &note, &expires, &decidedAt); err != nil {
			return nil, fmt.Errorf("scan a finding row: %w", err)
		}
		if hasOvr {
			override := contract.FindingOverride{Reviewer: reviewer, Note: note}
			if expires.Valid {
				at := expires.Time.UTC()
				override.ExpiresAt = &at
			}
			if decidedAt.Valid {
				override.DecidedAt = decidedAt.Time.UTC()
			}
			finding.Override = &override
		}
		finding.Evidence = []contract.FindingEvidence{}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the findings for scan %s: %w", scanID, err)
	}

	if err := attachPackageScanEvidence(ctx, db, scanID, findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// attachPackageScanEvidence reads all of the scan's evidence in one statement
// and groups it onto findings in Go.
func attachPackageScanEvidence(ctx context.Context, db bun.IDB, scanID string, findings []contract.PackageScanFinding) error {
	if len(findings) == 0 {
		return nil
	}

	const query = `
select fev.finding_id, fev.path, fev.line, coalesce(fev.quote, ''), fev.role::text
from finding_evidence as fev
join finding as fnd on fnd.id = fev.finding_id
where fnd.scan_id = ?
order by fev.finding_id, fev.role, fev.path, fev.line`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return fmt.Errorf("read the evidence for scan %s: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	byFinding := make(map[string][]contract.FindingEvidence, len(findings))
	for rows.Next() {
		var (
			findingID string
			item      contract.FindingEvidence
			line      sql.NullInt32
		)
		if err := rows.Scan(&findingID, &item.Path, &line, &item.Quote, &item.Role); err != nil {
			return fmt.Errorf("scan an evidence row: %w", err)
		}
		item.Line = lineOf(line)
		byFinding[findingID] = append(byFinding[findingID], item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read the evidence for scan %s: %w", scanID, err)
	}

	for i := range findings {
		if evidence, ok := byFinding[findings[i].ID]; ok {
			findings[i].Evidence = evidence
		}
	}
	return nil
}
