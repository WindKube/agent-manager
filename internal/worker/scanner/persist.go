package scanner

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/scanner/checks"
)

// maxDetailBytes bounds a finding's prose. The rule's own text is ours, but the
// matched values appended to it are the bundle's, so the column's size is not
// something an archive gets to choose.
const maxDetailBytes = 4000

// record is the one transaction the scan hangs on: the `scan` row, every
// `scan_check` row, every `finding`, every `finding_evidence` row, the
// version's verdict and the audit row land together or not at all — a
// partial write here is a finding with no scan behind it, or a flagged
// version whose findings did not land.
//
// It is also where idempotency is finally enforced: the pre-flight guard can
// be passed by two concurrent deliveries, but `unique (version_id,
// pack_version)` can be satisfied by only one, and `on conflict do nothing`
// turns the loser into a no-op rather than an error.
func (w *Worker) record(ctx context.Context, job Job, result analysis, started time.Time) (Outcome, error) {
	verdict := verdictOf(result)
	outcome := Outcome{
		Verdict:  verdict,
		Checks:   result.checks,
		Findings: result.findings,
		TimedOut: result.timedOut,
	}

	finished := time.Now().UTC()
	scan := &models.Scan{
		ID:          models.NewID(),
		VersionID:   job.VersionID,
		PackVersion: w.pack.Version(),
		StartedAt:   started.UTC(),
		FinishedAt:  &finished,
		Verdict:     verdict,
		TimedOut:    result.timedOut,
		UpdatedAt:   finished,
	}

	err := w.deps.DB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewInsert().Model(scan).
			On("conflict (version_id, pack_version) do nothing").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("record the scan of %s: %w", job, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("record the scan of %s: %w", job, err)
		}
		if affected != 1 {
			// Another delivery of this job committed first; writing a second
			// set would double every finding in the reviewer's list.
			return nil
		}
		outcome.Recorded = true
		outcome.ScanID = scan.ID

		if err := insertChecks(ctx, tx, scan.ID, result.checks); err != nil {
			return err
		}
		if err := insertFindings(ctx, tx, scan.ID, job.VersionID, result.findings); err != nil {
			return err
		}
		if err := w.setVerdict(ctx, tx, job, verdict); err != nil {
			return err
		}
		return writeScanAudit(ctx, tx, scanText(job, w.pack.Version(), result, verdict))
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// setVerdict moves the version's verdict, the only column on `version` this
// role may write — `grant update ("verdict")` and nothing else, because the
// scanner does not produce bundle bytes and must not be able to forge a
// digest or an object key.
//
// Two guards: a `rejected` version is left alone, since rejection is a
// reviewer's decision a rescan must not resurrect to `clean`; and a timed-out
// scan writes no verdict at all, since a timeout must never resolve to clean.
func (w *Worker) setVerdict(ctx context.Context, tx bun.IDB, job Job, verdict models.Verdict) error {
	if verdict == models.VerdictScanning {
		return nil
	}
	if _, err := tx.NewUpdate().Model((*models.Version)(nil)).
		Set("verdict = ?", verdict).
		Where("id = ? and verdict <> ?", job.VersionID, models.VerdictRejected).
		Exec(ctx); err != nil {
		return fmt.Errorf("set the verdict of %s: %w", job, err)
	}
	return nil
}

// insertChecks writes one row per registered check, including passes: the
// absence of a finding and the absence of a check are different facts, and a
// matrix that only carried failures could not tell them apart.
func insertChecks(ctx context.Context, tx bun.IDB, scanID uuid.UUID, runs []checks.CheckRun) error {
	if len(runs) == 0 {
		return nil
	}
	rows := make([]models.ScanCheck, 0, len(runs))
	for _, run := range runs {
		result := models.CheckResult(run.Result.Outcome)
		if !result.Valid() {
			return fmt.Errorf("check %s reported result %q, which the schema does not allow",
				run.CheckID, run.Result.Outcome)
		}
		rows = append(rows, models.ScanCheck{
			ScanID:    scanID,
			CheckID:   run.CheckID,
			Label:     run.Label,
			Result:    result,
			WarnCount: countAsInt32(run.Result.WarnCount),
		})
	}
	if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
		return fmt.Errorf("write the check results of scan %s: %w", scanID, err)
	}
	return nil
}

// insertFindings writes the findings and their evidence. Every finding is
// `open`: a rescan that raises a finding on an approved version reopens it,
// since the approval is an `override` row keyed to the old finding and
// carrying that state across would be an approval of something nobody read.
func insertFindings(ctx context.Context, tx bun.IDB, scanID, versionID uuid.UUID, findings []checks.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	rows := make([]models.Finding, 0, len(findings))
	evidence := make([]models.FindingEvidence, 0, len(findings))
	for _, finding := range findings {
		severity := models.FindingSeverity(finding.Severity)
		if !severity.Valid() {
			return fmt.Errorf("finding %s has severity %q, which the schema does not allow",
				finding.RuleID, finding.Severity)
		}

		id := models.NewID()
		primary := finding.Primary()
		row := models.Finding{
			ID:            id,
			ScanID:        scanID,
			VersionID:     versionID,
			RuleID:        finding.RuleID,
			Severity:      severity,
			Title:         finding.Title,
			Detail:        truncate(finding.Detail, maxDetailBytes),
			EvidencePath:  primary.Path,
			EvidenceQuote: primary.Quote,
			State:         models.FindingStateOpen,
		}
		if primary.Line > 0 {
			line := countAsInt32(primary.Line)
			row.EvidenceLine = &line
		}
		rows = append(rows, row)

		for _, location := range finding.Evidence {
			role := models.EvidenceRolePrimary
			if location.Supporting {
				role = models.EvidenceRoleSupporting
			}
			evidenceRow := models.FindingEvidence{
				ID:        models.NewID(),
				FindingID: id,
				Path:      location.Path,
				Quote:     location.Quote,
				Role:      role,
			}
			if location.Line > 0 {
				line := countAsInt32(location.Line)
				evidenceRow.Line = &line
			}
			evidence = append(evidence, evidenceRow)
		}
	}

	if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
		return fmt.Errorf("write the findings of scan %s: %w", scanID, err)
	}
	if len(evidence) > 0 {
		if _, err := tx.NewInsert().Model(&evidence).Exec(ctx); err != nil {
			return fmt.Errorf("write the finding evidence of scan %s: %w", scanID, err)
		}
	}
	return nil
}

// countAsInt32 fits a count derived from bundle content into the column's
// width. The clamp is unreachable in practice, but "in practice" is not a
// guarantee about attacker-supplied input: a line number from a huge file
// must saturate rather than wrap into a negative one.
func countAsInt32(n int) int32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n)
	}
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut] + "…"
}
