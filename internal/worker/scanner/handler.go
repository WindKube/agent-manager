package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"agent-manager/internal/bundle"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/rules"
)

// Outcome is what one scan produced. It is returned rather than only logged so a
// test asserts on the verdict the handler reached rather than on a log line.
type Outcome struct {
	// Recorded is false for a redelivery that did nothing; delivery is
	// at-least-once, so this is the normal outcome of a duplicate, not an error.
	Recorded bool
	ScanID   uuid.UUID
	Verdict  models.Verdict
	Checks   []checks.CheckRun
	Findings []checks.Finding
	TimedOut bool
	Duration time.Duration
}

// errBudgetExceeded is the scan clock, separate from a cancelled caller: a
// shutdown is not a statement about the bundle.
var errBudgetExceeded = errors.New("scan exceeded its budget")

// Scan runs the whole pipeline for one job.
func (w *Worker) Scan(ctx context.Context, job Job, lastAttempt bool) error {
	_, err := w.scan(ctx, job, lastAttempt)
	return err
}

func (w *Worker) scan(ctx context.Context, job Job, lastAttempt bool) (Outcome, error) {
	log := w.deps.Log.With().
		Str("job", "scan").
		Str("version", job.String()).
		Str("pack_version", w.pack.Version()).
		Logger()

	if err := job.Validate(); err != nil {
		// A payload that names nothing will name nothing on the fourth attempt
		// either, so the retries are cancelled rather than burned.
		return Outcome{}, river.JobCancel(err)
	}

	// The idempotency guard is answered by the data, not the queue: a version
	// with a scan at the running pack version has already been scanned by
	// these rules, and static analysis of immutable bytes cannot reach a
	// different verdict.
	already, err := outbox.Delivered(ctx, w.deps.DB, outbox.Job{
		Kind: outbox.KindScan, SubjectID: job.VersionID, SubjectVersion: w.pack.Version(),
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("scan %s: %w", job, err)
	}
	if already {
		log.Info().Msg("scan redelivered for a version already scanned at this rule-pack version; nothing to do")
		return Outcome{}, nil
	}

	key, err := w.objectKey(ctx, job)
	if err != nil {
		return Outcome{}, err
	}

	started := time.Now()
	result, err := w.analyse(ctx, key)
	elapsed := time.Since(started)

	if errors.Is(err, errBudgetExceeded) {
		// A scan that ran out of time is retried with backoff and never
		// resolves to `clean`. The row that records the timeout is written
		// only when there is no retry left, since writing it earlier would key
		// a `scan` row that the guard above would then suppress the retry
		// against.
		log.Error().Dur("elapsed", elapsed).Bool("last_attempt", lastAttempt).
			Msg("scan exceeded its budget")
		if !lastAttempt {
			return Outcome{TimedOut: true, Duration: elapsed}, err
		}
		outcome, recordErr := w.record(ctx, job, analysis{timedOut: true}, started)
		if recordErr != nil {
			return Outcome{}, recordErr
		}
		outcome.Duration = elapsed
		return outcome, err
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("scan %s: %w", job, err)
	}

	result, err = w.applyCommunityReview(ctx, job, result)
	if err != nil {
		return Outcome{}, err
	}

	outcome, err := w.record(ctx, job, result, started)
	if err != nil {
		return Outcome{}, err
	}
	outcome.Duration = elapsed

	event := log.Info()
	if outcome.Verdict == models.VerdictFlagged {
		event = log.Warn()
	}
	event.
		Str("verdict", string(outcome.Verdict)).
		Int("findings", len(outcome.Findings)).
		Int("checks", len(outcome.Checks)).
		Dur("elapsed", elapsed).
		Bool("recorded", outcome.Recorded).
		Msg("scan complete")
	return outcome, nil
}

// analysis is what the check registry produced for one bundle.
type analysis struct {
	checks   []checks.CheckRun
	findings []checks.Finding
	timedOut bool
}

// analyse reads the bundle and runs the checks. Nothing in it writes.
func (w *Worker) analyse(ctx context.Context, key string) (analysis, error) {
	// The budget is a context deadline rather than a watchdog, so every step
	// below honours it: the blob read, the decompression and the checks.
	ctx, cancel := context.WithTimeout(ctx, w.budget)
	defer cancel()

	tree, err := w.read(ctx, key)
	if err != nil {
		return analysis{}, w.classifyClock(ctx, err)
	}

	inspected, err := checks.Inspect(tree)
	if err != nil {
		return analysis{}, w.classifyClock(ctx, err)
	}

	runs, findings, err := w.registry.Run(ctx, inspected, w.pack)
	if err != nil {
		return analysis{}, w.classifyClock(ctx, err)
	}
	return analysis{checks: runs, findings: findings}, nil
}

// classifyClock separates "the scan ran out of its own budget" from "the
// process is shutting down". The second is not a statement about the bundle
// and must reach River as the cancellation it is.
func (w *Worker) classifyClock(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w of %s: %w", errBudgetExceeded, w.budget, err)
	}
	return err
}

// read pulls the stored bundle and unpacks it. bundle.Unpack re-applies the
// extraction caps here, because a bundle read out of object storage is still
// bytes off a network.
func (w *Worker) read(ctx context.Context, key string) (*bundle.Bundle, error) {
	reader, err := w.deps.BlobRead.NewReader(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read the bundle at %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	tree, err := bundle.Unpack(ctx, reader, w.limits)
	if err != nil {
		return nil, fmt.Errorf("unpack the bundle at %s: %w", key, err)
	}
	return tree, nil
}

// objectKey resolves which bytes to read. The payload's key wins when it has
// one, since it names the object the publish committed; a rescan carries
// none, so it comes off the version row instead.
func (w *Worker) objectKey(ctx context.Context, job Job) (string, error) {
	var (
		key       sql.NullString
		committed bool
	)
	err := w.deps.DB.QueryRowContext(ctx,
		`select object_key, digest is not null from version where id = ?`, job.VersionID).
		Scan(&key, &committed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The publish writes the version row and the outbox row in one
		// transaction, so a job whose row is missing is a payload that no
		// longer describes anything, not a race.
		return "", river.JobCancel(fmt.Errorf("scan %s: no version row %s", job, job.VersionID))
	case err != nil:
		return "", fmt.Errorf("scan %s: read version %s: %w", job, job.VersionID, err)
	case !committed:
		// A version with no digest has no committed bytes: either a rolled-back
		// publish or a fetch that never landed, neither a finding about the
		// package.
		return "", river.JobCancel(fmt.Errorf("scan %s: version %s has no committed bytes", job, job.VersionID))
	}

	if job.ObjectKey != "" {
		return job.ObjectKey, nil
	}
	if !key.Valid || key.String == "" {
		return "", river.JobCancel(fmt.Errorf("scan %s: version %s carries no object key", job, job.VersionID))
	}
	return key.String, nil
}

// verdictOf: a version with a finding is `flagged`, a version with none is
// `clean`. A warning-only scan is flagged too, since letting a medium finding
// pass unlooked-at would make the findings list a place things go to be
// ignored; `warn-with-override` is the gate for distributing it anyway.
// `rejected` is never written here — it's a reviewer's decision.
// communityReviewRuleID marks the synthetic finding applyCommunityReview
// raises. It is not a rule-pack id: this is organisation policy about the
// publisher, not the bytes.
const communityReviewRuleID = "ORG-COMMUNITY-REVIEW"

// applyCommunityReview flags a version from a non-verified publisher when the
// organisation's policy requires it, by raising a flagged finding a
// scanner-reviewer must approve — there is no separate review-queue state in
// the schema. A missing policy row is treated as the policy being off, so an
// ordinary scan still completes against a database with no policy row at all.
func (w *Worker) applyCommunityReview(ctx context.Context, job Job, result analysis) (analysis, error) {
	var needsReview bool
	err := w.deps.DB.QueryRowContext(ctx,
		`select community_needs_review from org_policy where id = ?`,
		models.OrgPolicySingletonID).Scan(&needsReview)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return result, nil
	case err != nil:
		return analysis{}, fmt.Errorf("read the community-review policy for %s: %w", job, err)
	}
	if !needsReview {
		return result, nil
	}

	var verified bool
	err = w.deps.DB.QueryRowContext(ctx,
		`select pub.verified from package pkg join publisher pub on pub.id = pkg.publisher_id where pkg.id = ?`,
		job.PackageID).Scan(&verified)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The publish writes package and publisher rows before any scan is
		// enqueued, so a missing join is a payload retrying cannot fix.
		return analysis{}, river.JobCancel(fmt.Errorf("scan %s: no package row %s", job, job.PackageID))
	case err != nil:
		return analysis{}, fmt.Errorf("read the publisher for %s: %w", job, err)
	}
	if verified {
		return result, nil
	}

	result.findings = append(result.findings, checks.Finding{
		RuleID:   communityReviewRuleID,
		Severity: rules.SeverityMedium,
		Title:    "Community source pending review",
		Detail: "This package's publisher is not verified, and organisation policy requires " +
			"community sources to be reviewed before they are treated as distributable.",
	})
	return result, nil
}

func verdictOf(result analysis) models.Verdict {
	switch {
	case result.timedOut:
		return models.VerdictScanning
	case len(result.findings) > 0:
		return models.VerdictFlagged
	default:
		return models.VerdictClean
	}
}
