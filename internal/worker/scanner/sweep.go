package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"agent-manager/internal/store/models"
)

// maxSweepVersions bounds one sweep: a package with three hundred published
// versions must not turn one publish into a job that runs for an hour. The
// bound costs nothing, since every rescan it skips is a no-op on the next
// sweep and the next publish sweeps again.
const maxSweepVersions = 50

// Sweeper works one `rescan-sweep` job. `am_scanner` holds no grant on
// `outbox` — deliberately, it is not a producer of work — so this handler
// cannot enqueue per-version scan jobs; it performs them instead, in-process,
// through the same handler a queued scan goes through. The only enqueue in
// this story is the `rescan-sweep` row the fetcher's publish transaction
// writes.
type Sweeper struct {
	river.WorkerDefaults[SweepJob]

	worker *Worker
}

// NewSweeper builds the rescan handler over an existing scan handler, so a sweep
// and a queued scan cannot diverge in what they write.
func NewSweeper(w *Worker) *Sweeper { return &Sweeper{worker: w} }

// Timeout is River's per-job budget for a sweep.
func (s *Sweeper) Timeout(*river.Job[SweepJob]) time.Duration { return sweepTimeout }

// Work runs one sweep.
func (s *Sweeper) Work(ctx context.Context, job *river.Job[SweepJob]) error {
	_, err := s.Sweep(ctx, job.Args)
	return err
}

// SweepOutcome is what one sweep did.
type SweepOutcome struct {
	// Enabled is the org policy's answer. A disabled policy is not a failure —
	// it is the operator's setting, and the sweep says so rather than looking
	// like it found nothing to do.
	Enabled   bool
	Examined  int
	Rescanned int
	Flagged   int
	Failed    int
}

// Sweep rescans the package's other versions under the running rule pack:
// every visible version with committed bytes that has no scan at the running
// pack version, not only already-approved ones — otherwise a flagged version
// nobody has triaged stays judged by rules the pack has since replaced. The
// per-version guard is the same idempotency key as everywhere else, so a
// package whose versions are all current is a sweep that reads one query and
// stops.
func (s *Sweeper) Sweep(ctx context.Context, job SweepJob) (SweepOutcome, error) {
	log := s.worker.deps.Log.With().
		Str("job", "rescan-sweep").
		Str("package", job.String()).
		Str("pack_version", s.worker.pack.Version()).
		Logger()

	if err := job.Validate(); err != nil {
		return SweepOutcome{}, river.JobCancel(err)
	}

	enabled, err := s.rescanEnabled(ctx)
	if err != nil {
		return SweepOutcome{}, err
	}
	if !enabled {
		log.Debug().Msg("rescan-on-new-version is off; nothing to sweep")
		return SweepOutcome{}, nil
	}

	candidates, err := s.candidates(ctx, job)
	if err != nil {
		return SweepOutcome{}, err
	}

	outcome := SweepOutcome{Enabled: true, Examined: len(candidates)}
	for _, candidate := range candidates {
		// A sweep is best effort per version: one unreadable bundle must not
		// stop the rest of the package from being rescanned. lastAttempt is
		// false, so a version whose scan runs out of budget records nothing.
		result, scanErr := s.worker.scan(ctx, candidate, false)
		switch {
		case scanErr != nil:
			outcome.Failed++
			log.Error().Err(scanErr).Str("version", candidate.String()).Msg("rescan failed")
		case result.Recorded:
			outcome.Rescanned++
			if result.Verdict == models.VerdictFlagged {
				outcome.Flagged++
			}
		}
	}

	event := log.Info()
	if outcome.Flagged > 0 {
		event = log.Warn()
	}
	event.
		Int("examined", outcome.Examined).
		Int("rescanned", outcome.Rescanned).
		Int("flagged", outcome.Flagged).
		Int("failed", outcome.Failed).
		Msg("rescan sweep complete")

	if outcome.Failed > 0 {
		// The job fails so River retries what did not work; the versions that
		// did rescan are no-ops on the retry.
		return outcome, fmt.Errorf("rescan sweep of %s: %d of %d versions failed",
			job, outcome.Failed, outcome.Examined)
	}
	return outcome, nil
}

// rescanEnabled reads the org policy. The scanner reads it, not the fetcher,
// because `am_scanner` holds the grant on `org_policy` and `am_fetcher` does
// not — the role that can read the policy is the role that decides on it.
func (s *Sweeper) rescanEnabled(ctx context.Context) (bool, error) {
	var enabled bool
	err := s.worker.deps.DB.QueryRowContext(ctx,
		`select rescan_on_new_version from org_policy where id = ?`,
		models.OrgPolicySingletonID).Scan(&enabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, errNoPolicy
	case err != nil:
		return false, fmt.Errorf("read the rescan policy: %w", err)
	}
	return enabled, nil
}

// candidates is the package's versions that the running pack has not judged.
func (s *Sweeper) candidates(ctx context.Context, job SweepJob) ([]Job, error) {
	// bun formats raw SQL with `?` and passes no arguments to the driver, so a `$1`
	// here would reach Postgres unbound.
	rows, err := s.worker.deps.DB.QueryContext(ctx,
		`select v.id, v.semver, v.object_key, p.namespace, p.name
		   from version v
		   join package p on p.id = v.package_id
		  where v.package_id = ?
		    and v.id <> ?
		    and v.digest is not null
		    and v.visible
		    and not exists (
		          select 1 from scan s
		           where s.version_id = v.id and s.pack_version = ?
		        )
		  order by v.semver_sort desc
		  limit ?`,
		job.PackageID, job.TriggerVersionID, s.worker.pack.Version(), maxSweepVersions)
	if err != nil {
		return nil, fmt.Errorf("read the versions of %s to rescan: %w", job, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Job
	for rows.Next() {
		var (
			candidate Job
			id        uuid.UUID
		)
		if err := rows.Scan(&id, &candidate.Semver, &candidate.ObjectKey,
			&candidate.Namespace, &candidate.Name); err != nil {
			return nil, fmt.Errorf("read a version of %s to rescan: %w", job, err)
		}
		candidate.VersionID = id
		candidate.PackageID = job.PackageID
		out = append(out, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the versions of %s to rescan: %w", job, err)
	}
	return out, nil
}

// errNoPolicy is here so a missing singleton reads as the configuration failure it
// is rather than as "rescan is off".
var errNoPolicy = errors.New("org_policy holds no row with id 1")
