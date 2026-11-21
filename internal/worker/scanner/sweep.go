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

// maxSweepVersions keeps one publish from turning into an hour-long sweep.
const maxSweepVersions = 50

// Sweeper works one `rescan-sweep` job. `am_scanner` holds no grant on
// `outbox`, so it runs the per-version scans in-process instead of enqueuing them.
type Sweeper struct {
	river.WorkerDefaults[SweepJob]

	worker *Worker
}

// NewSweeper builds the rescan handler over an existing scan handler.
func NewSweeper(w *Worker) *Sweeper { return &Sweeper{worker: w} }

// Timeout is River's per-job budget.
func (s *Sweeper) Timeout(*river.Job[SweepJob]) time.Duration { return sweepTimeout }

// Work runs one sweep.
func (s *Sweeper) Work(ctx context.Context, job *river.Job[SweepJob]) error {
	_, err := s.Sweep(ctx, job.Args)
	return err
}

// SweepOutcome summarises one sweep.
type SweepOutcome struct {
	// Enabled is the org policy's answer; a disabled policy is not a failure.
	Enabled   bool
	Examined  int
	Rescanned int
	Flagged   int
	Failed    int
}

// Sweep rescans every visible, committed version of the package that has no
// scan at the running fingerprint, not only approved ones.
func (s *Sweeper) Sweep(ctx context.Context, job SweepJob) (SweepOutcome, error) {
	log := s.worker.deps.Log.With().
		Str("job", "rescan-sweep").
		Str("package", job.String()).
		Str("pack_version", s.worker.Fingerprint(ctx)).
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
		// Best effort per version: one unreadable bundle must not stop the rest.
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
		return outcome, fmt.Errorf("rescan sweep of %s: %d of %d versions failed",
			job, outcome.Failed, outcome.Examined)
	}
	return outcome, nil
}

// rescanEnabled is read here rather than in the fetcher because only
// `am_scanner` holds the grant on `org_policy`.
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

func (s *Sweeper) candidates(ctx context.Context, job SweepJob) ([]Job, error) {
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
		job.PackageID, job.TriggerVersionID, s.worker.Fingerprint(ctx), maxSweepVersions)
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

// errNoPolicy makes a missing singleton a configuration failure rather than "rescan is off".
var errNoPolicy = errors.New("org_policy holds no row with id 1")
