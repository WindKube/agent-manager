// Package scanner is the `worker scanner` role: it reads stored bundle bytes and
// writes verdicts, check results and findings.
//
// The pipeline: read the bundle -> unpack under the bundle caps -> classify,
// parse, extract -> run the check registry over the rule pack -> one
// transaction writing `scan`, `scan_check`, `finding`, `finding_evidence`, the
// version's verdict and the audit row.
//
// Three constraints shape all of it. It never writes bundle bytes: Needs
// declares Blob: AccessRead, so the bootstrap constructs no blob.Writer for
// this role, and New refuses to start if one arrives anyway. It never
// executes, sources, imports or evaluates anything from a bundle — there is no
// os/exec, no interpreter and no `go plugin` anywhere under this tree, and
// internal/archcheck compiles that. And it is idempotent: `unique
// (version_id, pack_version)` on `scan` makes a redelivered job for a version
// already scanned at the running pack version a no-op rather than an error.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"agent-manager/internal/bundle"
	"agent-manager/internal/config"
	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
	"agent-manager/internal/worker/scanner/checks"
	"agent-manager/internal/worker/scanner/rules"
)

// RoleName is the argument `agent-manager worker run` takes.
const RoleName = "scanner"

// Concurrency is how many scans run at once. Each in-flight scan holds one
// decompressed tree in memory, so this times MaxDecompressedBytes is the
// role's worst case: 4 x 250 MB ~ 1 GB. Raising it is a memory decision, not a
// throughput one.
const Concurrency = 4

// jobTimeout bounds one job end to end, above the per-scan budget so the
// budget is what expires first and records `timed_out`. River killing the job
// instead would leave no record of why.
const jobTimeout = 10 * time.Minute

// sweepTimeout bounds one rescan sweep. It is generous because a sweep is many
// scans, and a sweep that runs out of time is retried and makes progress: the
// versions it already rescanned are no-ops the second time round.
const sweepTimeout = 30 * time.Minute

// Definition is the whole description of the role. The line that matters is
// Blob: AccessRead — worker.Build hands out a blob.Writer only for
// AccessReadWrite, so this declaration is the entire mechanism behind "the
// scanner never writes bundle bytes".
func Definition() worker.Definition {
	return worker.Definition{
		Name:   RoleName,
		Queues: map[string]int{outbox.QueueScan: Concurrency},
		Needs: worker.Needs{
			DB:       worker.AccessReadWrite,
			Blob:     worker.AccessRead,
			Outbound: false,
		},
		Register: register,
	}
}

// register builds the handlers. The role's own knobs — the rule-pack directory
// and the scan budget — are read here rather than in worker.Build, because a
// per-role setting in the shared bootstrap config would make every role carry
// every other role's environment.
func register(deps worker.Deps, workers *river.Workers) error {
	cfg, err := config.Load[config.Scanner]()
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	handler, err := New(deps, Options{RulepackDir: cfg.RulepackDir, Budget: cfg.ScanBudget})
	if err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, handler); err != nil {
		return err
	}
	return river.AddWorkerSafely(workers, &Sweeper{worker: handler})
}

// Options are the role's own settings.
type Options struct {
	// RulepackDir is AGENT_MANAGER_RULEPACK_DIR. Empty runs the pack embedded in
	// this build.
	RulepackDir string
	// Budget bounds one scan. Zero takes the config default.
	Budget time.Duration
}

// Worker works one `scan` job.
type Worker struct {
	river.WorkerDefaults[Job]

	deps     worker.Deps
	pack     *rules.Pack
	registry *checks.Registry
	limits   bundle.Limits
	budget   time.Duration
}

// New assembles the handler from what the bootstrap handed the role.
func New(deps worker.Deps, opts Options) (*Worker, error) {
	switch {
	case deps.DB == nil:
		return nil, errors.New("scanner: no database handle")
	case deps.BlobRead == nil:
		return nil, errors.New("scanner: no object-store reader, so it could not read a bundle")
	case deps.BlobWrite != nil:
		// The declaration and the bootstrap disagree here, so refuse to start
		// rather than let a scanner silently hold a writer.
		return nil, errors.New("scanner: the bootstrap handed this role an object-store writer; the scanner never writes bundle bytes")
	case deps.Fetch != nil:
		return nil, errors.New("scanner: the bootstrap handed this role an outbound client; a scan is static analysis and reaches no network")
	}

	pack, note, err := rules.Open(opts.RulepackDir)
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	registry, err := checks.Default()
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}

	// The pack that will actually run (often a mounted directory, not the
	// embedded one) is checked against its own fixtures before this role
	// starts: a rule whose pattern is `.` or whose fixture paths don't exist
	// would otherwise start cleanly and flag or silently skip for no reason a
	// reviewer can act on. Verified unconditionally, since a code path that
	// trusts the embedded pack because a test covers it is how this gap
	// happens.
	if err := checks.Verify(context.Background(), pack); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}

	budget := opts.Budget
	if budget <= 0 {
		budget = defaultBudget
	}

	log := deps.Log.Info().
		Str("pack_version", pack.Version()).
		Str("pack_origin", pack.Origin()).
		Int("rules", pack.Len()).
		Int("checks", len(registry.IDs()))
	if note != "" {
		log = log.Str("note", note)
	}
	log.Msg("rule pack loaded")

	return &Worker{
		deps:     deps,
		pack:     pack,
		registry: registry,
		limits:   bundle.DefaultLimits(),
		budget:   budget,
	}, nil
}

// defaultBudget mirrors config.Scanner's default, for a Worker constructed
// without one.
const defaultBudget = 120 * time.Second

// PackVersion is the value this worker records in `scan.pack_version`.
func (w *Worker) PackVersion() string { return w.pack.Version() }

// Timeout is River's per-job budget.
func (w *Worker) Timeout(*river.Job[Job]) time.Duration { return jobTimeout }

// Work runs one scan. Whether this is the last attempt is passed down because
// a scan that exceeds its budget must be retried with backoff, but the
// timeout must still be recorded rather than silently resolved to clean;
// recording it earlier would write a `scan` row that the idempotency guard
// then suppresses the retry against.
func (w *Worker) Work(ctx context.Context, job *river.Job[Job]) error {
	return w.Scan(ctx, job.Args, job.Attempt >= job.MaxAttempts)
}
