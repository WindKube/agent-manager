// Package scanner is the `worker scanner` role: it reads stored bundle bytes
// and writes verdicts, check results and findings.
//
// It never writes bundle bytes — Needs declares Blob: AccessRead, and New
// refuses to start if a writer arrives anyway — and it never executes,
// sources, imports or evaluates anything from a bundle.
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

// Concurrency is how many scans run at once. Each holds one decompressed
// tree in memory: 4 x 250 MB ~ 1 GB worst case.
const Concurrency = 4

// jobTimeout bounds one job end to end, above the per-scan budget so the
// budget expires first and records `timed_out`.
const jobTimeout = 10 * time.Minute

// sweepTimeout bounds one rescan sweep.
const sweepTimeout = 30 * time.Minute

// Definition is the whole description of the role. Blob: AccessRead is the
// mechanism behind "the scanner never writes bundle bytes" — worker.Build
// hands out a blob.Writer only for AccessReadWrite.
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

// register builds the handlers and loads the role's own config.
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
		// Refuse to start rather than let a scanner silently hold a writer.
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

	// Verified unconditionally: a bad pattern or missing fixture path would
	// otherwise start cleanly and flag or skip for no reason a reviewer can act on.
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

// Work runs one scan, passing down whether this is the last attempt so a
// budget-exceeded timeout is recorded only once retries are exhausted.
func (w *Worker) Work(ctx context.Context, job *river.Job[Job]) error {
	return w.Scan(ctx, job.Args, job.Attempt >= job.MaxAttempts)
}
