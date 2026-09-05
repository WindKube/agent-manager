// Package fetcher is the `worker fetcher` role: the only role in this system
// that may write bundle bytes. `visible` flips in the same transaction as
// the digest and the scan hand-off, so a readable version is always
// complete; a crash before that leaves orphaned bytes rather than a
// half-published one.
package fetcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"agent-manager/internal/blob"
	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/worker"
)

// RoleName is the argument `agent-manager worker run` takes.
const RoleName = "fetcher"

// Concurrency is how many fetches run at once; raising it is a memory
// decision, not a throughput one.
const Concurrency = 4

// jobTimeout bounds one fetch end to end, well above the extractor's own
// cap since a slow remote is the usual reason a fetch is slow.
const jobTimeout = 10 * time.Minute

// Definition is the whole description of the role. Blob: AccessReadWrite is
// the entire mechanism behind "only the fetcher may write bundle bytes" —
// the bootstrap hands out a blob.Writer for that value and no other.
func Definition() worker.Definition {
	return worker.Definition{
		Name:   RoleName,
		Queues: map[string]int{outbox.QueueFetch: Concurrency},
		Needs: worker.Needs{
			DB:       worker.AccessReadWrite,
			Blob:     worker.AccessReadWrite,
			Outbound: true,
		},
		Register: register,
	}
}

func register(deps worker.Deps, workers *river.Workers) error {
	handler, err := New(deps)
	if err != nil {
		return err
	}
	return river.AddWorkerSafely(workers, handler)
}

// Worker works one `fetch` job.
type Worker struct {
	river.WorkerDefaults[Job]

	deps      worker.Deps
	sources   *fetch.Registry
	committer *blob.Committer
	limits    bundle.Limits
	validator *pkgspec.Validator
	enqueue   outbox.Enqueuer
}

// New assembles the handler from what the bootstrap handed the role. A nil
// dependency here means the Definition and the bootstrap disagree.
func New(deps worker.Deps) (*Worker, error) {
	switch {
	case deps.DB == nil:
		return nil, errors.New("fetcher: no database handle")
	case deps.BlobRead == nil:
		return nil, errors.New("fetcher: no object-store reader")
	case deps.BlobWrite == nil:
		return nil, errors.New("fetcher: no object-store writer, so it could not store a bundle")
	case deps.Fetch == nil:
		return nil, errors.New("fetcher: no outbound client")
	}

	validator, err := pkgspec.Default()
	if err != nil {
		return nil, fmt.Errorf("fetcher: %w", err)
	}
	git, err := fetch.NewGitSource(deps.Fetch)
	if err != nil {
		return nil, fmt.Errorf("fetcher: %w", err)
	}

	return &Worker{
		deps: deps,
		sources: fetch.NewRegistry(
			fetch.NewUploadSource(),
			git,
			fetch.NewArchiveURLSource(deps.Fetch),
		),
		committer: blob.NewCommitter(deps.BlobRead, deps.BlobWrite),
		limits:    bundle.DefaultLimits(),
		validator: validator,
		enqueue:   outbox.NewWriter(),
	}, nil
}

// Timeout is River's per-job budget.
func (w *Worker) Timeout(*river.Job[Job]) time.Duration { return jobTimeout }

// Work runs the pipeline for one job.
func (w *Worker) Work(ctx context.Context, job *river.Job[Job]) error {
	return w.Fetch(ctx, job.Args)
}
