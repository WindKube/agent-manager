// Package fetcher is the `worker fetcher` role: the only role in this system
// that may write bundle bytes.
//
// The pipeline is FR-006 to FR-008 in order, and the order is the guarantee:
//
//	fetch -> extract under the R3 caps -> filter to the spec layout ->
//	validate the manifests -> derive components -> pack tar.zst -> digest ->
//	commit-last write -> flip `visible` -> outbox a `scan` job -> audit row
//
// Everything before the commit is reversible by doing nothing. The commit-last
// write means a crash anywhere leaves orphaned bytes and no readable version
// rather than a half-published one (FR-008), and `visible` is flipped in the same
// transaction as the digest, the components and the scan hand-off, so a version
// that is readable is a version that is complete.
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

// Concurrency is how many fetches run at once.
//
// Each in-flight job holds the compressed archive and the decompressed tree in
// memory (internal/bundle buffers both by design, so the caps are the memory
// budget), so this number times MaxCompressedBytes + MaxDecompressedBytes is the
// role's worst-case footprint: 4 x (25 MB + 250 MB) ~ 1.1 GB. Raising it is a
// memory decision, not a throughput one.
const Concurrency = 4

// jobTimeout bounds one fetch end to end. It is well above the extractor's own
// 60-second cap because a slow remote is the usual reason a fetch is slow, and the
// extractor's clock only governs extraction.
const jobTimeout = 10 * time.Minute

// Definition is the whole description of the role (contracts/worker.md).
//
// Needs is the narrowest set that works, and the one line that matters is
// Blob: AccessReadWrite — the bootstrap hands out a blob.Writer for that value and
// for no other, which is the entire mechanism behind "only the fetcher may write
// bundle bytes" (principle II).
func Definition() worker.Definition {
	return worker.Definition{
		Name:   RoleName,
		Queues: map[string]int{river.QueueDefault: Concurrency},
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

// New assembles the handler from what the bootstrap handed the role.
//
// Every dependency the role declared is required here rather than defaulted: a nil
// BlobWrite means the Definition and the bootstrap disagree, and defaulting past it
// would produce a fetcher that fetches and stores nothing.
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
		// The three FR-001 shapes. Adding an OCI or GitLab source later is a new
		// file in internal/fetch plus a line here (contracts/worker.md section 3).
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
