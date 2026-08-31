// Package seed loads the design's representative dataset (001 FR-057, SC-004).
//
// It exists because every screen's first impression is otherwise an empty state:
// a fresh stack has no package to browse, no finding to triage and no profile to
// resolve, so nothing built on top of it can be validated through the product.
//
// The seed writes BOTH HALVES of a version — the bytes and the rows — which is
// why the compose service that runs it holds the object-store writer key rather
// than the reader key every other non-fetcher role gets. A row whose object_key
// names nothing is a catalog entry with no download behind it, and that is not a
// state worth seeding.
//
// It is a ONE-SHOT AND IT MAY RUN AGAIN. `docker compose up` starts it on every
// invocation, so idempotence is a requirement rather than a nicety: derived ids
// plus `on conflict do nothing` on the row side (see rows.go), and the committer's
// own "the index already names this version" short-circuit on the byte side.
// Running it twice leaves the same rows and the same objects.
//
// Timestamps are relative to seed time. Every date the screens render is an
// offset from the moment the seed ran, so "2 days ago" stays true on a stack
// started next month.
package seed

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"agent-manager/internal/blob"
	"agent-manager/internal/store/models"
)

// Deps is what the seed is handed. The shape mirrors the worker roles': the
// caller opens the connections, this package opens nothing.
type Deps struct {
	DB        bun.IDB
	BlobRead  blob.Reader
	BlobWrite blob.Writer
}

// Report is what the run did, for the log line and for a test to assert on.
//
// Bundles and Lockfiles count what this run WROTE to the bucket, so both are zero
// on a re-run. The rest count what the dataset holds, whoever wrote it.
type Report struct {
	Bundles   int
	Lockfiles int
	Packages  int
	Versions  int
	Profiles  int
	Revisions int
	Findings  int
}

// Run loads the dataset. It is safe to call against a database that already
// holds it.
func Run(ctx context.Context, deps Deps) (Report, error) {
	if deps.DB == nil || deps.BlobRead == nil || deps.BlobWrite == nil {
		return Report{}, fmt.Errorf("seed: a database handle and both halves of the bucket are required")
	}
	now := time.Now().UTC()

	built, err := build()
	if err != nil {
		return Report{}, err
	}
	idx, err := newIndex(built)
	if err != nil {
		return Report{}, err
	}
	revisionRows, err := buildRevisions(idx, now)
	if err != nil {
		return Report{}, err
	}

	// Bytes first, rows second, in both halves. A row that names bytes which are
	// not there yet is the failure FR-008's commit-last ordering exists to prevent,
	// and the seed has no reason to be the one place that inverts it.
	bundles, err := commitBytes(ctx, deps, built)
	if err != nil {
		return Report{}, err
	}
	lockfiles, err := writeRevisionObjects(ctx, deps, revisionRows)
	if err != nil {
		return Report{}, err
	}
	if err := writeRows(ctx, deps.DB, built, idx, revisionRows, now); err != nil {
		return Report{}, err
	}

	return Report{
		Bundles:   bundles,
		Lockfiles: lockfiles,
		Packages:  len(designPackages),
		Versions:  len(built),
		Profiles:  len(designProfiles),
		Revisions: len(revisionRows),
		Findings:  len(designFindings),
	}, nil
}

// writeRevisionObjects writes each revision's lockfile at the key its row names.
//
// An existing object is left alone rather than overwritten. That is not
// tidiness: a revision is immutable, and the lockfile carries the instant it was
// resolved, so a re-run would otherwise replace bytes whose row — inserted on the
// first run and never updated — still holds the original document.
func writeRevisionObjects(ctx context.Context, deps Deps, revisions []models.Revision) (int, error) {
	written := 0
	for i := range revisions {
		revision := &revisions[i]
		exists, err := deps.BlobRead.Exists(ctx, revision.ObjectKey)
		if err != nil {
			return written, fmt.Errorf("look for %s: %w", revision.ObjectKey, err)
		}
		if exists {
			continue
		}
		if _, err := deps.BlobWrite.Write(ctx, revision.ObjectKey,
			bytes.NewReader(revision.Lockfile)); err != nil {
			return written, fmt.Errorf("write %s: %w", revision.ObjectKey, err)
		}
		written++
	}
	return written, nil
}

// namespaceOf is the first segment of a publisher slug. Three strings are at work
// in this dataset and only two of them are columns: the publisher is the whole
// slug and carries `verified`, the namespace is its first segment, and
// namespace/name is both the id the screens render and the object-key prefix.
func namespaceOf(publisher string) string {
	namespace, _, _ := strings.Cut(publisher, "/")
	return namespace
}
