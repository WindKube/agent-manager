// Package seed loads the design's representative dataset, so a fresh
// stack has something to browse, triage and resolve from the start.
//
// The seed writes both halves of a version — bytes and rows — which is
// why it holds the writer key every other non-fetcher role doesn't get.
// It is a one-shot that may run again: `docker compose up` starts it
// every time, so idempotence comes from derived ids plus `on conflict do
// nothing` (rows.go) and a byte-side "already committed" short-circuit.
//
// Timestamps are relative to seed time, so "2 days ago" stays true on a
// stack started next month.
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

// Report is what the run did. Bundles and Lockfiles count what this run
// wrote to the bucket, so both are zero on a re-run; the rest count what
// the dataset holds, whoever wrote it.
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

	// Bytes first, rows second: a row naming bytes not yet written is the
	// failure commit-last ordering exists to prevent.
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

// writeRevisionObjects writes each revision's lockfile at the key its row
// names. An existing object is left alone: a revision is immutable, so a
// re-run must not replace bytes whose row still holds the original document.
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

// namespaceOf is the first segment of a publisher slug.
func namespaceOf(publisher string) string {
	namespace, _, _ := strings.Cut(publisher, "/")
	return namespace
}
