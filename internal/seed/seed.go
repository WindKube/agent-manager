// Package seed loads the design's representative dataset so a fresh stack has
// something to browse from the start.
//
// It runs on every `docker compose up`, so it must be idempotent: derived ids
// with `on conflict do nothing` for rows, and an "already committed" check for bytes.
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

// Deps is what the seed is handed; this package opens no connections itself.
type Deps struct {
	DB        bun.IDB
	BlobRead  blob.Reader
	BlobWrite blob.Writer
}

// Report is what the run did. Bundles and Lockfiles count this run's bucket
// writes (zero on a re-run); the rest count what the dataset holds.
type Report struct {
	Bundles   int
	Lockfiles int
	Packages  int
	Versions  int
	Profiles  int
	Revisions int
	Findings  int
}

// Run loads the dataset. It is safe to call again.
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

	// Bytes before rows, so no row ever names bytes that are not written yet.
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

// writeRevisionObjects writes each revision's lockfile, leaving existing objects
// alone because revisions are immutable.
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

func namespaceOf(publisher string) string {
	namespace, _, _ := strings.Cut(publisher, "/")
	return namespace
}
